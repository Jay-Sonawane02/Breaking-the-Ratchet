// netutil.hpp
//
// Minimal TCP helpers for speaking the AS3 wire protocol: connect-by-name,
// and read/write newline-delimited JSON lines (protocol.md section 2.1).

#pragma once
#include <string>
#include <stdexcept>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>

namespace net {

inline int connectTo(const std::string& host, int port) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    std::string portStr = std::to_string(port);
    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0 || !res) {
        throw std::runtime_error("getaddrinfo failed for " + host);
    }
    int fd = -1;
    for (auto* p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) throw std::runtime_error("connect() failed to " + host + ":" + portStr);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return fd;
}

inline int listenOn(const std::string& bindAddr, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) throw std::runtime_error("socket() failed");
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = bindAddr.empty() ? INADDR_ANY : inet_addr(bindAddr.c_str());
    if (bind(fd, (sockaddr*)&addr, sizeof(addr)) < 0) throw std::runtime_error("bind() failed");
    if (listen(fd, 16) < 0) throw std::runtime_error("listen() failed");
    return fd;
}

// Buffered newline-delimited reader over a raw fd.
class LineReader {
public:
    explicit LineReader(int fd) : fd_(fd) {}

    // Returns false on EOF/error.
    bool readLine(std::string& out) {
        out.clear();
        while (true) {
            size_t nl = buf_.find('\n');
            if (nl != std::string::npos) {
                out = buf_.substr(0, nl);
                buf_.erase(0, nl + 1);
                return true;
            }
            char chunk[4096];
            ssize_t n = ::read(fd_, chunk, sizeof(chunk));
            if (n <= 0) {
                if (!buf_.empty()) { out = buf_; buf_.clear(); return true; }
                return false;
            }
            buf_.append(chunk, n);
        }
    }

private:
    int fd_;
    std::string buf_;
};

inline void sendLine(int fd, const std::string& line) {
    std::string out = line;
    if (out.empty() || out.back() != '\n') out.push_back('\n');
    size_t off = 0;
    while (off < out.size()) {
        ssize_t n = ::write(fd, out.data() + off, out.size() - off);
        if (n <= 0) throw std::runtime_error("write() failed");
        off += (size_t)n;
    }
}

} // namespace net
