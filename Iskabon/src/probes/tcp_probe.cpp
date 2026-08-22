#include "probes/tcp_probe.hpp"
#include "utils/time_utils.hpp"
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

namespace iskabon::probes {

TcpProbe::TcpProbe(double timeout_sec) : timeout_sec_(timeout_sec) {}

ProbeResult TcpProbe::run(const std::string& host, int port) {
    double start = utils::monotonic_ms();

    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host.c_str(), port_str, &hints, &res) != 0) {
        return { host, Protocol::TCP, port, "error",
                 utils::monotonic_ms() - start, "getaddrinfo failed" };
    }

    int fd = socket(res->ai_family, SOCK_STREAM, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        return { host, Protocol::TCP, port, "error",
                 utils::monotonic_ms() - start, std::strerror(errno) };
    }

    // Non-blocking connect
    fcntl(fd, F_SETFL, O_NONBLOCK);
    connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    fd_set wset;
    FD_ZERO(&wset); FD_SET(fd, &wset);
    timeval tv;
    tv.tv_sec  = static_cast<long>(timeout_sec_);
    tv.tv_usec = static_cast<long>((timeout_sec_ - tv.tv_sec) * 1e6);

    std::string status = "closed";
    int rc = select(fd + 1, nullptr, &wset, nullptr, &tv);
    if (rc > 0) {
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
        status = (err == 0) ? "open" : "closed";
    }
    close(fd);
    return { host, Protocol::TCP, port, status,
             utils::monotonic_ms() - start, std::nullopt };
}

} // namespace iskabon::probes
