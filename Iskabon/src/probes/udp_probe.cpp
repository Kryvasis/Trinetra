#include "probes/udp_probe.hpp"
#include "utils/time_utils.hpp"
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

namespace iskabon::probes {

UdpProbe::UdpProbe(double timeout_sec) : timeout_sec_(timeout_sec) {}

ProbeResult UdpProbe::run(const std::string& host, int port) {
    double start = utils::monotonic_ms();

    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host.c_str(), port_str, &hints, &res) != 0) {
        return { host, Protocol::UDP, port, "error",
                 utils::monotonic_ms() - start, "getaddrinfo failed" };
    }

    int fd = socket(res->ai_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        return { host, Protocol::UDP, port, "error",
                 utils::monotonic_ms() - start, std::strerror(errno) };
    }

    static const uint8_t probe_pkt[] = { 0x00 };
    sendto(fd, probe_pkt, sizeof(probe_pkt), 0,
           res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    fd_set rset;
    FD_ZERO(&rset); FD_SET(fd, &rset);
    timeval tv;
    tv.tv_sec  = static_cast<long>(timeout_sec_);
    tv.tv_usec = static_cast<long>((timeout_sec_ - tv.tv_sec) * 1e6);

    std::string status = "open|filtered";
    uint8_t buf[512];
    int rc = select(fd + 1, &rset, nullptr, nullptr, &tv);
    if (rc > 0) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        status = (n >= 0) ? "open|responsive" : "open|filtered";
    }
    close(fd);
    return { host, Protocol::UDP, port, status,
             utils::monotonic_ms() - start, std::nullopt };
}

} // namespace iskabon::probes
