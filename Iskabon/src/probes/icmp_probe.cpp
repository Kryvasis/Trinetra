#include "probes/icmp_probe.hpp"
#include "utils/time_utils.hpp"
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

namespace iskabon::probes {

static uint16_t checksum(const uint16_t* buf, int len) {
    uint32_t sum = 0;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len) sum += *reinterpret_cast<const uint8_t*>(buf);
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

bool IcmpProbe::check_raw_capability() {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) return false;
    close(fd);
    return true;
}

IcmpProbe::IcmpProbe(double timeout_sec)
    : timeout_sec_(timeout_sec),
      raw_available_(check_raw_capability()) {}

ProbeResult IcmpProbe::run(const std::string& host, int /*port_unused*/) {
    double start = utils::monotonic_ms();

    if (!raw_available_) {
        // Graceful fallback: attempt TCP-80/443 liveness
        for (int port : {80, 443, 22}) {
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) continue;
            struct sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port   = htons(static_cast<uint16_t>(port));
            inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
            timeval tv;
            tv.tv_sec  = static_cast<long>(timeout_sec_);
            tv.tv_usec = static_cast<long>((timeout_sec_ - tv.tv_sec) * 1e6);
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            int rc = connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
            close(fd);
            if (rc == 0)
                return { host, Protocol::ICMP, std::nullopt, "up(tcp-fallback)",
                         utils::monotonic_ms() - start, "raw ICMP unavailable; used TCP probe" };
        }
        return { host, Protocol::ICMP, std::nullopt, "unknown",
                 utils::monotonic_ms() - start,
                 "raw ICMP unavailable and no TCP ports responded" };
    }

    // Raw ICMP echo request
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0)
        return { host, Protocol::ICMP, std::nullopt, "error",
                 utils::monotonic_ms() - start, std::strerror(errno) };

    struct icmphdr pkt{};
    pkt.type             = ICMP_ECHO;
    pkt.code             = 0;
    pkt.un.echo.id       = static_cast<uint16_t>(getpid() & 0xFFFF);
    pkt.un.echo.sequence = 1;
    pkt.checksum         = checksum(reinterpret_cast<const uint16_t*>(&pkt),
                                    sizeof(pkt));

    struct sockaddr_in dest{};
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, host.c_str(), &dest.sin_addr);
    sendto(fd, &pkt, sizeof(pkt), 0,
           reinterpret_cast<sockaddr*>(&dest), sizeof(dest));

    fd_set rset;
    FD_ZERO(&rset); FD_SET(fd, &rset);
    timeval tv;
    tv.tv_sec  = static_cast<long>(timeout_sec_);
    tv.tv_usec = static_cast<long>((timeout_sec_ - tv.tv_sec) * 1e6);

    std::string status = "down";
    if (select(fd + 1, &rset, nullptr, nullptr, &tv) > 0)
        status = "up";

    close(fd);
    return { host, Protocol::ICMP, std::nullopt, status,
             utils::monotonic_ms() - start, std::nullopt };
}

} // namespace iskabon::probes
