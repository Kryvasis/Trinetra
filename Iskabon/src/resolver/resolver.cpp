#include "resolver/resolver.hpp"
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <algorithm>
#include <cstring>
#include <set>
#include <sstream>
#include <stdexcept>

namespace iskabon::resolver {

bool is_ip_literal(const std::string& s) {
    struct in_addr  a4{};
    struct in6_addr a6{};
    return inet_pton(AF_INET, s.c_str(), &a4) == 1 ||
           inet_pton(AF_INET6, s.c_str(), &a6) == 1;
}

bool is_cidr(const std::string& s) {
    return s.find('/') != std::string::npos;
}

static std::vector<std::string> expand_cidr(const std::string& cidr) {
    auto slash = cidr.find('/');
    std::string base = cidr.substr(0, slash);
    int prefix = std::stoi(cidr.substr(slash + 1));
    if (prefix < 0 || prefix > 32)
        throw std::runtime_error("Invalid prefix length: " + cidr);

    struct in_addr addr{};
    if (inet_pton(AF_INET, base.c_str(), &addr) != 1)
        throw std::runtime_error("Invalid CIDR base address: " + base);

    uint32_t ip   = ntohl(addr.s_addr);
    uint32_t mask = prefix == 0 ? 0u : (~0u << (32 - prefix));
    uint32_t net  = ip & mask;
    uint32_t bc   = net | ~mask;

    std::vector<std::string> hosts;
    char buf[INET_ADDRSTRLEN];
    for (uint32_t h = net + 1; h < bc; ++h) {
        in_addr tmp; tmp.s_addr = htonl(h);
        inet_ntop(AF_INET, &tmp, buf, sizeof(buf));
        hosts.emplace_back(buf);
    }
    return hosts;
}

std::vector<std::string> expand(const std::string& target) {
    if (is_cidr(target))
        return expand_cidr(target);

    if (is_ip_literal(target))
        return { target };

    // DNS resolution
    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    int rc = getaddrinfo(target.c_str(), nullptr, &hints, &res);
    if (rc != 0)
        throw std::runtime_error("DNS resolution failed for '" +
                                 target + "': " + gai_strerror(rc));

    std::set<std::string> seen;
    char buf[INET6_ADDRSTRLEN];
    for (auto* p = res; p; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            auto* s = &reinterpret_cast<sockaddr_in*>(p->ai_addr)->sin_addr;
            inet_ntop(AF_INET, s, buf, sizeof(buf));
            seen.insert(buf);
        } else if (p->ai_family == AF_INET6) {
            auto* s = &reinterpret_cast<sockaddr_in6*>(p->ai_addr)->sin6_addr;
            inet_ntop(AF_INET6, s, buf, sizeof(buf));
            seen.insert(buf);
        }
    }
    freeaddrinfo(res);
    return { seen.begin(), seen.end() };
}

} // namespace iskabon::resolver
