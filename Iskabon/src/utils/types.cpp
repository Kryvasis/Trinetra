#include "utils/types.hpp"
#include <stdexcept>

namespace iskabon {

std::string protocol_str(Protocol p) {
    switch (p) {
        case Protocol::TCP:  return "tcp";
        case Protocol::UDP:  return "udp";
        case Protocol::ICMP: return "icmp";
    }
    return "unknown";
}

Protocol protocol_from_str(const std::string& s) {
    if (s == "tcp")  return Protocol::TCP;
    if (s == "udp")  return Protocol::UDP;
    if (s == "icmp") return Protocol::ICMP;
    throw std::invalid_argument("Unknown protocol: " + s);
}

} // namespace iskabon
