#pragma once
#include <cstdint>
#include <optional>
#include <string>

namespace iskabon {

enum class Protocol { TCP, UDP, ICMP };

std::string protocol_str(Protocol p);
Protocol    protocol_from_str(const std::string& s);

struct ProbeResult {
    std::string            host;
    Protocol               protocol;
    std::optional<int>     port;          // nullopt for ICMP
    std::string            status;        // "open" | "closed" | "up" | ...
    std::optional<double>  latency_ms;
    std::optional<std::string> error;
};

}  // namespace iskabon
