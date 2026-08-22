#pragma once
#include <vector>
#include <string>
#include "utils/types.hpp"

namespace iskabon::planner {

struct ProbeJob {
    std::string host;
    Protocol    protocol;
    int         port;   // 0 for ICMP
};

/// Known well-known ports per protocol.
const std::vector<int>& default_tcp_ports();
const std::vector<int>& default_udp_ports();

/// Builds the full list of probe jobs for a set of hosts and protocols.
std::vector<ProbeJob> build(
    const std::vector<std::string>& hosts,
    const std::vector<Protocol>&    protocols
);

}  // namespace iskabon::planner
