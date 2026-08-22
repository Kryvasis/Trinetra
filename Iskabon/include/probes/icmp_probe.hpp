#pragma once
#include "probes/probe_base.hpp"

namespace iskabon::probes {
/// Raw ICMP echo probe.  Requires CAP_NET_RAW or root on Linux.
/// Falls back to TCP-based liveness if socket creation fails.
class IcmpProbe : public ProbeBase {
public:
    explicit IcmpProbe(double timeout_sec);
    ProbeResult run(const std::string& host, int /*port_unused*/) override;
private:
    double timeout_sec_;
    bool   raw_available_;
    bool   check_raw_capability();
};
}
