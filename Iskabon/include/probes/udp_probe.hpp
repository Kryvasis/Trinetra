#pragma once
#include "probes/probe_base.hpp"

namespace iskabon::probes {
class UdpProbe : public ProbeBase {
public:
    explicit UdpProbe(double timeout_sec);
    ProbeResult run(const std::string& host, int port) override;
private:
    double timeout_sec_;
};
}
