#pragma once
#include "probes/probe_base.hpp"

namespace iskabon::probes {
class TcpProbe : public ProbeBase {
public:
    explicit TcpProbe(double timeout_sec);
    ProbeResult run(const std::string& host, int port) override;
private:
    double timeout_sec_;
};
}
