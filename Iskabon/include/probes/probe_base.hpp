#pragma once
#include "utils/types.hpp"

namespace iskabon::probes {

/// Interface all probes implement.  Each probe is stateless and thread-safe.
class ProbeBase {
public:
    virtual ~ProbeBase() = default;
    virtual ProbeResult run(const std::string& host, int port) = 0;
};

}  // namespace iskabon::probes
