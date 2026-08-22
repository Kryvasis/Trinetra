#pragma once
#include <functional>
#include <vector>
#include "planner/planner.hpp"
#include "utils/types.hpp"

namespace iskabon::probes {

using ResultCallback = std::function<void(const ProbeResult&)>;

struct ScanStats {
    int    total      = 0;
    int    open_count = 0;
    int    closed     = 0;
    int    errors     = 0;
    double elapsed_s  = 0.0;
};

/// Thread-pool scanner; calls callback for every result as it arrives.
class Scanner {
public:
    Scanner(int workers, double timeout_sec);
    ScanStats run(
        const std::vector<planner::ProbeJob>& jobs,
        const ResultCallback&                 on_result
    );
private:
    int    workers_;
    double timeout_sec_;
};

}  // namespace iskabon::probes
