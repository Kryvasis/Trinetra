#pragma once
#include <string>
#include <vector>
#include "utils/types.hpp"

namespace iskabon::cli {

struct Args {
    std::string            session_name;
    std::string            target_router;   // label only – stored, not probed
    std::string            target;          // IP | hostname | CIDR
    std::vector<Protocol>  protocols;       // populated by --protocols
    int                    workers  = 256;
    double                 timeout  = 0.8;  // seconds per probe
};

/// Parse argv; prints usage and exits on error.
Args parse(int argc, char** argv);
void print_usage(const char* prog);

}  // namespace iskabon::cli
