#pragma once
#include "probes/probe_base.hpp"
#include <string>
#include <vector>

namespace iskabon::probes {

struct BannerRecord {
    std::string host;
    int         port         = 0;
    std::string protocol     = "tcp";
    std::string raw_banner;
    std::string vendor_guess;
    std::string version_guess;
};

class BannerProbe : public ProbeBase {
public:
    explicit BannerProbe(double timeout_sec);

    ProbeResult run(const std::string& host, int port) override;

    const std::vector<BannerRecord>& results() const;

    struct Guess {
        std::string vendor;
        std::string version;
    };

    static Guess parse_vendor_version(const std::string& raw_banner);
    static bool  supported_port(int port);
    static bool  sends_request(int port);

private:
    double                    timeout_sec_;
    std::vector<BannerRecord> records_;
};

void append_banner_results_to_session(const std::string& session_json_path,
                                      const std::vector<BannerRecord>& records);

}  // namespace iskabon::probes
