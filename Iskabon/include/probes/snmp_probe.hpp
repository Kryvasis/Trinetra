#pragma once
#include "probes/probe_base.hpp"
#include <string>
#include <vector>

namespace iskabon::probes {

struct SnmpRecord {
    std::string host;
    int         port         = 161;
    std::string oid          = "1.3.6.1.2.1.1.2.0";  // sysObjectID
    std::string raw_value;
    std::string vendor_guess;
    std::string confidence;  // "high" | "low" | "none"
};

class SnmpProbe : public ProbeBase {
public:
    /// timeout_sec mirrors the --timeout CLI arg (Args::timeout);
    /// community defaults to "public" and is injected at construction,
    /// following the same pattern used by the other probes.
    explicit SnmpProbe(double timeout_sec,
                       const std::string& community = "public");

    ProbeResult run(const std::string& host, int port) override;

    const std::vector<SnmpRecord>& results() const;

    struct VendorMatch {
        std::string vendor;
        std::string confidence;  // "high" | "low" | "" (no OID at all)
    };

    /// Classify a sysObjectID value against vendor_oid_table().
    static VendorMatch classify_oid(const std::string& raw_value);

private:
    double                  timeout_sec_;
    std::string             community_;
    std::vector<SnmpRecord> records_;
};

void append_snmp_result_to_session(const std::string& session_json_path,
                                   const SnmpRecord& record);

}  // namespace iskabon::probes
