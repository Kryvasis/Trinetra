#pragma once
#include <string>

namespace iskabon::vendor_resolver {

/// Evidence from the TCP/IP stack fingerprinting probes.
struct StackFingerprint {
    std::string os_family;      // e.g. "ios", "junos", "fortios", "tmos"
    bool        strong_match = false;
};

/// Evidence extracted by banner_probe for this target.
struct BannerEvidence {
    std::string vendor_guess;   // empty when nothing was identified
    std::string version_guess;
};

/// Evidence extracted by snmp_probe for this target.
struct SnmpEvidence {
    std::string raw_value;      // sysObjectID value (dotted OID)
    std::string vendor_guess;
    std::string confidence;     // "high" | "low" | "none"
};

/// Combined verdict written into the session JSON.
struct VendorResolution {
    std::string final_vendor;
    std::string detection_method;   // "snmp" | "banner" | "stack_fingerprint"
                                    // | "conflict" | "none"
    double      confidence_score = 0.0;  // 0.0 - 1.0
};

/// Merge all three fingerprint sources into a single verdict.
///
/// Priority:
///   1. SNMP confidence "high"            -> 0.90 .. 0.95
///   2. banner_probe vendor_guess         -> 0.60 .. 0.80
///   3. strong stack OS-family match      -> 0.30 .. 0.50
///   4. unresolved / strong disagreement  -> "unknown" below 0.30
VendorResolution resolve_vendor(const StackFingerprint& stack,
                                const BannerEvidence&   banner,
                                const SnmpEvidence&     snmp);

/// Map an OS family name to its hardware vendor ("unknown" if unmapped).
std::string os_family_to_vendor(const std::string& os_family);

void append_vendor_resolution_to_session(
    const std::string&        session_json_path,
    const VendorResolution&   resolution);

}  // namespace iskabon::vendor_resolver
