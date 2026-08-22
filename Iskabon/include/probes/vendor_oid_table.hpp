#pragma once
#include <map>
#include <string>

namespace iskabon::probes {

/// Static lookup table mapping SNMP enterprise OID prefixes to vendor names.
///
/// sysObjectID values returned by devices live under the enterprise subtree
/// `1.3.6.1.4.1.<enterprise-number>...`; the keys here are those prefixes.
///
/// To add a new vendor, append one entry below, e.g.:
///     {"1.3.6.1.4.1.8072", "Net-SNMP"},
/// Matching is longest-prefix with a '.' boundary, so ordering does not
/// matter — entries may be listed in any sequence.
inline const std::map<std::string, std::string>& vendor_oid_table() {
    static const std::map<std::string, std::string> kVendorOidTable = {
        {"1.3.6.1.4.1.9",     "Cisco"},
        {"1.3.6.1.4.1.2636",  "Juniper"},
        {"1.3.6.1.4.1.12356", "Fortinet"},
        {"1.3.6.1.4.1.3375",  "F5"},
        {"1.3.6.1.4.1.11",    "HP"},
        // Add new entries here: {"<enterprise-prefix>", "<Vendor>"},
    };
    return kVendorOidTable;
}

}  // namespace iskabon::probes
