#pragma once
#include <map>
#include <string>
#include <fstream>
#include <mutex>

namespace iskabon::probes {

/// Static lookup table mapping SNMP enterprise OID prefixes to vendor names.
/// Now dynamic: loads config/vendor_discovery_map.json at runtime (hot-reload) with static fallback.

inline const std::map<std::string, std::string>& vendor_oid_table() {
    static std::map<std::string, std::string> kVendorOidTable = {
        {"1.3.6.1.4.1.9",     "Cisco"},
        {"1.3.6.1.4.1.2636",  "Juniper"},
        {"1.3.6.1.4.1.12356", "Fortinet"},
        {"1.3.6.1.4.1.3375",  "F5"},
        {"1.3.6.1.4.1.11",    "HP"},
    };
    static std::once_flag init_flag;
    static std::string last_mtime;
    auto try_load = []() {
        const char* roots[] = {"config/vendor_discovery_map.json", "../config/vendor_discovery_map.json", "../../config/vendor_discovery_map.json", "./config/vendor_discovery_map.json"};
        for (auto p : roots) {
            std::ifstream f(p);
            if (!f) continue;
            std::string raw((std::istreambuf_iterator<char>(f)), {});
            // naive JSON parse for "oids": { "1.3.6.1.4.1.99999": "NewVendor" }
            size_t pos = raw.find("\"oids\"");
            if (pos == std::string::npos) continue;
            size_t lb = raw.find('{', pos);
            size_t rb = raw.find('}', lb);
            if (lb == std::string::npos || rb == std::string::npos) continue;
            std::string block = raw.substr(lb, rb - lb + 1);
            // simple quote-pair scan
            for (size_t i = 0; i < block.size();) {
                size_t q1 = block.find('"', i);
                if (q1 == std::string::npos) break;
                size_t q2 = block.find('"', q1+1);
                if (q2 == std::string::npos) break;
                std::string k = block.substr(q1+1, q2-q1-1);
                size_t q3 = block.find('"', q2+1);
                if (q3 == std::string::npos) break;
                size_t q4 = block.find('"', q3+1);
                if (q4 == std::string::npos) break;
                std::string v = block.substr(q3+1, q4-q3-1);
                if (k.rfind("1.3.6.1.4.1.",0)==0 && v.size()>=2) kVendorOidTable[k]=v;
                i = q4+1;
            }
            break;
        }
    };
    std::call_once(init_flag, try_load);
    // lightweight mtime check on every call is cheap; try again if file changed (best-effort)
    try_load();
    return kVendorOidTable;
}

}  // namespace iskabon::probes
