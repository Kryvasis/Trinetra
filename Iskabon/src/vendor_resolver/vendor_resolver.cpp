#include "vendor_resolver/vendor_resolver.hpp"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <map>
#include <sstream>

namespace iskabon::vendor_resolver {
namespace {

std::string to_lower(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s)
        out.push_back(static_cast<char>(
            std::tolower(static_cast<unsigned char>(c))));
    return out;
}

bool same_vendor(const std::string& a, const std::string& b) {
    if (a.empty() || b.empty()) return false;
    std::string la = to_lower(a), lb = to_lower(b);
    return la == lb || la.find(lb) != std::string::npos ||
           lb.find(la) != std::string::npos;
}

/// OS family -> hardware vendor.  Now dynamic via config/vendor_discovery_map.json + static fallback.
const std::map<std::string, std::string>& os_family_table() {
    static std::map<std::string, std::string> kOsFamilyTable = {
        {"ios",      "Cisco"},
        {"ios-xe",   "Cisco"},
        {"ios-xr",   "Cisco"},
        {"nx-os",    "Cisco"},
        {"junos",    "Juniper"},
        {"fortios",  "Fortinet"},
        {"tmos",     "F5"},
        {"procurve", "HP"},
        {"sonic",    "SONiC"},
        {"cumulus",  "Cumulus"},
        {"eos",      "Arista"},
    };
    static bool loaded = false;
    if (!loaded) {
        const char* roots[] = {"config/vendor_discovery_map.json", "../config/vendor_discovery_map.json", "../../config/vendor_discovery_map.json"};
        for (auto p : roots) {
            std::ifstream f(p);
            if (!f) continue;
            std::string raw((std::istreambuf_iterator<char>(f)), {});
            size_t pos = raw.find("\"os_families\"");
            if (pos == std::string::npos) continue;
            size_t lb = raw.find('{', pos);
            size_t rb = raw.find('}', lb);
            if (lb == std::string::npos || rb == std::string::npos) continue;
            std::string block = raw.substr(lb, rb - lb + 1);
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
                if (!k.empty() && !k.starts_with("_") && v.size()>=2) kOsFamilyTable[to_lower(k)] = v;
                i = q4+1;
            }
            loaded = true;
            break;
        }
        if (!loaded) loaded = true;
    }
    return kOsFamilyTable;
}

}  // namespace

std::string os_family_to_vendor(const std::string& os_family) {
    const auto& table = os_family_table();
    auto it = table.find(to_lower(os_family));
    if (it == table.end()) return {};
    return it->second;
}

VendorResolution resolve_vendor(const StackFingerprint& stack,
                                const BannerEvidence&   banner,
                                const SnmpEvidence&     snmp) {
    VendorResolution r;
    r.final_vendor = "unknown";

    bool banner_present = !banner.vendor_guess.empty();
    bool stack_present  = stack.strong_match &&
                          !stack.os_family.empty() &&
                          !os_family_to_vendor(stack.os_family).empty();
    std::string stack_vendor =
        stack_present ? os_family_to_vendor(stack.os_family) : "";

    // ── Tier 1: SNMP-confirmed identity ─────────────────────
    if (snmp.confidence == "high" && !snmp.vendor_guess.empty()) {
        bool banner_disagrees = banner_present &&
                                !same_vendor(banner.vendor_guess,
                                             snmp.vendor_guess);
        bool stack_disagrees  = stack_present &&
                                !same_vendor(stack_vendor,
                                             snmp.vendor_guess);

        if (banner_disagrees && stack_disagrees) {
            // Both remaining sources contradict the SNMP verdict.
            r.detection_method   = "conflict";
            r.confidence_score   = 0.25;
            return r;
        }

        r.final_vendor       = snmp.vendor_guess;
        r.detection_method   = "snmp";
        r.confidence_score   = (banner_present && same_vendor(
                                    banner.vendor_guess, snmp.vendor_guess))
                                   ? 0.95
                                   : 0.90;
        return r;
    }

    // ── Tier 2: banner-derived vendor ───────────────────────
    if (banner_present) {
        if (stack_present && !same_vendor(stack_vendor,
                                          banner.vendor_guess)) {
            // Banner and stack fingerprint strongly disagree.
            r.detection_method   = "conflict";
            r.confidence_score   = 0.25;
            return r;
        }
        r.final_vendor     = banner.vendor_guess;
        r.detection_method = "banner";
        // Corroborated by the stack -> upper band; bare guess -> lower.
        r.confidence_score = stack_present ? 0.80 : 0.70;
        return r;
    }

    // ── Tier 3: strong TCP/IP stack fallback ────────────────
    if (stack_present) {
        r.final_vendor     = stack_vendor;
        r.detection_method = "stack_fingerprint";
        r.confidence_score = 0.40;
        return r;
    }

    // ── Nothing resolved ────────────────────────────────────
    r.detection_method   = "none";
    r.confidence_score   = 0.10;
    return r;
}

void append_vendor_resolution_to_session(
    const std::string&      session_json_path,
    const VendorResolution& resolution) {
    std::ifstream f(session_json_path);
    if (!f) return;
    std::string raw{std::istreambuf_iterator<char>(f), {}};

    char score[16];
    snprintf(score, sizeof(score), "%.2f", resolution.confidence_score);

    std::ostringstream obj;
    obj << "{\n"
        << "    \"final_vendor\": \"" << resolution.final_vendor
        << "\",\n"
        << "    \"detection_method\": \"" << resolution.detection_method
        << "\",\n"
        << "    \"confidence_score\": " << score << "\n"
        << "  }";

    std::string block = "\"vendor_resolution\": " + obj.str();

    auto key = raw.find("\"vendor_resolution\"");
    if (key != std::string::npos) {
        auto lb = raw.find('{', key);
        if (lb != std::string::npos) {
            bool   in_str = false;
            size_t rb     = lb;
            int    depth  = 0;
            for (size_t i = lb; i < raw.size(); ++i) {
                char c = raw[i];
                if (in_str && c == '\\') { ++i; continue; }
                if (c == '"') in_str = !in_str;
                if (!in_str && c == '{') ++depth;
                if (!in_str && c == '}') {
                    --depth;
                    if (depth == 0) { rb = i; break; }
                }
            }
            raw.erase(key, rb - key + 1);
            raw.insert(key, block);
        }
    } else {
        auto pos = raw.rfind('}');
        if (pos == std::string::npos) return;
        raw.insert(pos, ",\n  " + block + "\n  ");
    }

    std::string tmp = session_json_path + ".tmp";
    {
        std::ofstream o(tmp);
        if (!o) return;
        o << raw;
    }
    std::rename(tmp.c_str(), session_json_path.c_str());
}

}  // namespace iskabon::vendor_resolver
