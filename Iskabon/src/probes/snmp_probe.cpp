#include "probes/snmp_probe.hpp"
#include "probes/vendor_oid_table.hpp"
#include "utils/time_utils.hpp"
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

namespace iskabon::probes {
namespace {

constexpr const char* kDefaultOid = "1.3.6.1.2.1.1.2.0";  // sysObjectID

// ── BER encoding helpers ─────────────────────────────────────

void append_len(std::vector<uint8_t>& out, size_t len) {
    if (len < 0x80) {
        out.push_back(static_cast<uint8_t>(len));
    } else if (len <= 0xff) {
        out.push_back(0x81);
        out.push_back(static_cast<uint8_t>(len));
    } else {
        out.push_back(0x82);
        out.push_back(static_cast<uint8_t>(len >> 8));
        out.push_back(static_cast<uint8_t>(len & 0xff));
    }
}

std::vector<uint8_t> tlv(uint8_t tag, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> out{tag};
    append_len(out, payload.size());
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

std::vector<uint8_t> encode_int(uint64_t v) {
    std::vector<uint8_t> p;
    if (v == 0) {
        p = {0x00};
    } else {
        while (v) {
            p.push_back(static_cast<uint8_t>(v & 0xff));
            v >>= 8;
        }
        std::reverse(p.begin(), p.end());
    }
    return tlv(0x02, p);
}

std::vector<uint8_t> encode_octet_string(const std::string& s) {
    return tlv(0x04,
               {s.begin(), s.end()});
}

std::vector<uint8_t> encode_oid(const std::string& oid) {
    std::vector<uint64_t> parts;
    std::string cur;
    auto flush = [&] {
        if (!cur.empty()) {
            parts.push_back(std::stoull(cur));
            cur.clear();
        }
    };
    for (char c : oid) {
        if (c == '.') flush();
        else cur.push_back(c);
    }
    flush();

    std::vector<uint8_t> body;
    if (parts.size() < 2) return tlv(0x06, body);
    body.push_back(static_cast<uint8_t>(parts[0] * 40 + parts[1]));
    for (size_t i = 2; i < parts.size(); ++i) {
        uint64_t v = parts[i];
        uint8_t tmp[10];
        int n = 0;
        tmp[n++] = static_cast<uint8_t>(v & 0x7f);
        v >>= 7;
        while (v) {
            tmp[n++] = static_cast<uint8_t>(0x80 | (v & 0x7f));
            v >>= 7;
        }
        while (n--) body.push_back(tmp[n]);
    }
    return tlv(0x06, body);
}

/// Build a complete SNMPv2c GET request PDU.
std::vector<uint8_t> build_get_request(const std::string& community,
                                       const std::string& oid) {
    std::vector<uint8_t> null_val = tlv(0x05, {});
    std::vector<uint8_t> varbind =
        tlv(0x30, [&] {
            auto v = encode_oid(oid);
            v.insert(v.end(), null_val.begin(), null_val.end());
            return v;
        }());
    std::vector<uint8_t> varbind_list = tlv(0x30, varbind);

    // GetRequest PDU: [APPLICATION 0] IMPLICIT SEQUENCE
    std::vector<uint8_t> pdu_body = encode_int(1);      // request-id
    auto zero = encode_int(0);
    pdu_body.insert(pdu_body.end(), zero.begin(), zero.end());   // error-status
    pdu_body.insert(pdu_body.end(), zero.begin(), zero.end());   // error-index
    pdu_body.insert(pdu_body.end(),
                    varbind_list.begin(), varbind_list.end());

    std::vector<uint8_t> msg_body = encode_int(1);      // SNMPv2c (version=1)
    auto comm = encode_octet_string(community);
    msg_body.insert(msg_body.end(), comm.begin(), comm.end());

    std::vector<uint8_t> get_pdu = tlv(0xA0, pdu_body);
    msg_body.insert(msg_body.end(), get_pdu.begin(), get_pdu.end());

    return tlv(0x30, msg_body);
}

// ── BER decoding helpers ─────────────────────────────────────

struct Tlv {
    uint8_t         tag = 0;
    const uint8_t*  val = nullptr;
    size_t          len = 0;
};

bool read_tlv(const uint8_t* buf, size_t size, size_t& pos, Tlv& out) {
    if (pos + 2 > size) return false;
    out.tag = buf[pos++];
    size_t len = buf[pos++];
    if (len & 0x80) {
        size_t n = len & 0x7f;
        if (n == 0 || n > 4 || pos + n > size) return false;
        len = 0;
        for (size_t i = 0; i < n; ++i)
            len = (len << 8) | buf[pos++];
    }
    if (pos + len > size) return false;
    out.val = buf + pos;
    out.len = len;
    pos += len;
    return true;
}

std::string decode_oid(const uint8_t* v, size_t len) {
    if (len == 0) return {};
    std::ostringstream o;
    uint64_t first = v[0];
    o << first / 40 << "." << first % 40;
    uint64_t acc  = 0;
    bool     cont = false;
    for (size_t i = 1; i < len; ++i) {
        acc = (acc << 7) | (v[i] & 0x7f);
        if (v[i] & 0x80) {
            cont = true;
            continue;
        }
        o << "." << acc;
        acc  = 0;
        cont = false;
    }
    (void)cont;
    return o.str();
}

std::string sanitize_bytes(const uint8_t* v, size_t len) {
    std::string out;
    out.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = static_cast<unsigned char>(v[i]);
        out.push_back((c >= 0x20 && c <= 0x7e) ? static_cast<char>(c) : '.');
    }
    return out;
}

uint64_t big_endian(const uint8_t* v, size_t len) {
    uint64_t r = 0;
    for (size_t i = 0; i < len && i < 8; ++i)
        r = (r << 8) | v[i];
    return r;
}

/// Render an SNMP variable-binding value as a human-readable string.
std::string decode_value(const Tlv& val) {
    switch (val.tag) {
    case 0x06:  // OBJECT IDENTIFIER (sysObjectID case)
        return decode_oid(val.val, val.len);
    case 0x05:  // NULL
        return {};
    case 0x02:  // INTEGER
        return std::to_string(big_endian(val.val, val.len));
    case 0x40:  // IpAddress
    {
        if (val.len == 4)
            return sanitize_bytes(val.val, val.len);
        return {};
    }
    default:    // Counter/Gauge/TimeTicks/Opaque/strings
        return sanitize_bytes(val.val, val.len);
    }
}

/// Extract the first variable-binding value from an SNMP GET response.
bool extract_response_value(const uint8_t* buf, size_t size,
                            std::string& value_out) {
    size_t pos = 0;
    Tlv outer;
    if (!read_tlv(buf, size, pos, outer) || outer.tag != 0x30) return false;

    pos = static_cast<size_t>(outer.val - buf);
    size_t end = pos + outer.len;

    Tlv part;
    if (!read_tlv(buf, end, pos, part) || part.tag != 0x02) return false;  // version
    if (!read_tlv(buf, end, pos, part) || part.tag != 0x04) return false;  // community

    if (!read_tlv(buf, end, pos, part) || part.tag != 0xA2) return false;  // GetResponse

    size_t pdu_off = static_cast<size_t>(part.val - buf);
    size_t pdu_end = pdu_off + part.len;

    size_t p = pdu_off;
    Tlv request_id, err_status_tlv, err_index_tlv;
    if (!read_tlv(buf, pdu_end, p, request_id) || request_id.tag != 0x02)
        return false;                                                        // request-id
    if (!read_tlv(buf, pdu_end, p, err_status_tlv) ||
        err_status_tlv.tag != 0x02)
        return false;                                                        // error-status
    if (!read_tlv(buf, pdu_end, p, err_index_tlv) || err_index_tlv.tag != 0x02)
        return false;                                                        // error-index
    uint64_t err_status = big_endian(err_status_tlv.val, err_status_tlv.len);

    if (!read_tlv(buf, pdu_end, p, part) || part.tag != 0x30) return false;  // varbind list
    size_t vb_off = static_cast<size_t>(part.val - buf);
    size_t vb_end = vb_off + part.len;

    size_t q = vb_off;
    if (!read_tlv(buf, vb_end, q, part) || part.tag != 0x30) return false;  // varbind

    size_t bind_off = static_cast<size_t>(part.val - buf);
    size_t bind_end = bind_off + part.len;

    size_t b = bind_off;
    Tlv name, value;
    if (!read_tlv(buf, bind_end, b, name) || name.tag != 0x06) return false;
    if (!read_tlv(buf, bind_end, b, value)) return false;

    if (err_status != 0) {
        value_out.clear();  // SNMP error (noSuchName etc.)
        return true;
    }
    value_out = decode_value(value);
    return true;
}

}  // namespace

SnmpProbe::SnmpProbe(double timeout_sec, const std::string& community)
    : timeout_sec_(timeout_sec), community_(community) {}

const std::vector<SnmpRecord>& SnmpProbe::results() const {
    return records_;
}

SnmpProbe::VendorMatch SnmpProbe::classify_oid(const std::string& raw_value) {
    VendorMatch m{{}, {}};
    std::string v;
    auto b = raw_value.find_first_not_of(" \t\r\n");
    if (b != std::string::npos) {
        auto e = raw_value.find_last_not_of(" \t\r\n");
        v = raw_value.substr(b, e - b + 1);
    }
    if (v.empty()) return {{}, "none"};

    const auto& table = vendor_oid_table();
    const std::string* best_prefix = nullptr;
    for (const auto& [prefix, vendor] : table) {
        bool boundary =
            v.compare(0, prefix.size(), prefix) == 0 &&
            (v.size() == prefix.size() ||
             (v.size() > prefix.size() && v[prefix.size()] == '.'));
        if (boundary && (!best_prefix || prefix.size() > best_prefix->size()))
            best_prefix = &prefix;
    }

    if (best_prefix) {
        m.vendor     = table.at(*best_prefix);
        m.confidence = "high";
    } else {
        m.vendor     = "";
        m.confidence = "low";  // OID retrieved but unmapped
    }
    return m;
}

ProbeResult SnmpProbe::run(const std::string& host, int port) {
    double start = utils::monotonic_ms();
    int    p     = port > 0 ? port : 161;

    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", p);

    if (getaddrinfo(host.c_str(), port_str, &hints, &res) != 0) {
        records_.push_back({host, p, kDefaultOid, "", "", "none"});
        return {host, Protocol::UDP, p, "error",
                utils::monotonic_ms() - start, "getaddrinfo failed"};
    }

    int fd = socket(res->ai_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        records_.push_back({host, p, kDefaultOid, "", "", "none"});
        return {host, Protocol::UDP, p, "error",
                utils::monotonic_ms() - start, std::strerror(errno)};
    }

    std::vector<uint8_t> req = build_get_request(community_, kDefaultOid);
    sendto(fd, req.data(), req.size(), 0, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(fd, &rset);
    timeval tv;
    tv.tv_sec  = static_cast<long>(timeout_sec_);
    tv.tv_usec = static_cast<long>((timeout_sec_ - tv.tv_sec) * 1e6);

    SnmpRecord rec;
    rec.host       = host;
    rec.port       = p;
    rec.oid        = kDefaultOid;

    std::string status = "open|filtered";
    uint8_t buf[2048];
    int rc = select(fd + 1, &rset, nullptr, nullptr, &tv);
    if (rc > 0) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        std::string value;
        if (n > 0 && extract_response_value(buf, static_cast<size_t>(n),
                                            value)) {
            status           = "open";
            rec.raw_value    = value;
            auto m           = classify_oid(value);
            rec.vendor_guess = m.vendor;
            rec.confidence   = m.confidence;  // "high" or "low"
        }
    }
    close(fd);

    if (rec.confidence.empty()) {
        rec.vendor_guess = "";
        rec.confidence   = "none";  // query failed / timed out / error reply
    }
    records_.push_back(rec);

    return {host, Protocol::UDP, p, status,
            utils::monotonic_ms() - start, std::nullopt};
}

void append_snmp_result_to_session(const std::string& session_json_path,
                                   const SnmpRecord& record) {
    std::ifstream f(session_json_path);
    if (!f) return;
    std::string raw{std::istreambuf_iterator<char>(f), {}};

    std::ostringstream obj;
    obj << "{\n"
        << "        \"oid\": \"" << record.oid << "\",\n"
        << "        \"raw_value\": \"" << record.raw_value << "\",\n"
        << "        \"vendor_guess\": \"" << record.vendor_guess
        << "\",\n"
        << "        \"confidence\": \"" << record.confidence << "\"\n"
        << "      }";

    std::string block = "\"snmp_result\": " + obj.str();

    auto key = raw.find("\"snmp_result\"");
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

}  // namespace iskabon::probes
