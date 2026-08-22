#include "probes/banner_probe.hpp"
#include "utils/time_utils.hpp"
#include <arpa/inet.h>
#include <fcntl.h>
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

constexpr size_t kMaxBannerBytes = 4096;

bool is_supported(int p) {
    return p == 21 || p == 22 || p == 23 || p == 80 || p == 443;
}

bool uses_request(int p) { return p == 80 || p == 443; }

std::string trim(const std::string& s) {
    auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::string rstrip_punct(const std::string& s) {
    auto e = s.find_last_not_of(",.;)]}\"'");
    if (e == std::string::npos) return {};
    return s.substr(0, e + 1);
}

bool word_like(const std::string& t) {
    if (t.size() < 2) return false;
    if (!std::isalpha(static_cast<unsigned char>(t[0]))) return false;
    for (char c : t)
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' &&
            c != '_')
            return false;
    return true;
}

bool version_like(const std::string& t) {
    if (t.empty() || !std::isdigit(static_cast<unsigned char>(t[0])))
        return false;
    bool dot = false, alldigit = true;
    for (char c : t) {
        unsigned char u = static_cast<unsigned char>(c);
        if (!std::isdigit(u)) alldigit = false;
        if (c == '.') dot = true;
        if (!std::isdigit(u) && c != '.' && c != 'p' && c != 'a' && c != 'b')
            return false;
    }
    return dot || alldigit;
}

std::vector<std::string> tokenize(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        unsigned char u = static_cast<unsigned char>(c);
        if (u == ' ' || u == '\t' || u == '\r' || u == '\n' || c == '(' ||
            c == ')' || c == ',' || c == ';' || c == ':') {
            if (!cur.empty()) out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

std::string sanitize(const char* data, ssize_t n) {
    std::string out;
    out.reserve(static_cast<size_t>(n));
    for (ssize_t i = 0; i < n; ++i) {
        unsigned char c = static_cast<unsigned char>(data[i]);
        if ((c >= 0x20 && c <= 0x7e) || c == '\r' || c == '\n' || c == '\t')
            out.push_back(static_cast<char>(c));
        else
            out.push_back('.');
    }
    return out;
}

std::string recv_deadline(int fd, double timeout_sec) {
    std::string banner;
    double deadline = utils::monotonic_ms() + timeout_sec * 1000.0;
    char buf[1024];
    while (banner.size() < kMaxBannerBytes) {
        double remain_ms = deadline - utils::monotonic_ms();
        if (remain_ms <= 0) break;
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(fd, &rset);
        timeval tv;
        tv.tv_sec  = static_cast<long>(remain_ms / 1000.0);
        tv.tv_usec = static_cast<long>((remain_ms / 1000.0 - tv.tv_sec) * 1e6);
        int rc     = select(fd + 1, &rset, nullptr, nullptr, &tv);
        if (rc <= 0) break;
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        banner.append(sanitize(buf, n));
        if (banner.size() >= kMaxBannerBytes) break;
    }
    return trim(banner.substr(0, kMaxBannerBytes));
}

std::string json_escape(const std::string& s) {
    std::ostringstream o;
    for (unsigned char c : s) {
        switch (c) {
        case '"': o << "\\\""; break;
        case '\\': o << "\\\\"; break;
        case '\n': o << "\\n"; break;
        case '\r': o << "\\r"; break;
        case '\t': o << "\\t"; break;
        default:
            if (c < 0x20) {
                char b[8];
                snprintf(b, sizeof(b), "\\u%04x", c);
                o << b;
            } else {
                o << static_cast<char>(c);
            }
        }
    }
    return o.str();
}

}  // namespace

BannerProbe::BannerProbe(double timeout_sec) : timeout_sec_(timeout_sec) {}

bool BannerProbe::supported_port(int port) { return is_supported(port); }

bool BannerProbe::sends_request(int port) { return uses_request(port); }

BannerProbe::Guess BannerProbe::parse_vendor_version(const std::string& raw_banner) {
    Guess g;
    std::string s = trim(raw_banner);
    if (s.empty()) return g;

    if (s.rfind("SSH-", 0) == 0) {
        auto dash = s.find('-', 4);
        if (dash == std::string::npos) return g;
        std::string rest = trim(s.substr(dash + 1));
        if (rest.empty()) return g;
        auto us = rest.find('_');
        if (us != std::string::npos) {
            g.vendor  = rest.substr(0, us);
            std::string ver = trim(rest.substr(us + 1));
            auto       sp  = ver.find(' ');
            g.version = rstrip_punct(sp == std::string::npos
                                         ? ver
                                         : ver.substr(0, sp));
        } else {
            auto sp = rest.find(' ');
            g.vendor = rstrip_punct(sp == std::string::npos
                                        ? rest
                                        : rest.substr(0, sp));
        }
        return g;
    }

    auto toks = tokenize(s);

    for (const auto& t : toks) {
        auto slash = t.find('/');
        if (slash == std::string::npos) continue;
        std::string name = t.substr(0, slash);
        std::string ver  = rstrip_punct(t.substr(slash + 1));
        if (name == "HTTP") continue;
        if (word_like(name) && version_like(ver)) return {name, ver};
    }

    for (size_t i = 0; i + 1 < toks.size(); ++i) {
        if (toks[i] == "Server" || toks[i] == "HTTP") continue;
        std::string ver = rstrip_punct(toks[i + 1]);
        if (word_like(toks[i]) && version_like(ver))
            return {toks[i], ver};
    }

    return g;
}

const std::vector<BannerRecord>& BannerProbe::results() const {
    return records_;
}

ProbeResult BannerProbe::run(const std::string& host, int port) {
    double start = utils::monotonic_ms();

    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host.c_str(), port_str, &hints, &res) != 0) {
        records_.push_back({host, port, "tcp", "", "", ""});
        return {host, Protocol::TCP, port, "error",
                utils::monotonic_ms() - start, "getaddrinfo failed"};
    }

    int fd = socket(res->ai_family, SOCK_STREAM, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        records_.push_back({host, port, "tcp", "", "", ""});
        return {host, Protocol::TCP, port, "error",
                utils::monotonic_ms() - start, std::strerror(errno)};
    }

    fcntl(fd, F_SETFL, O_NONBLOCK);
    connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(fd, &wset);
    timeval tv;
    tv.tv_sec  = static_cast<long>(timeout_sec_);
    tv.tv_usec = static_cast<long>((timeout_sec_ - tv.tv_sec) * 1e6);

    std::string status = "closed";
    int rc             = select(fd + 1, nullptr, &wset, nullptr, &tv);
    if (rc > 0) {
        int       err = 0;
        socklen_t len = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
        status = (err == 0) ? "open" : "closed";
    }

    std::string raw;
    if (status == "open") {
        if (uses_request(port)) {
            std::string req = "HEAD / HTTP/1.0\r\nHost: " + host +
                              "\r\nUser-Agent: Iskabon-BannerProbe/0.1\r\n\r\n";
            send(fd, req.data(), req.size(), MSG_NOSIGNAL);
        }
        raw = recv_deadline(fd, timeout_sec_);
    }
    close(fd);

    Guess g = parse_vendor_version(raw);
    records_.push_back({host, port, "tcp", raw, g.vendor, g.version});

    return {host, Protocol::TCP, port, status,
            utils::monotonic_ms() - start, std::nullopt};
}

void append_banner_results_to_session(
    const std::string& session_json_path,
    const std::vector<BannerRecord>& records) {
    if (records.empty()) return;

    std::ifstream f(session_json_path);
    if (!f) return;
    std::string raw{std::istreambuf_iterator<char>(f), {}};

    std::ostringstream arr;
    arr << "[\n";
    for (size_t i = 0; i < records.size(); ++i) {
        const auto& r = records[i];
        arr << "      {\n"
            << "        \"host\": \"" << json_escape(r.host) << "\",\n"
            << "        \"port\": " << r.port << ",\n"
            << "        \"protocol\": \"" << json_escape(r.protocol)
            << "\",\n"
            << "        \"raw_banner\": \""
            << json_escape(r.raw_banner) << "\",\n"
            << "        \"vendor_guess\": \""
            << json_escape(r.vendor_guess) << "\",\n"
            << "        \"version_guess\": \""
            << json_escape(r.version_guess) << "\"\n"
            << "      }" << (i + 1 < records.size() ? ",\n" : "\n");
    }
    arr << "    ]";

    std::string block =
        "\"banner_results\": " + arr.str();

    auto key = raw.find("\"banner_results\"");
    if (key != std::string::npos) {
        auto lb = raw.find('[', key);
        if (lb != std::string::npos) {
            bool in_str = false;
            size_t rb   = lb;
            for (size_t i = lb; i < raw.size(); ++i) {
                char c = raw[i];
                if (in_str && c == '\\') { ++i; continue; }
                if (c == '"') in_str = !in_str;
                if (!in_str && c == ']') { rb = i; break; }
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
