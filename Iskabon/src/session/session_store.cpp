#include "session/session_store.hpp"
#include "utils/constants.hpp"
#include "utils/time_utils.hpp"
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace iskabon::session {

// Must be defined BEFORE constructor — used in SessionStore::SessionStore()
const fs::path SESSIONS_ROOT{"session"};

// Minimal JSON helpers (no third-party deps)
static std::string jkv(const std::string& k, const std::string& v, bool quote = true) {
    return "\"" + k + "\": " + (quote ? ("\"" + v + "\"") : v);
}

SessionStore::SessionStore(const std::string& name)
    : session_name_(name)
{
    session_dir_  = SESSIONS_ROOT / name;
    session_path_ = session_dir_ / (name + ".json");
    fs::create_directories(session_dir_);
}

void SessionStore::init(const std::string& router, const std::string& target) {
    std::lock_guard<std::mutex> lk(lock_);
    std::ostringstream o;
    o << "{\n"
      << "  " << jkv("session",              session_name_)              << ",\n"
      << "  " << jkv("version",              std::string(APP_VERSION))   << ",\n"
      << "  " << jkv("created_at",           utils::iso8601_now())       << ",\n"
      << "  " << jkv("target_router",        router)                     << ",\n"
      << "  " << jkv("target",               target)                     << ",\n"
      << "  " << jkv("continuous_discovery", "false", false)             << ",\n"
      << "  \"findings\": []\n"
      << "}\n";
    atomic_write(o.str());
}

void SessionStore::append(const ProbeResult& r) {
    std::lock_guard<std::mutex> lk(lock_);
    std::string raw = read_raw();

    auto pos       = raw.rfind(']');
    if (pos == std::string::npos) return;
    auto arr_start = raw.rfind('[');
    bool empty     = (pos - arr_start == 1);

    std::ostringstream entry;
    entry << (empty ? "" : ",\n    ") << "{\n"
          << "      " << jkv("host",     r.host)                    << ",\n"
          << "      " << jkv("protocol", protocol_str(r.protocol))  << ",\n";

    if (r.port)
        entry << "      " << jkv("port",       std::to_string(*r.port),       false) << ",\n";

    entry << "      "     << jkv("status",     r.status)                             << ",\n";

    if (r.latency_ms)
        entry << "      " << jkv("latency_ms", std::to_string(*r.latency_ms), false) << ",\n";
    if (r.error)
        entry << "      " << jkv("error",      *r.error)                             << ",\n";

    // Trim the trailing ",\n" before closing the object
    std::string s = entry.str();
    if (s.size() >= 2 && s.substr(s.size() - 2) == ",\n")
        s = s.substr(0, s.size() - 2) + "\n";
    s += "    }";

    raw.insert(pos, (empty ? "\n    " : "") + s + "\n  ");
    atomic_write(raw);
}

void SessionStore::finalize(const probes::ScanStats& st) {
    std::lock_guard<std::mutex> lk(lock_);
    std::string raw = read_raw();

    auto pos = raw.rfind('}');
    if (pos == std::string::npos) return;

    std::ostringstream s;
    s << ",\n  \"stats\": {\n"
      << "    " << jkv("total",      std::to_string(st.total),      false) << ",\n"
      << "    " << jkv("open_count", std::to_string(st.open_count), false) << ",\n"
      << "    " << jkv("closed",     std::to_string(st.closed),     false) << ",\n"
      << "    " << jkv("errors",     std::to_string(st.errors),     false) << ",\n"
      << "    " << jkv("elapsed_s",  std::to_string(st.elapsed_s),  false) << "\n"
      << "  }";
    raw.insert(pos, s.str());
    atomic_write(raw);
}

void SessionStore::atomic_write(const std::string& json_str) {
    fs::path tmp = session_path_.string() + ".tmp";
    {
        std::ofstream f(tmp);
        if (!f) throw std::runtime_error("Cannot open tmp session file: " + tmp.string());
        f << json_str;
    }
    fs::rename(tmp, session_path_);
}

std::string SessionStore::read_raw() const {
    std::ifstream f(session_path_);
    if (!f) return "{}";
    return { std::istreambuf_iterator<char>(f), {} };
}

} // namespace iskabon::session
