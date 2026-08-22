#pragma once
#include <filesystem>
#include <mutex>
#include <string>
#include "probes/scanner.hpp"
#include "utils/types.hpp"

namespace iskabon::session {

namespace fs = std::filesystem;

class SessionStore {
public:
    explicit SessionStore(const std::string& session_name);

    /// Write header metadata; call once before scanning.
    void init(const std::string& target_router, const std::string& target);

    /// Append a single probe result (thread-safe).
    void append(const ProbeResult& r);

    /// Write final stats (call after scan completes).
    void finalize(const probes::ScanStats& stats);

    fs::path path() const { return session_path_; }

private:
    std::string  session_name_;
    fs::path     session_dir_;
    fs::path     session_path_;
    std::mutex   lock_;

    void atomic_write(const std::string& json_str);
    std::string read_raw() const;
};

}  // namespace iskabon::session
