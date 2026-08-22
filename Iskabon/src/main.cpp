#include <iostream>
#include <stdexcept>

#include "cli/args.hpp"
#include "probes/scanner.hpp"
#include "planner/planner.hpp"
#include "resolver/resolver.hpp"
#include "session/session_store.hpp"
#include "utils/constants.hpp"
#include "utils/sha256.hpp"
#include "utils/color.hpp"

int main(int argc, char** argv) {
    // ── 1. Banner + integrity gate ───────────────────────────────────────
    std::cout << iskabon::LOGO << '\n';
    const std::string actual = iskabon::utils::sha256(iskabon::LOGO);
    if (actual != std::string(iskabon::LOGO_SHA256)) {
        std::cerr << "[ABORT] Logo integrity check failed. "
                     "Refusing to run a modified banner.\n";
        return 1;
    }

    // ── 2. Parse arguments ───────────────────────────────────────────────
    iskabon::cli::Args args;
    try {
        args = iskabon::cli::parse(argc, argv);
    } catch (const std::exception& ex) {
        std::cerr << "[ERROR] " << ex.what() << '\n';
        iskabon::cli::print_usage(argv[0]);
        return 1;
    }

    // ── 3. Resolve target to host list ───────────────────────────────────
    std::vector<std::string> hosts;
    try {
        hosts = iskabon::resolver::expand(args.target);
    } catch (const std::exception& ex) {
        std::cerr << "[ERROR] " << ex.what() << '\n';
        return 1;
    }

    // ── 4. Build probe plan ──────────────────────────────────────────────
    const auto jobs = iskabon::planner::build(hosts, args.protocols);
    std::cout << "[*] Session     : " << args.session_name    << '\n'
              << "[*] Router      : " << args.target_router   << '\n'
              << "[*] Target      : " << args.target          << '\n'
              << "[*] Hosts       : " << hosts.size()         << '\n'
              << "[*] Probe jobs  : " << jobs.size()          << '\n';

    // ── 5. Open session store ────────────────────────────────────────────
    iskabon::session::SessionStore store(args.session_name);
    store.init(args.target_router, args.target);

    // ── 6. Run scan ──────────────────────────────────────────────────────
    iskabon::probes::Scanner scanner(args.workers, args.timeout);
    const auto stats = scanner.run(jobs, [&](const iskabon::ProbeResult& r) {
        store.append(r);
        // Live output – print only interesting findings
        if (r.status.find("open") != std::string::npos ||
            r.status == "up") {
            std::string line = "[" + iskabon::protocol_str(r.protocol) + "] ";
            line += r.host;
            if (r.port.has_value()) line += ":" + std::to_string(*r.port);
            line += " -> " + r.status;
            if (r.latency_ms) line += " (" + std::to_string(*r.latency_ms) + " ms)";
            std::cout << line << '\n';
        }
    });

    // ── 7. Finalize ──────────────────────────────────────────────────────
    store.finalize(stats);
    std::cout << "\n[+] Session : " << store.path().string() << '\n'
              << "[+] Open    : " << stats.open_count
              << "  Closed: "     << stats.closed
              << "  Errors: "     << stats.errors
              << "  Time: "       << stats.elapsed_s << "s\n";
    return 0;
}
