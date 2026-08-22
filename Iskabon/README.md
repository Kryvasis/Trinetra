<div align="center">

```
@%+::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::+%@
@:    :@@:                                                                                        :@
%:   :*:#%:                                                                                       :%
%:  .*-..##.                                                                                      :%
%:  **++++%#.                                                                                     :%
%::#*:   .+@#-.                                                                                   :%
%:    .--.                                                                                        :%
%:  .-%@@%:.                                                                                      :%
%: :@@@@@@@%.                                                                                     :%
%: #@@@@@@@@+                                                                                     :%
%:  ...##..                                                                                       :%
%:                                                                                                :%
%:                                                                                                :%
%:                                                                                                :%
%:                                               :=.                                              :%
%:                                              *@@@*                                             :%
%:                                           .+@@@@@@@=.                                          :%
%:                                          -@@@@@@@@@@@-                                         :%
%:                                        -%@@@@@@@@@@@@@%-.                                      :%
%:                                      :#@@@@@@@@@@@@@@@@@%:                                     :%
%:                                    :#@@@@@@@@@@@@@@@@@@@@@#:.                                  :%
%:                                  :#@@@@@@@@@@@@@@@@@@@@@@@@@#:                                 :%
%:                               .:%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#:.                              :%
%:                              :%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%:.                            :%
%:                           .=@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%-.                          :%
%:                         .-@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:.                        :%
%:                       .:@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#..                      :%
%:                      .+@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:                      :%
%:                      #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@-                     :%
%:                    .#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:                    :%
%:                    =@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+                    :%
%:                   .*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*                    :%
%:                    *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@=                    :%
%:                    :@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#.                    :%
%:                     :@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+                      :%
%:                      .=@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*.                       :%
%:                         .+%@@@@@@@@@@@@@@@#+.@@@@%:+#@@@@@@@@@@@@@%+:                          :%
%:                              .:=+***+-..    =@@@@@=.     ..::..                                :%
%:                                           .-@@@@@@@-.                                          :%
%:                                          .=@@@@@@@@@=.                                         :%
%:                                         .#@@@@@@@@@@@%..                                       :%
%:                                       .-@@@@@@@@@@@@@@@=.                                      :%
%:                                      .+@@@@@@@@@@@@@@@@@%.                                     :%
%:                                                                                                :%
%:                                                                                                :%
%:                                                                                                :%
%:                                                                                         :@=..  :%
%:                                                                                      %@@@@@@@@=:%
%:                                                                                      =@@@@@@@#.:%
%:                                                                                       .+@@@*.  :%
%:                                                                                         .+:    :%
%:                                                                                    :+@%-.  .=@+-%
%:                                                                                      -@*====%- :%
%:                                                                                      .=@- .*-  :%
%:                                                                                       .*@-+=.  :%
%:                                                                                        .#@*.   :%
@%=::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::=%@
│                                                                                                  │
│                                            Iskabon by Nil                                        │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

# Iskabon

**Zero-dependency · C++20 · Session-first · Multi-protocol**

[
[
[

</div>

***

## What is Iskabon?

Iskabon is a fast, minimal-dependency network reconnaissance tool written in C++20. It is designed for penetration testers and security researchers who need a single, portable binary that probes TCP, UDP, and ICMP across individual hosts, hostnames, and CIDR ranges — and stores every result in a structured, machine-readable session file for later analysis or pipeline integration.

Unlike Wireshark, tshark, and pyshark — which are **passive packet capture and dissection** tools — Iskabon is an **active probe scanner**: it reaches out to targets, tests reachability, and logs findings per-session. It is purpose-built for red team recon workflows, not traffic analysis.

***

## Key Features

- **Zero runtime dependencies** — pure C++ stdlib + POSIX sockets. No libpcap, no external libraries.
- **Multi-protocol active probing** — TCP connect scan, UDP probe, raw ICMP echo (with graceful TCP fallback when `CAP_NET_RAW` is unavailable).
- **CIDR + hostname resolution** — expand `192.168.1.0/24`, a single IP, or a DNS hostname into a full host list automatically.
- **Session-first output** — every run writes to `session/<name>/<name>.json`. Atomic writes (write-to-tmp + rename) mean the file is never corrupted mid-scan.
- **Concurrency without frameworks** — `std::thread` worker pool with configurable size; no Boost, no Asio.
- **Logo integrity gate** — the ASCII banner is SHA-256 verified at startup. A modified binary refuses to run, protecting the Iskabon brand in forks.
- **System-wide installation** — one `sudo make install` copies the binary to `/usr/local/bin`.
- **No continuous discovery** — scans are run-based. Each invocation is deliberate, not a background daemon.

***

## Installation

### Requirements

| Requirement | Version |
|---|---|
| Linux (POSIX) | Any modern kernel |
| g++ | ≥ 11 (C++20 support) |
| make | GNU make |
| `CAP_NET_RAW` or root | Optional — for real ICMP |

### Build from source

```bash
# 1. Extract the archive
tar -xzf iskabon_src.tar.gz
cd iskabon

# 2. Compile (release build with -O2 -march=native -flto)
make

# 3. Install system-wide (adds `iskabon` to /usr/local/bin)
sudo make install
```

### Verify installation

```bash
iskabon --help
```

### Uninstall

```bash
sudo make uninstall
```

***

## Usage

```
iskabon <session_name> <target_router> <target> [options]
```

| Argument | Description |
|---|---|
| `session_name` | Label for this session; also becomes the directory and filename |
| `target_router` | Router label or IP — stored in session metadata, not actively probed |
| `target` | IP address, hostname, or CIDR range (e.g. `192.168.1.0/24`) |

### Options

| Flag | Default | Description |
|---|---|---|
| `--protocols` | `all` | Comma-separated: `tcp`, `udp`, `icmp`, or `all` |
| `--workers` | `cpu_count × 32` | Worker thread count (max concurrency) |
| `--timeout` | `0.8` | Per-probe timeout in seconds |

### Examples

```bash
# Scan a full subnet with all protocols
iskabon lab-session 192.168.1.1 192.168.1.0/24

# Scan a single host, TCP only, high concurrency
iskabon redteam-01 10.0.0.1 10.0.0.50 --protocols tcp --workers 512

# Scan a hostname with a slower timeout (e.g. across WAN)
iskabon wan-recon 203.0.113.1 target.example.com --timeout 2.0 --protocols tcp,udp

# Run without installing (from project root)
./iskabon pentest 192.168.0.1 192.168.0.100
```

***

## Session Output

Findings are stored at:

```
session/<session_name>/<session_name>.json
```

Example output structure:

```json
{
  "session": "lab-session",
  "version": "0.1.0",
  "created_at": "2026-05-23T11:30:00Z",
  "target_router": "192.168.1.1",
  "target": "192.168.1.0/24",
  "continuous_discovery": false,
  "findings": [
    {
      "host": "192.168.1.10",
      "protocol": "tcp",
      "port": 22,
      "status": "open",
      "latency_ms": 1.42
    },
    {
      "host": "192.168.1.10",
      "protocol": "tcp",
      "port": 80,
      "status": "open",
      "latency_ms": 0.98
    }
  ],
  "stats": {
    "total": 3420,
    "open_count": 12,
    "closed": 3400,
    "errors": 8,
    "elapsed_s": 4.21
  }
}
```

Writes are **atomic** — the file is always valid JSON, even if the process is interrupted mid-scan.

***

## Project Structure

```
iskabon/
├── Makefile
├── README.md
├── docs/
│   └── DESIGN_NOTES.md
├── include/                    ← Headers only; no implementation
│   ├── cli/args.hpp
│   ├── resolver/resolver.hpp
│   ├── planner/planner.hpp
│   ├── probes/
│   │   ├── probe_base.hpp      ← Pure interface (ProbeBase)
│   │   ├── tcp_probe.hpp
│   │   ├── udp_probe.hpp
│   │   ├── icmp_probe.hpp
│   │   └── scanner.hpp
│   ├── session/session_store.hpp
│   └── utils/
│       ├── constants.hpp       ← Logo constant + SHA-256 reference
│       ├── sha256.hpp
│       ├── color.hpp
│       ├── time_utils.hpp
│       └── types.hpp
└── src/                        ← All implementations
    ├── main.cpp
    ├── cli/args.cpp
    ├── resolver/resolver.cpp
    ├── planner/planner.cpp
    ├── probes/
    │   ├── tcp_probe.cpp
    │   ├── udp_probe.cpp
    │   ├── icmp_probe.cpp
    │   └── scanner.cpp
    ├── session/session_store.cpp
    └── utils/
        ├── sha256.cpp
        ├── color.cpp
        ├── time_utils.cpp
        └── types.cpp
```

### Module Boundaries (Minimal Coupling)

Each module communicates exclusively through plain structs. No module accesses the internals of another.

| Module | Responsibility | Depends on |
|---|---|---|
| `cli` | Parse `argv` → `Args` struct | `utils/types` only |
| `resolver` | hostname / IP / CIDR → `vector<string>` | POSIX `getaddrinfo` |
| `planner` | hosts + protocols → `vector<ProbeJob>` | `utils/types` |
| `probes` | Execute one probe → `ProbeResult` | POSIX sockets, `utils` |
| `session` | Atomic JSON persistence | `utils`, `<filesystem>` |
| `utils` | SHA-256, color, time, shared types | stdlib only |
| `main` | Wires all layers; owns object lifetimes | all of the above |

***

## Makefile Reference

```bash
make                # Release build (-O2 -flto -march=native)
make debug          # Debug build (ASAN + UBSan + debug symbols)
make install        # sudo: installs to /usr/local/bin/iskabon
make uninstall      # sudo: removes from /usr/local/bin
make clean          # Removes build/ directory and binaries
make test           # Test runner (extend with your unit tests)
```

***

## Iskabon vs Wireshark / tshark / pyshark

Iskabon and the Wireshark family serve **fundamentally different purposes** and are not in direct competition. The table below clarifies when to use each.

| Dimension | Iskabon | Wireshark | tshark | pyshark |
|---|---|---|---|---|
| **Primary purpose** | Active probe scanner | Passive packet capture & dissection | Passive CLI packet capture | Python wrapper for tshark |
| **Mode** | Active (sends probes) | Passive (listens to traffic) | Passive (listens to traffic) | Passive (wraps tshark) |
| **Protocol support** | TCP, UDP, ICMP (active probes) | 3,000+ protocol dissectors | 3,000+ protocol dissectors | Inherits from tshark |
| **Dependencies** | None (pure C++ stdlib + POSIX) | libpcap, Qt, dozens of libs | libpcap, tshark binary | Python + tshark binary |
| **Live traffic required** | No — probes on demand | Yes — needs NIC in promiscuous mode | Yes — needs NIC access | Yes — wraps tshark |
| **Output format** | Structured session JSON | PCAP / PCAPNG / GUI | JSON / XML / text / PDML | Python objects |
| **Scripting/automation** | First-class (JSON out, CLI flags) | Limited (GUI-first) | Good (`-T json`, pipes) | Good (Python API) |
| **GUI** | None (CLI only) | Full GUI | None | None |
| **Pentest/recon use** | ✅ Designed for it | ❌ Traffic analysis only | ⚠️ Post-capture analysis | ⚠️ Post-capture scripting |
| **Binary size** | Tiny (single static binary) | Large (GUI application) | Medium (ships with Wireshark) | N/A (Python package) |
| **Privilege required** | Root only for raw ICMP | Root / CAP_NET_RAW always | Root / CAP_NET_RAW always | Root / CAP_NET_RAW always |
| **Continuous capture** | ❌ Intentional (run-based) | ✅ Live capture | ✅ Live capture | ✅ Live capture |
| **Session management** | ✅ Built-in per-session JSON | ❌ Manual PCAP file management | ❌ Manual file management | ❌ Manual file management |
| **Language** | C++20 | C | C | Python |

### When to use which

- **Iskabon** — red team recon, service enumeration, host discovery on a target network. You want to know what is alive and what ports are open, logged per-session.
- **Wireshark** — deep interactive inspection of captured packets; protocol debugging; forensic analysis of existing PCAP files.
- **tshark** — automating packet capture and filtering in scripts, SIEM pipelines, or headless servers where Wireshark's GUI is unavailable.
- **pyshark** — Python-based post-capture analysis; when you need to iterate over packet fields programmatically within a Python workflow.

In a real engagement, all four tools complement each other: Iskabon discovers live hosts and open services → tshark/Wireshark captures traffic on identified services → pyshark automates field extraction from captures.

***

## ICMP Privilege Note

Raw ICMP echo requires `CAP_NET_RAW` or root. Without it, Iskabon automatically falls back to a TCP-based liveness check on ports 22, 80, and 443, and marks the result as `up(tcp-fallback)` in the session file. No manual configuration is needed.

To grant capability without running as root:

```bash
sudo setcap cap_net_raw+ep ./iskabon
```

***

## Logo & Branding Policy

The ASCII Ace-of-Spades banner and the name **Iskabon** are authored by Nil. The banner string is SHA-256 verified at binary startup — any modification to the logo causes an immediate abort with an integrity error. Forks of this repository are permitted under the GPL-3.0 license, but modified forks **must not use the Iskabon name or logo** in their releases or documentation.

***

## License

```
Iskabon — Zero-dependency C++ network scanner
Copyright (C) 2026  Nil

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
```

See [LICENSE](./LICENSE) for the full text.

***

## Contributing

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Follow the module boundary rules in `docs/DESIGN_NOTES.md`.
4. Submit a pull request with a clear description of changes.

Do not modify `include/utils/constants.hpp` LOGO or LOGO_SHA256 unless you are Nil or an upstream maintainer — doing so will break the integrity gate and all release builds.

***

<div align="center">
Built by Nil · GPL-3.0 · Kolkata, India
</div>
