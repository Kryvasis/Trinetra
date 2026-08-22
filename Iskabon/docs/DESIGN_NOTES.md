# Iskabon – Design Notes

## SDLC Model: Waterfall
All modules are designed upfront and implemented in one pass.

## Command shape
```
iskabon <session_name> <target_router> <target> [--protocols all|icmp,tcp,udp] [--workers N] [--timeout S]
```

## Module boundaries (minimal coupling)

| Layer | Responsibility | Depends on |
|-------|----------------|-----------|
| `cli` | Parse argv → `Args` struct | `utils/types` |
| `resolver` | hostname / IP / CIDR → `vector<string>` | POSIX sockets |
| `planner` | hosts + protocols → `vector<ProbeJob>` | `utils/types` |
| `probes` | Execute one job → `ProbeResult` | POSIX sockets, `utils` |
| `session` | Atomic JSON persistence | `utils`, filesystem |
| `utils` | SHA-256, color, time, shared types | stdlib only |
| `main` | Wires layers; owns lifetime | all of the above |

No layer directly touches another layer's internals.
All inter-layer communication is through plain structs.

## Logo integrity
`LOGO_SHA256` is checked at startup. Any modification to the
banner string causes immediate abort. Upstream CI should also
run `make test` which will eventually include a logo-hash check.

Note: This cannot prevent someone from changing their local clone.
What it guarantees is that a modified binary will refuse to run
with the official Iskabon branding.

## Thread safety
- `SessionStore` owns a `std::mutex`; all JSON writes are atomic (write-to-tmp + rename).
- `Scanner` uses a mutex-guarded work queue; `ResultCallback` is called under a per-scanner mutex.
- Probes are stateless objects instantiated per worker thread; no shared mutable state.

## No continuous discovery
Scan is run-based only. Each invocation appends to the same session JSON
but does not loop or poll continuously.

## Protocol fallback
| Protocol | Requirements | Fallback |
|----------|--------------|---------|
| TCP | none | — |
| UDP | none | — |
| ICMP | `CAP_NET_RAW` or root | TCP liveness probe on ports 80/443/22 |
