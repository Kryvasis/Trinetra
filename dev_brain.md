# Trinetra Beta — Development Brain

## Last updated
2026-08-26 (v4 — HexStrike integration fully removed)

## v4 change: HexStrike removed
HexStrike (MCP server / REST tool orchestration at `http://127.0.0.1:8888/api/command`)
was dropped from Trinetra's scope entirely; the product is an AI-driven
multi-vendor network security compliance auditor. Removed in v4:
- `src/TrinetraPen.java` (the HexStrike client/dispatcher) and all 131
  `hex_scripts/V-*.sh` scripts that called the HexStrike API.
- CLI commands `-pen` and `-run`/`-stop`/`-status`; Makefile targets
  `run`/`stop`/`status`/`logs`/`test-api` and the `hexstrike_server`
  lifecycle/PID/log/port configuration.
- `-doctor` checks for the HexStrike config dir, API key file, and server
  process.
- Config keys moved to a neutral `~/.trinetra/` dir (legacy `~/.hexsrtike/`
  still read as a fallback so existing OpenRouter/Gemini keys keep working).
Compliance testing now runs entirely through the stat engine
(`trinetra -stat ...`, `stat_scripts/`). Historical v3 notes below describe
the pre-removal state.

## Last updated (v3)
2026-07-25 (v3 — trinetra_brain + trinetra_stat dual-engine integration)

## What was implemented (v3, historical)
Complete vertical slice of the Trinetra beta framework (Phases 1-8) + HexStrike Makefile + 131 V-code scripts.

### Directory structure (v3, historical — hex engine removed in v4)
- `src/` — Java source files
- `hex_scripts/` — REMOVED in v4 (were 131 HexStrike-client scripts)
- `stat_scripts/` — compliance-relevant stat engine scripts
- `sessions/` — session storage
- `output/` — output directory
- `out/` — compiled class files
- `Makefile` — build/test/diagnostics (HexStrike lifecycle targets removed in v4)

### Core Java files
- **TrinetraJson.java**: Minimal JSON parser/builder (no external dependencies). Handles construction, parsing, and pretty-printing.
- **TrinetraCommon.java**: Shared utilities — file I/O, atomic writes, timestamps, shell execution, OpenRouter API calls with rate limiting, Gemini CLI integration, JSON helpers, logging.
- **TrinetraSession.java**: Session lifecycle — create, load, append findings, bootstrap brain markdown/state, refresh global state, state machine.
- **TrinetraBrain.java**: Brain update engine — incremental markdown patching, compression with rotating backup, query via Gemini CLI, suggestion engine with structured output, CVE/certificate scoring.
- **TrinetraStat.java**: Compliance decision engine — loads 2_static_map.json + 3_decision_engine.csv, executes `stat_scripts/`, applies eval methods (grep_present, grep_absent, exit_code_zero, numeric_threshold, regex_match), writes verdicts to session.json.
- **TrinetraAgr.java**: Aggregation — reads session JSON, computes severity heuristics, generates scorecard markdown with scoring algorithm.
- **TrinetraIde.java**: IDE helpers — run scripts, copy files to session artifacts, list sessions/artifacts.
- **Trinetra.java**: Main entry point — CLI argument parsing, command dispatch for -stat, -mind, -agr, -compliance-score/-report, and -doctor.
- **TrinetraPen.java**: REMOVED in v4 (was the HexStrike client layer).

### Shell scripts (v3, historical — hex engine removed in v4)
The 131 former hex_scripts called the HexStrike API and appended findings to
session JSON directly. That contract is gone; only `stat_scripts/` remain
(contract: `bash <code>.sh <TARGET> <SESSION_DIR>`, tools invoked directly).

## Verified behavior
- `trinetra -help` — prints usage
- `trinetra -new test1 example.com` — creates session with all artifacts
- `trinetra -sessions` — lists sessions
- (v3, historical) `trinetra -pen -hex run V-025 test1 example.com` — hex engine removed in v4
- (v3, historical) `trinetra -pen -hex run V-001 test1 example.com` — hex engine removed in v4
- (v3, historical) `trinetra -pen -hex run V-040 test1 example.com` — hex engine removed in v4
- `trinetra -mind -suggest test1` — returns suggestion (falls back to first available V-code when Gemini CLI unavailable)
- `trinetra -agr default test1` — generates scorecard with scoring
- Global `brain_state.json` tracks cross-session activity

## Command contracts implemented
- `trinetra -stat run <V-XXX> <session> <target>` ✓ (`-pen -hex` removed in v4)
- `trinetra -stat run <V-XXX> <session> <target>` ✓
- `trinetra -stat run-all <session> <target>` ✓
- `trinetra -stat status <session>` ✓
- `trinetra -mind -read <session> "query"` ✓
- `trinetra -mind -update <session>` ✓
- `trinetra -mind -suggest <session>` ✓
- `trinetra -mind -overall "query"` ✓
- `trinetra -mind -score <session>` ✓
- `trinetra -agr [cert] <session>` ✓
- `trinetra -new <session> <target>` ✓
- `trinetra -sessions` ✓
- `trinetra -ide -r <script> [args...]` ✓
- `trinetra -ide -cp <source> <session>` ✓

## Known limitations / technical debt
1. **Gemini CLI not installed on this system** — -mind -read, -update, -suggest, -overall fall back to raw data when Gemini unavailable.
2. **OpenRouter summarization not integrated into the test runners** — stat scripts handle their own execution; findings are stored unsummarized.
3. **Brain markdown patching is basic** — works but could be more robust section-aware insertion.
4. **No duplicate V-code guardrail** — running the same V-code twice creates duplicate findings.
5. **Score severity is heuristic-based** — no real vulnerability classification data yet.
6. **No logging to file** — all logging goes to stderr only.
7. **Brain compression threshold test** — not triggered in testing (brain too small).

## Verified
- (v3, historical) `-pen -hex run V-003` → nmap finding appended; engine removed in v4
- (v3, historical) `-pen -hex run V-001` → theharvester finding appended; engine removed in v4
- (v3, historical) `-pen -hex run V-050` → nuclei finding appended; engine removed in v4
- All 131 scripts patched for Trinetra session dict format ✓
- Makefile `make test-api` verified working ✓

## Schema adherence
All files follow `schema.md`:
- Session JSON: ✓ session_name, target, created_at, updated_at, findings array with finding_id, v_code, etc.
- Brain state JSON: ✓ state, last_updated, byte_size, estimated_tokens, already_run_v_codes, counts, suggestion_history
- Global brain state JSON: ✓ last_updated, active_sessions, session_count, recent_activity
- Brain markdown: ✓ Session Overview, Findings Summary, Key Observations, Recommendations sections

## Next recommended steps
1. **Install Gemini CLI** or implement alternative LLM backend for -mind commands
2. **Add duplicate V-code guardrail** in statRun() (was TrinetraPen.run(), removed in v4)
3. **Add file-based logging** (session-specific log files)
4. **Improve brain markdown patching** — more robust section-aware insertion
5. **Add integration test** that triggers brain compression
6. **Phase 9: Beta hardening** — schema validation, doctor diagnostics, dry-run mode

---

## Session: 2026-07-25 — trinetra_brain + trinetra_stat Integration (v3)

### What was built
Complete integration of the dual-engine architecture: trinetra_brain.java (brain layer) and trinetra_stat.java (static decision engine), wired into the main orchestrator with 158 stat scripts.

### Files touched/created
| File | Action | Purpose |
|------|--------|---------|
| `src/TrinetraBrain.java` | **Modified** | Added `brainScore()` method for CVE/certificate scoring; API aligned to spec (brainUpdate, brainCompress, brainRead, brainSuggest, brainOverall, brainScore) |
| `src/TrinetraStat.java` | **Created** | Decision engine + static test executor: loads 2_static_map.json + 3_decision_engine.csv, executes stat_scripts/, applies eval methods, writes to session.json |
| `src/Trinetra.java` | **Modified** | Added `-stat` flag family (run, run-all, status), `-mind -score` flag, updated help text, updated doctor diagnostics to show stat_scripts |
| `stat_scripts/*.sh` | **Created (158)** | 123 stat-owned scripts (tool_parsing + custom_script) + 35 pen_req delegation scripts |

### Decisions made
1. **TrinetraBrain already existed** — it was not inline in the (now removed) pen dispatcher. The task was to add `brainScore()` and align the public API to the spec. All existing methods preserved.
2. **DecisionEngine is a stateless inner class** within TrinetraStat — pure `evaluate()` method takes (evalMethod, rawOutput, exitCode) and returns Verdict enum. Testable independent of file I/O.
3. **Eval method priority**: For grep_present/grep_absent, fail criteria checked first (fail takes precedence to avoid false negatives).
4. **Script contract**: `bash stat_scripts/<code>.sh <target> <session_output_dir>` — same positional args as hex_scripts but reversed order (target first, matching stat engine expectations).
5. **Stat scripts pruned to compliance-relevant set (v4)**: former pen_req delegations shelling out to `-pen -hex` are gone with the hex engine.
6. **Session JSON is shared**: Both trinetra_pen and trinetra_stat append to the same `sessions/<session>/<session>.json` findings array, with an `"engine"` field distinguishing them.

### Flag syntax implemented
```
# Static engine
trinetra -stat run <V-XXX> <session> <target>       # Run single stat test
trinetra -stat run-all <session> <target>           # Run all 123 stat tests
trinetra -stat status <session>                     # Print pass/fail/review tally

# Brain layer (existing + new)
trinetra -mind -read <session> "query"              # Query session brain
trinetra -mind -update <session>                    # Incremental brain patch
trinetra -mind -suggest <session>                   # Next V-code suggestion
trinetra -mind -overall "query"                     # Cross-session query
trinetra -mind -score <session>                     # CVE/certificate scoring (NEW)
```

### Verified behavior
- `trinetra -help` — shows all commands including new -stat and -mind -score ✓
- `trinetra -doctor` — shows stat_scripts/ OK, 123 definitions loaded ✓
- `trinetra -stat status demo` — reports 0 stat tests run, 123 defined ✓
- (v3, historical) `-pen -hex run V-003 ... --dry-run` — pen dry-run; engine removed in v4
- `trinetra -mind -update demo` — brain patch still works ✓
- `javac` compilation — clean build, no errors ✓

### Known limitations
1. **pen_req fallback scripts removed with the hex engine (v4)** — compliance-relevant checks live in stat_scripts/ and run standalone
2. **numeric_threshold eval** uses simple regex extraction — may miss complex output formats (e.g. multi-line metrics)
3. **grep_present/grep_absent criteria matching** is case-insensitive substring search — no full regex for criteria strings (though regex_match eval method supports regex)
4. **No duplicate V-code guardrail** in TrinetraStat.statRun() — running the same test twice creates duplicate findings
5. **Brain compression threshold** still not triggered in testing (brain too small)
6. **Gemini CLI available** but rate limits may cause fallback to raw data
7. **TrinetraStat.statRunAll()** runs 123 tests sequentially — no parallelization

### What remains incomplete / deferred
1. Real-target validation of stat scripts against live systems
2. Retry/backoff around Gemini Flash calls in TrinetraBrain
3. Duplicate V-code guardrail in both pen and stat engines
4. Integration test that triggers brain compression with large finding sets
5. Parallelized stat-run-all for faster execution

### Next session should read first
- `dev_brain.md` (this file) for context recovery
- `src/TrinetraStat.java` — the new decision engine, likely needs hardening
- `3_decision_engine.csv` — may need new test entries
- `stat_scripts/` — scripts need real-target validation
