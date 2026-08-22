# Trinetra Beta — Development Brain

## Last updated
2026-07-25 (v3 — trinetra_brain + trinetra_stat dual-engine integration)

## What was implemented
Complete vertical slice of the Trinetra beta framework (Phases 1-8) + HexStrike Makefile + 131 V-code scripts.

### Directory structure
- `src/` — 9 Java source files (TrinetraBrain + TrinetraStat added)
- `hex_scripts/` — 131 shell scripts (V-001.sh through V-131.sh) — pen engine
- `stat_scripts/` — 158 shell scripts (123 stat-owned + 35 pen_req delegations) — stat engine
- `sessions/` — session storage
- `output/` — output directory
- `out/` — compiled class files
- `Makefile` — HexStrike lifecycle management

### Core Java files
- **TrinetraJson.java**: Minimal JSON parser/builder (no external dependencies). Handles construction, parsing, and pretty-printing.
- **TrinetraCommon.java**: Shared utilities — file I/O, atomic writes, timestamps, shell execution, OpenRouter API calls with rate limiting, Gemini CLI integration, JSON helpers, logging.
- **TrinetraSession.java**: Session lifecycle — create, load, append findings, bootstrap brain markdown/state, refresh global state, state machine.
- **TrinetraBrain.java**: Brain update engine — incremental markdown patching, compression with rotating backup, query via Gemini CLI, suggestion engine with structured output, CVE/certificate scoring.
- **TrinetraPen.java**: Pentest execution — dynamic V-code discovery from `hex_scripts/V-*.sh`, invokes scripts with `<session> <target>`, reads back findings appended by scripts.
- **TrinetraStat.java**: Static decision engine — loads 2_static_map.json + 3_decision_engine.csv, executes `stat_scripts/`, applies eval methods (grep_present, grep_absent, exit_code_zero, numeric_threshold, regex_match), writes verdicts to session.json.
- **TrinetraAgr.java**: Aggregation — reads session JSON, computes severity heuristics, generates scorecard markdown with scoring algorithm.
- **TrinetraIde.java**: IDE helpers — run scripts, copy files to session artifacts, list sessions/artifacts.
- **Trinetra.java**: Main entry point — CLI argument parsing, command dispatch for all subcommands including -pen, -stat, and -mind.

### Shell scripts (131 scripts, V-001 through V-131)
- Naming: `V-XXX.sh` (no descriptive suffix)
- Contract: `bash V-XXX.sh <SESSION> <TARGET>`
- Scripts call HexStrike API at `http://127.0.0.1:8888/api/command`
- Scripts append findings to session JSON directly (dict format with `findings` key)
- ROOT resolves one level up from `hex_scripts/`

### HexStrike Makefile
- `make run` — starts hexstrike_server (validates API key, guards against stale PIDs)
- `make stop` — stops server
- `make status` — checks if running
- `make logs` — tails log file
- `make test-api` — tests OpenRouter API key
- Config dir: `/home/kali/.hexsrtike`
- API key file: `/home/kali/.hexsrtike/openrouter_api_key` (chmod 600)
- Default model: `nvidia/nemotron-3-ultra-550b-a55b:free`

## Verified behavior
- `trinetra -help` — prints usage
- `trinetra -new test1 example.com` — creates session with all artifacts
- `trinetra -sessions` — lists sessions
- `trinetra -pen -hex run V-025 test1 example.com` — executes shell script, captures output, appends finding, updates brain
- `trinetra -pen -hex run V-001 test1 example.com` — second finding appended correctly
- `trinetra -pen -hex run V-040 test1 example.com` — third finding
- `trinetra -mind -suggest test1` — returns suggestion (falls back to first available V-code when Gemini CLI unavailable)
- `trinetra -agr default test1` — generates scorecard with scoring
- Global `brain_state.json` tracks cross-session activity

## Command contracts implemented
- `trinetra -pen -hex run <V-XXX> <session> <target>` ✓
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
2. **OpenRouter summarization not integrated into TrinetraPen** — scripts now handle their own execution via HexStrike API; TrinetraPen reads back findings.
3. **Brain markdown patching is basic** — works but could be more robust section-aware insertion.
4. **No duplicate V-code guardrail** — running the same V-code twice creates duplicate findings.
5. **Score severity is heuristic-based** — no real vulnerability classification data yet.
6. **No logging to file** — all logging goes to stderr only.
7. **Brain compression threshold test** — not triggered in testing (brain too small).

## Verified
- `trinetra -pen -hex run V-003 test1 scannmap.org` → nmap finding appended ✓
- `trinetra -pen -hex run V-001 test1 scannmap.org` → theharvester finding appended ✓
- `trinetra -pen -hex run V-050 test1 scannmap.org` → nuclei finding appended ✓
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
2. **Add duplicate V-code guardrail** in TrinetraPen.run()
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
1. **TrinetraBrain already existed** — it was not inline in TrinetraPen. The task was to add `brainScore()` and align the public API to the spec. All existing methods preserved.
2. **DecisionEngine is a stateless inner class** within TrinetraStat — pure `evaluate()` method takes (evalMethod, rawOutput, exitCode) and returns Verdict enum. Testable independent of file I/O.
3. **Eval method priority**: For grep_present/grep_absent, fail criteria checked first (fail takes precedence to avoid false negatives).
4. **Script contract**: `bash stat_scripts/<code>.sh <target> <session_output_dir>` — same positional args as hex_scripts but reversed order (target first, matching stat engine expectations).
5. **158 total stat scripts**: 123 from decision engine (tool_parsing/custom_script) + 35 pen_req delegations that shell out to `trinetra -pen -hex run`.
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
- `trinetra -pen -hex run V-003 demo example.com --dry-run` — existing pen still works ✓
- `trinetra -mind -update demo` — brain patch still works ✓
- `javac` compilation — clean build, no errors ✓

### Known limitations
1. **All 35 pen_req fallback scripts delegate to trinetra_pen** — requires HexStrike server running for actual execution
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
