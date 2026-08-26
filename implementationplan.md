# Trinetra Implementation Plan

## Phase 1: repository and structure
- Create Java module/file layout.
- Create `sessions/`, `stat_scripts/`, `output/`, and config layout. (hex_scripts/ later removed with HexStrike)
- Define shared utilities for file IO, JSON IO, shell execution, timestamps, and logging.

## Phase 2: session core
- Implement session directory creation.
- Implement session JSON bootstrap.
- Implement per-session brain markdown bootstrap.
- Implement per-session state JSON bootstrap.
- Implement global `brain_state.json` bootstrap.

## Phase 3: trinetra_pen.java beta path (superseded — TrinetraPen and HexStrike removed; see trinetra_stat.java)
- Hardcode beta V-code to shell-script mapping.
- Implement `-pen -hex run` dispatcher.
- Capture stdout/stderr, exit code, timestamps, target, script path.
- Append normalized finding object to session JSON.
- Mark finding as summarized or unsummarized depending on result.

## Phase 4: AI summarization integration
- Add OpenRouter request pacing in `trinetra_pen.java` or common orchestration layer.
- Implement 401/402 fallback key retry.
- Parse summary response.
- Write summarization metadata into finding record.

## Phase 5: brain update engine
- Implement markdown section-aware patching.
- Implement byte-size and token-estimation threshold checks.
- Implement compression workflow with one rotating backup file.
- Implement `brain_state_<session>.json` refresh.
- Implement global `brain_state.json` refresh.

## Phase 6: `-mind`
- Implement `-mind -read`.
- Implement `-mind -update`.
- Implement `-mind -suggest` with dual output.
- Implement `-mind -overall` using global state only.

## Phase 7: aggregation
- Implement `trinetra -agr [cert] [session]`.
- Start with one beta cert mode.
- Read only session JSON findings.
- Write scorecard into session directory.

## Phase 8: IDE integration
- Port essential `-ide` functions.
- Add optional session copy behavior for `-ide -r`.
- Ensure file execution and copy semantics are deterministic.

## Phase 9: beta hardening
- Add logging.
- Add schema validation.
- Add duplicate V-code guardrails.
- Add stale brain recovery handling.
- Add dry-run and doctor-style diagnostics.

## Beta milestone definition
The beta is ready when a user can:
- run a selected V-code,
- persist findings in a session,
- query the session with `-mind`,
- receive a next-step suggestion,
- and generate one cert-aligned scorecard.
