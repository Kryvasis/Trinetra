# Trinetra Technical Specification

## Architecture
The beta architecture contains four Java entry components:
- `trinetra.java`: primary orchestrator, session manager, state machine owner, brain update owner, and `-mind` dispatcher.
- `trinetra_ide.java`: IDE utilities, OpenCode-oriented parsing, build/run helpers, and optional session-aware file copy behavior.
- `trinetra_stat.java`: compliance test engine — triggers a stat script, applies decision rules, appends verdicts into session JSON, and maintains the tamper-evident normalized_results chain.
- `trinetra_agr.java`: reads session JSON only, applies cert-specific scoring logic, and writes session-local scorecards.

Note: the former HexStrike-backed pen engine (`trinetra_pen.java`, `hex_scripts/`) was removed along with the HexStrike integration; compliance testing runs entirely through the stat engine.

## Execution model
A compliance run uses:
`trinetra -stat run <V-XXX> <session> <target>`

The flow is:
1. Validate session and target.
2. Resolve hardcoded V-code to shell script path.
3. Execute the script.
4. Capture raw output, metadata, status, timestamps, and artifacts.
5. Append to `sessions/<session>/<session>.json`.
6. Trigger brain update pipeline.
7. Refresh `brain_state_<session>.json`.
8. Optionally refresh global `brain_state.json`.

## AI model usage
Two distinct AI paths are used:
- Tool-output summarization: OpenRouter free tier with Nemotron 3 Ultra, paced centrally because OpenRouter free usage is rate-limited.[cite:78]
- Brain and memory reasoning: Gemini CLI using Gemini 2.5 Flash-Lite as the cheapest stable long-context option.[cite:191][cite:205]

## Brain pipeline
Each session maintains:
- `brain_<session>.md`
- `brain_state_<session>.json`

Brain markdown is patched incrementally. If byte size and estimated token count exceed configured thresholds, Trinetra reads the entire session brain and session findings, writes a backup to `brain_<session>.bak.md`, then regenerates a compressed `brain_<session>.md` using Gemini CLI context management patterns.[cite:206][cite:203]

## `-mind` modes
- `-mind -read [session] "query"`: answer using session brain markdown plus session state.
- `-mind -update [session]`: force session brain/state refresh.
- `-mind -suggest [session]`: derive next recommended V-code using `brain_state_<session>.json` and vulnerability mapping context.
- `-mind -overall "query"`: answer using global `brain_state.json` only.

## Suggestion engine
`-suggest` has dual output:
- Natural-language operator recommendation.
- Structured JSON candidate persisted into `brain_state_<session>.json`.

Suggested schema example:
```json
{
  "next_v_code": "V-029",
  "reason": "Possible injection path remains untested",
  "confidence": "high",
  "requires_revalidation": false,
  "based_on": ["input_surface_present", "authz_gap_detected"]
}
```

## State machine
The state machine in `trinetra.java` remains deterministic and file-driven. Suggested states:
- `initialized`
- `session_created`
- `finding_recorded`
- `brain_pending`
- `brain_updated`
- `suggestion_ready`
- `report_ready`
- `compressed`

The state machine uses JSON/state artifacts as authority, not LLM prose.

## Failure handling
- If shell execution fails, the failure is recorded in session JSON.
- If OpenRouter summarization fails, the finding is stored as captured but unsummarized.
- Fallback API key retry is only attempted for 401/402 conditions.
- If Gemini CLI brain update fails, the finding remains committed and state is marked stale.
