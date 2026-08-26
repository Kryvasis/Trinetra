# Trinetra Data Flow

## Compliance run flow
1. User runs `trinetra -stat run <V-XXX> <session> <target>`.
2. `trinetra_stat.java` resolves the test definition from 2_static_map.json / 3_decision_engine.csv.
3. Stat script executes (tool invoked directly; no orchestration server).
4. Raw result is captured and saved to the session directory.
5. Decision engine applies pass/fail criteria to produce a verdict.
6. Finding object is appended to session JSON.
7. `brain_<session>.md` is updated.
8. `brain_state_<session>.json` is recalculated (with hash-chained normalized_results).
9. Global `brain_state.json` is refreshed.

## Brain update flow
1. Read latest session JSON delta.
2. Read current session brain markdown.
3. Decide incremental patch vs full compression.
4. If compression required, overwrite one backup file.
5. Write refreshed markdown.
6. Write refreshed session brain state JSON.

## `-mind -read`
1. Read `brain_<session>.md`.
2. Read `brain_state_<session>.json`.
3. Build Gemini CLI prompt.
4. Return grounded response.

## `-mind -suggest`
1. Read `brain_state_<session>.json`.
2. Read vulnerability mapping reference/context.
3. Build Gemini CLI prompt with already-run V-codes and current risk state.
4. Receive natural-language suggestion plus structured candidate.
5. Persist candidate to session brain state JSON.
6. Return operator-readable recommendation.

## `-mind -overall`
1. Read global `brain_state.json` only.
2. Build Gemini CLI prompt.
3. Return overall portfolio-level summary.

## `-agr`
1. Read session JSON only.
2. Apply cert strategy.
3. Generate scorecard artifact in session directory.
