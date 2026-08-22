# Trinetra Rules

## General rules
- Session JSON is authoritative for findings.
- Brain state JSON is authoritative for control flow and suggestions.
- Brain markdown is authoritative for human-readable evolving memory.
- AI output must never replace stored evidence.

## Execution rules
- Only hardcoded V-codes are executable in beta.
- Missing shell script means immediate deterministic failure.
- Every run must append a record, even on partial or failed summarization.
- OpenRouter fallback key retry happens only on 401 or 402.
- Global pacing is handled centrally, not inside individual scripts.

## Brain rules
- Brain markdown is patched section by section by default.
- Compression is triggered by byte size and estimated token count.
- Compression overwrites a single rotating backup file.
- `-overall` reads only global `brain_state.json`.

## Suggestion rules
- Suggestions must exclude already-run V-codes unless revalidation is required.
- Suggestions must be grounded in session state plus allowed V-code space.
- `-suggest` must output human-readable text and structured JSON.
- Structured suggestion output is appended to session brain state.

## Reliability rules
- Evidence capture must succeed independently of AI services.
- AI failures should mark artifacts stale, not corrupt the session.
- All timestamps should use ISO-8601.
- All file writes should be atomic where practical.
