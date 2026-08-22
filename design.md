# Trinetra Design

## Design principles
- CLI-first and deterministic.
- Session-centric, not target-centric only.
- Evidence first, AI second.
- Human-readable plus machine-readable memory.
- Graceful degradation when AI providers fail.
- Minimal runtime dependencies beyond Java, bash, curl, jq, and Gemini CLI.

## Conceptual model
Trinetra is a layered audit memory system:
- Shell scripts perform test-specific work.
- Session JSON stores immutable-ish factual history.
- Brain markdown stores evolving analyst intelligence.
- Brain state JSON stores compact execution and recommendation state.
- Aggregation transforms raw findings into scorecards.

## UX model
The operator experience should feel like a disciplined CLI workbench:
- run tests,
- grow a session,
- ask the audit what it knows,
- ask what to do next,
- generate a scorecard.

## File philosophy
Every meaningful action should leave a durable artifact. Nothing critical should live only in volatile memory or terminal output.

## AI philosophy
AI is used for summarization, compression, explanation, and bounded recommendation. It is not the source of truth. Session JSON and state JSON remain authoritative.

## Beta visual simplicity
No UI dependency is required for beta. Directory structure and artifact naming should be self-describing and grep-friendly for Kali/Linux workflows.
