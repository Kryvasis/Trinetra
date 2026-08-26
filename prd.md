# Trinetra PRD

## Product overview
Trinetra is a modular pentesting masterclass framework built for Kali Linux 2026.2 that orchestrates vulnerability checks, session evidence, AI-assisted audit memory, and standards-aware reporting. The new beta replaces the earlier monolithic C++ design with a Java-centered architecture that separates orchestration, IDE support, pentest execution, and aggregation/reporting.

The product goal is not just to run checks, but to preserve audit intelligence over time. Each session produces raw evidence, structured findings, evolving analyst memory, and machine-readable state to support continued testing, audit summaries, and guided next-step suggestions.

## Product goals
- Provide a deterministic CLI-first pentesting framework for repeated offensive security workflows.
- Maintain session-scoped evidence, findings, and AI-generated audit memory.
- Support human-readable and machine-readable audit continuity.
- Enable future automation through structured next-step recommendations.
- Support standards-aligned scorecards through `trinetra -agr [cert] [session]`.

## Non-goals for beta
- Full implementation of every vulnerability code in the master list.
- Multi-cert aggregation in a single run.
- Autonomous exploitation or self-directed attack chaining.
- Live browser UI as a core beta requirement.

## Removed scope
- HexStrike (MCP server / REST tool orchestration) was removed from the
  product entirely. Trinetra is an AI-driven multi-vendor network security
  compliance auditor; offensive tool orchestration is out of scope. The
  former `hex_scripts/` engine and its server lifecycle targets no longer exist.

## Target users
- Pentesters and red team learners.
- Security researchers running repeatable CLI-driven audits.
- Developers who want structured offensive testing records.
- Power users on Kali/Linux who prefer terminal-first workflows.

## Core user stories
- As an operator, a specific V-code can be run against a target and appended to a named session.
- As an operator, the session can preserve both raw findings and evolving audit memory.
- As an operator, the current audit state can be queried in natural language with `-mind`.
- As an operator, the framework can suggest the next relevant test based on already-run checks and session state.
- As an operator, a standards-aware scorecard can be generated from existing session findings.

## Beta scope
The beta must deliver a complete vertical slice:
- Session creation and update.
- Shell-script dispatch for selected V-codes.
- Session JSON append flow.
- Brain markdown incremental update flow via Gemini CLI.
- Session state JSON update flow.
- `-mind -read`, `-mind -update`, `-mind -suggest`, and `-mind -overall`.
- One initial cert mode in `-agr`.

## Success criteria
- A session can be created and updated across multiple vulnerability runs.
- Findings remain durable even if AI summarization fails.
- Brain markdown can be updated incrementally and compressed when thresholds are exceeded.
- `-suggest` can return both operator-readable guidance and a machine-readable next-step candidate.
- Session state prevents duplicate V-code suggestions unless revalidation is justified.

## Constraints
- Base OS is Kali Linux 2026.2.[cite:4]
- Compliance tests execute as standalone shell scripts (stat_scripts/); no external orchestration server.
- OpenRouter free tier is used for tool-output summarization, which is rate-limited.[cite:78]
- Gemini CLI is used for brain update and query behavior.

