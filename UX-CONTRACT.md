# Cortex workflow contract

Visual identity and runtime token ownership: [DESIGN.md](DESIGN.md).
Business scope for the new mode: [WEBSITE-ANALYSIS.md](WEBSITE-ANALYSIS.md), approved
website/device separation (2026-09-04). Security and score semantics: [SECURITY-REVIEW.md](SECURITY-REVIEW.md).

## Canonical UI map

| Capability | Owner | Variants / verification |
| --- | --- | --- |
| Navigation and titles | `frontend/src/App.jsx`, `UploadView.jsx` | Open workspace leads to `/dashboard` overview; `/upload` owns inputs; `/system` retains diagnostics; `/website` and `/?source=website` redirect to `/upload?source=website` |
| Page headings | `SceneHeader.jsx` | Compact title and description, without a workspace kicker |
| Forms and controls | Workspace-scoped `workspace.css` over existing base styles | Native fields; Website retains noValidate, inline error association and first-invalid focus; optional hardware fields use native details/summary |
| Feedback | `Toast.jsx` and persistent page status | Shared toast for completion; actionable failures persist inline |
| Scrollbar and tokens | `workspace.css` within `.workspace-shell`; `scene.css` for intro/base | Natural document scroll; tables have horizontal overflow, no shared fixed-height form container |
| Overview | `OverviewView.jsx`, `assessmentSummary.js` | Read-only named-session device fetch; 30s timeout, stale-response protection, retry, empty/loading/loaded/error states; first-five device preview |
| Website response state | `WebsiteView.jsx` | Idle, pending, success, error, PDF pending; abort on unmount, block duplicates, explicit retry |

No new select, date picker, modal, table selection or CRUD contract is introduced.
Existing Training select remains platform-owned; unchanged legacy forms are not
claimed to meet all of this new workflow's validation behavior.

## Website behavior

English copy; recorded times are UTC. Ten fixed findings render in full; no pagination
is necessary. A URL field and an explicit scope acknowledgement precede submission.
No URL is assessed automatically. Report outcomes are pass/fail/manual review/not
tested, and are never communicated through color alone. Missing evidence is not a
failure and a passing observation is not site-wide assurance.

No local-storage drafts or background scans. Navigation discards this transient
form/report; the on-page notice tells users to download before leaving. Website
observations have no save/delete/overwrite action. Failed network/export requests
preserve the URL and existing report where applicable. No automatic retries.
PDF expiry/restart errors ask the user to rerun the assessment. Backend is a local
tool, not a multi-user authorization service; do not expose it publicly as-is.

## Design reconciliation

The approved 2026-09-04 workspace redesign replaces square ruled regions with
rounded graphite surfaces, compact sans-serif typography and white current-route
pills. `workspace.css` owns this scoped presentation; the introduction and its canvas
remain unchanged. Route arrival is 220ms, control state changes 160ms; reduced motion
removes workspace motion. Native Training select popup remains platform-owned.

The overview reads `/api/session/<name>/devices` without starting scans or generating
reports. Counts aggregate recorded per-device outcomes; unresolved equals total less
pass/fail and is never shown as confirmed failure. No session directory, historical
trend, account identity or system-wide telemetry is invented. A valid empty session
shows zero; an unloaded or unavailable session shows no measured values.

Open workspace routes to the overview after the existing 760ms transition (immediate
with reduced motion). Secondary routes remain independent pages. Main-content focus
and document title update on route navigation. Unknown routes show an app-owned
not-found page with a return link. Titles follow `{Page} — Cortex`; no authentication
or permission system was introduced by this redesign.

| Operation | Pending | Outcome / feedback | Failure / focus |
| --- | --- | --- | --- |
| Open overview session | Busy button, fixed metric regions | Same page, named-session URL, actual counts | Persistent error with retry; input retained |
| Follow device link | Device loader | Automatically loads query session | Timeout/error with retry; stale work canceled |
| Change workspace page | Short route arrival | Destination heading and document title | Main content receives focus; navigation remains available |
| Expand hardware details | Immediate native disclosure | Existing optional fields, values preserved | Validation errors expand disclosure |

Existing mutation behavior and legacy validation boundaries are retained; this visual
redesign does not claim full end-to-end security or backend-state coverage. Device
Results still requires explicit Load Results to generate its report. No export or
network collection runs on opening the overview.

Source selectors precede device metadata. Website mode never asks for a device/session,
vendor or collection credentials. Switching source clears credentials and transient results;
selectors are disabled during requests. The explicit download-before-switch notice remains.
Device Results labels the percentage as a mapped-check pass rate and displays unresolved
outcomes separately. Earlier report files are historical and are not silently rewritten.
