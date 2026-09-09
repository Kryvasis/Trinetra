# Cortex workflow contract

## Runtime activity console — 2026-09-09

- `ActivityConsole.jsx` is the canonical shared owner for visible collection and ingestion activity. Its fixed Runtime launcher remains outside route content, defaults closed on every workspace route, reports the current textual state and confirmed event count, and follows the selected session across route changes. Starting an assessment updates the launcher but never forces the drawer open.
- The console polls the local bridge only while a session is selected and the live view is not paused. Requests are abortable, stale work is discarded on session change, hidden tabs do not poll, and completed traces refresh less frequently than running traces.
- User activation opens a right-side non-modal drawer. The workspace remains operable, so the drawer does not trap focus or claim modal semantics. Close and Escape dismiss it and restore focus to the launcher. Pause affects only display refresh; it never pauses, cancels or changes an assessment. Copy exports the sanitized displayed trace and reports clipboard failure through the shared toast owner.
- Backend activity files contain a bounded latest-operation trace. They record allowlisted stages, timestamps, sanitized command forms and summary counts. They never contain raw configuration lines, credential values, tokens, temporary paths or subprocess stdout/stderr. Activity metadata is not presented as hash-chain evidence.
- Upload, paste and authorized SSH/URL collection create one operation ID per submitted assessment. Bulk files share that ID, so sequential device ingestion remains one readable trace. The client explicitly finalizes success, partial, cancelled or error state; failure of activity recording never blocks the underlying assessment.
- Empty, standing-by, live, paused, success, partial, cancelled, error and unavailable states have stable geometry and text labels. Newly received lines use one bounded 160ms arrival; reduced motion removes it. The terminal shows only timestamped prompt, command and output entries—no duplicate metadata chrome, fake commands, simulated timing or perpetual cursor animation.

## Production interface pass — 2026-09-09

- Results presents framework totals as a stable semantic summary and keeps the paginated evidence table keyboard-scrollable with explicit captions, column scopes, recorded-control fallbacks and a clearer device/check hierarchy.
- Training uses one bounded review queue with a persistent instructional empty state in the editor. Selection is communicated through pressed state, contrast and a structural inset—not independent card borders. Saved labels remain advisory until the configuration is re-uploaded.
- Devices and System share canonical section headings, status panels, inline confirmations, compact action groups and retained-item lists. Remove actions use the danger intent and remain recoverable. Raw diagnostic statuses are translated into operator-facing health language while exact validation issues remain visible.
- Fixed Runtime controls never cover final-page content; the workspace reserves a bottom safe area on every route. Tables retain their own horizontal scrolling and accessible region labels.

Implementation owners: `frontend/src/components/ActivityConsole.jsx`, `frontend/src/utils/activityStream.js`, `frontend/src/App.jsx`, `frontend/src/pages/UploadView.jsx`, `bridge/app.py`, `frontend/src/workspace.css`.

## Workspace resilience review — 2026-09-05

- Results keeps the last successful assessment visible while refreshing the same session; failures label it as previously loaded. Switching sessions clears the old result. PDF work captures the displayed session name and is canceled when the selected session changes.
- Overview, Results, Devices and Training validate session names using the shared identifier contract, associate errors with inputs and focus invalid fields.
- Devices adds local search and ten-row pagination. Search resets paging; shortened datasets clamp it. Search and paging are deliberately transient within this local inventory, matching System. The existing semantic table retains horizontal scrolling with a keyboard-focusable region and a visible cue.
- Device cancellation and Escape restore trigger focus. Successful removal/restoration focuses a surviving content target. Missing OS metadata reads Not recorded, and recorded-check pass rates do not imply certification.
- Training fields have explicit label associations and invalid-state descriptions. The summary starts with equal loaded/remaining counts, preserves zero, and describes local review progress. Reupload remains necessary to verify recognition; labeling alone does not establish security compliance. Its select remains native/platform-owned.
- App.jsx owns bounded, deduplicated notifications with unique IDs and timer cleanup. WorkspaceErrorBoundary.jsx keeps navigation usable after a route render failure and provides an explicit retry. Unknown routes use a Page not found title.
- Existing graphite tokens, natural page scrolling and reduced-motion rules remain canonical. No backend, retention or authorization policy changes are introduced by this review.

## Evidence and workflow hardening — 2026-09-04

- Results reads scores only on load. Report generation is an explicit PDF action; it may invoke configured narrative services. Merely opening Results must not generate a report or contact an LLM.
- Framework choices are draft until Load results. Displayed data and PDF share the applied scope. Changing a draft shows a persistent notice. Failures preserve existing data; duplicate loads/exports are disabled.
- Results exposes recorded checks in 20-row pages, device IDs, mapped controls and evidence explanations. No mapped evidence displays a dash rather than an invented percentage. Counts represent retained history, not a latest-snapshot certification.
- Configuration observations are separate from runtime verdicts. Source lines and parser limitations are visible. Legacy configuration records carry a warning; existing evidence is never silently rewritten. Broken evidence chains show an integrity warning.
- System loads diagnostics on entry, including after removing the selected session. Its saved-session inventory supports case-insensitive search, Clear, 10-row pagination and reversible removal. AI connectivity is not inferred from configuration-file presence.
- Training auto-loads the selected session, guards stale responses and duplicate submissions, and offers guidance when no session is selected. Pattern recognition is not security compliance.
- Search, pagination and draft framework choices are intentionally local transient UI state. Assessment selection retains the existing per-tab, 30-minute inactivity contract. These refinements introduce no new component library or global storage layer.
- Narrow-screen controls wrap, inputs use 16px text and actions have 44px minimum height. Existing graphite tokens and introduction are retained.

Implementation owners: `ResultsView.jsx`, `DashboardView.jsx`, `TrainingView.jsx`, `workspace.css`; server evidence semantics: `TrinetraConfigObservations.java`, `TrinetraConfigIngestor.java`, `TrinetraComplianceScorer.java`, `TrinetraSession.java`.

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
| Active assessment selection | `ActiveSession.jsx`, `activeSession.js` | Per-tab sessionStorage, validated session name and last-activity timestamp only; query links override the current selection; 30-minute inactivity expiry; refresh/navigation restore; New assessment clears selection without deleting data |
| Runtime activity | `ActivityConsole.jsx`, `activityStream.js`, `bridge/app.py` | Closed-by-default fixed launcher with textual state/count; user-opened right-side non-modal drawer; abortable polling; explicit pause/copy/Close and Escape with launcher focus restoration; no focus trap, secrets or raw evidence; activity failure does not block assessment |

No new select, date picker, modal or table selection contract is introduced.
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
Results automatically loads the selected session on entry; Load Results retries or applies framework choices. No PDF export or
network collection runs on opening the overview.

## Active assessment selection (2026-09-04)

User-requested cross-page continuity: successful file, paste, bulk (including partial
success), and authorized network ingestion selects the assessment. Overview selection
and successful manual loaders also update the shared selection. Session names remain
editable for switching. Website observations remain transient and independent.

Only the validated name and last-activity timestamp are stored in sessionStorage,
scoped to this browser tab. No credentials, configs, reports or tokens are persisted
client-side. Storage failures degrade to in-memory navigation. Pointer, keyboard,
wheel and touch activity renew the 30-minute selection timeout; background requests
do not. Focus/visibility return checks expiry before renewing activity.

Expiry clears displayed assessment state and returns to Overview with an explanation.
New assessment clears selection and opens Upload. Neither action deletes server data
or constitutes logout/authentication; this remains a local single-user tool. An old
expired URL is not silently restored on refresh; explicitly opening a session again
starts a new selection period. New tabs have independent selection lifetimes.

Source selectors precede device metadata. Website mode never asks for a device/session,
vendor or collection credentials. Switching source clears credentials and transient results;
selectors are disabled during requests. The explicit download-before-switch notice remains.
Device Results labels the percentage as a mapped-check pass rate and displays unresolved
outcomes separately. Earlier report files are historical and are not silently rewritten.

## Device assessment scope (2026-09-04)

`SessionDevicesView.jsx` owns Remove and Restore. Removal excludes the named device
from the active device list, new scores/reports and Training unknown lines. It does
not delete historical evidence or alter its hash chain. Earlier exports are unchanged.
Removed devices remain available in a separate Restore section; successful explicit
re-upload also restores their evidence to active scope.

The app-owned inline confirmation names the device and session and explains these
consequences. It is deliberately non-modal, initially focuses Cancel and does not
trap focus. Mutations disable duplicate actions, use a 30-second timeout and ignore
stale responses after navigation. Errors persist inline; after an uncertain timeout,
reload the device list before retrying. Shared toasts acknowledge completion.

The DELETE device and POST restore endpoints delegate to `TrinetraSession` through
`TrinetraBridgeHelper`. Changes use the existing per-session lock and atomic state
write. `removed_devices` and timestamped `device_scope_history` record scope changes;
these scope metadata records are not themselves protected by the evidence hash chain.

System Status lists real session files separately from validation errors. Missing
session score/report API requests return 404 without creating session directories.
The backend remains a local single-user tool, not an authorization boundary.

## Saved-session list removal (2026-09-04)

User-requested removal from System is a recoverable list operation, not erasure.
`DashboardView.jsx` uses the existing non-modal inline confirmation pattern with
Cancel initially focused, persistent failure text, duplicate prevention, a 30-second
timeout and stale-response cancellation. Cancel restores trigger focus; completion
focuses the list heading. Removed sessions appear in a collapsed Restore section.
`ActiveSession.jsx` clears the matching selected session on confirmed removal.

POST `/api/session/<name>/archive` creates an exclusive empty `.cortex-archived`
marker; DELETE on the same endpoint removes only that marker. Both are idempotent.
Session directories and all original evidence/report files remain untouched. The
marker is not a security boundary or a hash-chain record. Saved links and manual
session lookup still work, and diagnostics still validate retained sessions.
The doctor response partitions real session files into `sessions` and
`archived_sessions`; the UI never turns validation errors into session inventory.

## Assurance and governed rules (2026-09-09)

- `/assurance` publishes repository-derived control, probe and vendor-depth counts. Missing expert-labelled accuracy remains visibly unavailable rather than rendered as zero or estimated.
- Integrity receipt generation requires a valid saved session. Receipts commit to recorded chain hashes with a Merkle root and local Ed25519 signature; the interface explicitly distinguishes this from an independently anchored ledger transaction.
- Receipt verification accepts JSON, reports malformed, signature-failed and current-evidence-mismatch states separately, and never treats an embedded public key as external identity proof.
- New UI-created training rules enter `draft`. Draft and deprecated rules are ignored by the Java parser. A different named reviewer must approve a draft before it becomes active; author, reviewer, timestamps, version, reference, confidence and state history remain in the rule record.
- `make start` builds the React application and serves the SPA through the loopback Flask service at port 5000. Vite remains a development-only workflow.
