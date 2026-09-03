# Cortex workflow contract

Visual identity and runtime token ownership: [DESIGN.md](DESIGN.md).
Business scope for the new mode: [WEBSITE-ANALYSIS.md](WEBSITE-ANALYSIS.md), approved
website/device separation (2026-09-04). Security and score semantics: [SECURITY-REVIEW.md](SECURITY-REVIEW.md).

## Canonical UI map

| Capability | Owner | Variants / verification |
| --- | --- | --- |
| Navigation and titles | `frontend/src/App.jsx`, `UploadView.jsx` | Upload & collect owns all inputs; `/website` redirects to `/?source=website`; observation results stay independent of device Results |
| Page headings | `SceneHeader.jsx` | Existing kicker/title/description layout |
| Forms and controls | Global `scene.css` form-group/input/btn styles | Native labeled fields; Website uses noValidate, inline error association and first-invalid focus |
| Feedback | `Toast.jsx` and persistent page status | Shared toast for completion; actionable failures persist inline |
| Scrollbar and tokens | `scene.css` | Natural document scroll; no Website shell-height override |
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

The collection panel uses existing colors, typography, buttons, heading primitive and
flat ruled content regions. Only the evidence label/value layout and bounded
four-outcome summary are new. No global palette or animation changes were made.

Source selectors precede device metadata. Website mode never asks for a device/session,
vendor or collection credentials. Switching source clears credentials and transient results;
selectors are disabled during requests. The explicit download-before-switch notice remains.
Device Results labels the percentage as a mapped-check pass rate and displays unresolved
outcomes separately. Earlier report files are historical and are not silently rewritten.
