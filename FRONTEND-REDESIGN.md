# Cortex workspace redesign

## Changes

- Preserved the cinematic introduction and vertical transition. Open workspace now leads to `/dashboard`.
- Added a read-only session overview with actual device/check counts, an outcome ring, review guidance, linked assessment workflow, and a five-device preview.
- Moved collection to `/upload` and existing diagnostics to `/system`. Legacy website links redirect to the website source within collection. Unknown routes have an app-owned recovery page.
- Applied shared graphite surfaces, white active navigation, compact typography, rounded controls, consistent forms/tables and 220ms route transitions. Reduced-motion rules disable workspace motion; no animation dependency, raster asset or remote font was added.
- Collapsed optional hardware metadata into an accessible native disclosure, improved field names and selection semantics, and fixed automatic device loading from session links with cancellation and timeout protection.
- Recorded the new workspace system separately from the preserved intro in DESIGN.md and UX-CONTRACT.md.

## Verification

- `npm run lint`: passed, zero warnings.
- `npm run build`: passed; application JS approximately 258 kB / 80 kB gzip.
- `node tests/assessment-summary.mjs`: six assertions passed (empty, mixed outcomes, inconsistent totals, invalid values, unresolved-only and pass-only).
- Repeated lint, six assertions and Vite build in the actual WSL repository using its existing `/home/mystic/.local/node/bin/node`; all passed. The login shell initially selected Windows npm, so no dependency reinstall was attempted. Main and staging production asset hashes match.
- Frontend premium strict static audit: zero findings.
- DESIGN.md schema lint: zero errors, 35 advisory warnings (missing conventional primary alias and documented colors not referenced by the compact component-preview token map). Runtime color ownership remains explicit; no fake component references were added to suppress these warnings.
- Browser: all six workspace routes at 1440px and 390px; no document-width overflow observed. Vendor radio and benchmark checkbox selections work. Website collection remains separate and retains its authorization acknowledgement.
- Browser: original intro button reaches overview; route focus moves to main content; missing-session error is persistent and recoverable; keyboard Enter loads a valid session; device workflow links automatically load the selected session.
- Actual read-only session `cisco_reg`: one device, one unresolved check, zero passed/failed. Unresolved is not recategorized as failure. Empty session `demo` shows zeros.
- Fresh final verification tab: no console errors or warnings. An earlier development-only Vite HMR reload warning occurred while creating an imported module; the completed build and fresh tab passed.
- Original `scene.css` and `ThreatField.jsx` match the main repository byte-for-byte.

## Scope and limitations

No backend logic, authorization boundary, report semantics, dependencies, or intro canvas code changed. No real network scans, training writes, exports or report generation were triggered during this UI verification. Loaded result/training/system state coverage, assistive-technology testing, OS reduced-motion testing and cross-browser certification remain outside these checks. The local backend is not made safe for public deployment by a visual redesign.

Visual review covered all twelve supplied desktop/mobile route captures and sampled source; its only material fix was stale design documentation. Final verdict: `ship` for that sole documentation fix, scored resolved with no remaining documentation regression. This is not blanket production-readiness approval.
