---
name: "Cortex"
description: "A graphite assessment workspace with a preserved cinematic network-observatory introduction."
colors:
  bg: "#090a0a"
  surface: "#121414"
  surface2: "#191b1b"
  surface3: "#292d2c"
  border: "#2c302f"
  border-strong: "#4c5250"
  text: "#f0f2ef"
  text-dim: "#b2b8b4"
  text-faint: "#a2aaa5"
  accent: "#e6ece7"
  accent-hover: "#ffffff"
  accent-ink: "#111412"
  green: "#a8c9b4"
  red: "#e4a59c"
  yellow: "#d9c596"
  field: "#0e1010"
  table: "#101212"
  focus: "#e0e8e2"
  selection: "#cbd6ce"
  scrollbar: "#69726c"
  brand-ring: "#bfc9c2"
  choice-selected: "#212724"
  choice-border: "#9daaa1"
  choice-control: "#929e96"
  benchmark-selected: "#1d2320"
  benchmark-border: "#69786d"
  metric-icon: "#87948b"
  review-icon: "#becbc1"
  outcome-pass: "#e7ede8"
  outcome-fail: "#a89d98"
  outcome-other: "#616d66"
  intro-ink: "#090a0a"
  intro-ink-deep: "#090a0a"
  intro-surface: "#121414"
  intro-surface-raised: "#191b1b"
  intro-text: "#f0f2ef"
  intro-muted: "#b2b8b4"
  intro-faint: "#a2aaa5"
  intro-mesh: "#929e96"
  intro-signal: "#bfc9c2"
  intro-exception: "#a89d98"
typography:
  display:
    fontFamily: "Bahnschrift Condensed, Arial Narrow, Segoe UI, sans-serif"
    fontWeight: 650
    lineHeight: 0.84
  headline:
    fontFamily: "Segoe UI Variable Text, Segoe UI, system-ui, sans-serif"
    fontSize: "25px"
    fontWeight: 600
    lineHeight: 1.25
    letterSpacing: "-.025em"
  body:
    fontFamily: "Segoe UI Variable Text, Segoe UI, system-ui, sans-serif"
    fontSize: "14px"
  label:
    fontFamily: "Segoe UI Variable Text, Segoe UI, system-ui, sans-serif"
    fontSize: "12px"
    fontWeight: 500
    lineHeight: 1.3
  mono:
    fontFamily: "Cascadia Code, SFMono-Regular, Consolas, monospace"
rounded:
  flat: "0px"
  intro-control: "1px"
  legend: "2px"
  choice: "4px"
  badge: "5px"
  file-button: "6px"
  segment: "8px"
  field: "9px"
  control: "10px"
  inset: "12px"
  stat: "16px"
  card: "20px"
  overview: "22px"
  nav-item: "24px"
  nav-rail: "30px"
spacing:
  tight: "4px"
  small: "8px"
  control-gap: "12px"
  grid-gap: "16px"
  panel-gap: "20px"
  panel: "24px"
  overview-panel: "26px"
  section: "28px"
  workspace-bottom: "48px"
components:
  button-primary:
    backgroundColor: "{colors.text}"
    textColor: "{colors.accent-ink}"
    rounded: "{rounded.control}"
    padding: "10px 16px"
  button-primary-hover:
    backgroundColor: "{colors.accent-hover}"
    textColor: "{colors.accent-ink}"
  button-secondary:
    backgroundColor: "{colors.surface2}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "10px 16px"
  navigation-active:
    backgroundColor: "{colors.text}"
    textColor: "{colors.accent-ink}"
    rounded: "{rounded.nav-item}"
    padding: "0 18px"
  card:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.card}"
    padding: "24px"
  overview-panel:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.overview}"
    padding: "26px"
  input:
    backgroundColor: "{colors.field}"
    rounded: "{rounded.field}"
  badge:
    backgroundColor: "{colors.surface2}"
    rounded: "{rounded.badge}"
    padding: "4px 8px"
---

# Design System: Cortex

## Overview

**Creative North Star: "The Graphite Assessment Workspace"**

Cortex pairs a preserved cinematic network observatory with a compact, calm operational workspace. The user's NEXORA reference governs the workspace: near-black graphite, rounded tonal panels, white current navigation and restrained functional motion. Evidence and readable task state take priority over decorative telemetry.

The introduction preserves its quiet masthead, large left-aligned statement, geographic mesh and circular entry action. Its supplied Pioneer science composition and global signal model are preserved without importing proprietary imagery or agricultural content. The user-approved color adjustment matches the dashboard's graphite palette while preserving layout and animation. `frontend/src/scene.css` scopes the intro colors and gradient; `frontend/src/components/ThreatField.jsx` reads its inherited canvas color tokens once per mount. `frontend/src/workspace.css` owns the separate workspace skin. Do not restore discarded square-panel/underline-navigation rules to the workspace.

**Key Characteristics:**

- Rounded graphite containers and white selection in the workspace.
- Compact local typography, honest metrics and visible recovery paths.
- Preserved cinematic introduction with one global signal model.
- Functional route and control motion, disabled by reduced-motion preference.

## Colors

The workspace is a near-black neutral system with a slight green cast. Frontmatter values are normative; `intro-*` roles belong only to the preserved opening.

### Primary

White text doubles as primary-action and active-navigation fill, paired with accent-ink. Accent and accent-hover support control feedback. Focus is a high-contrast pale outline, not a glow.

### Neutral

Background, surface, surface2 and surface3 establish increasing tonal separation. Border and border-strong distinguish fields and dividers. Text-dim and text-faint carry supporting information. Field and table backgrounds sit between the canvas and panels. Selection, scrollbar, brand-ring and icon colors retain the literal source values in the frontmatter.

### Semantic colors

Green, red and yellow carry success, failure and caution with text. Outcome pass/fail/other are a separate subdued chart palette paired with legends and counts. Choice and benchmark selected fills and borders indicate actual selection, not decoration.

**The Evidence Rule.** Never manufacture alerts, people, histories, telemetry or a compliance certification to populate this visual system.

The introduction uses a static radial gradient centered behind the globe: surface-raised at 0%, surface at 36%, and ink-deep at 74%. Its neutral white text, muted sage/silver mesh and warm-gray exception paths match the dashboard palette. The entry button and vertical wipe share those neutrals. Scope these colors to `.intro-experience`; animation timing, geometry, copy and dashboard colors remain unchanged.

## Typography

Segoe UI Variable Text with Segoe UI/system fallbacks is the workspace display and body family; no remote font is added. Page headlines use the frontmatter headline role, reducing to 23px on narrow screens. Descriptions use 13px/1.65 with a 76ch maximum. Panel headings use 14px/1.4 at weight 500; major form headings use 17px/1.4 at 600. Navigation and buttons are compact sentence-case text. Tabular numerals stabilize measurements; overview metrics use 40px weight 400, reducing to 34px at the smallest breakpoint. Technical evidence and identifiers retain Cascadia Code/SFMono-Regular/Consolas.

Bahnschrift Condensed with Arial Narrow/Segoe UI fallback remains the cinematic statement family. Its source display size is `clamp(58px, 6.3vw, 104px)`; this responsive expression stays outside the frontmatter dimension schema. Preserve the introduction's local display role, compact mono labels, uppercase scene hierarchy and orchestrated appearance.

## Layout

The root opens a standalone full-viewport introduction with copy left and global model right. Open workspace changes state through the preserved wipe and enters `/dashboard` (Overview), not content below the intro. `/upload` is Upload & collect; `/system` contains system diagnostics. Results, Devices and Training remain separate routes. Direct workspace links bypass the introduction; `/website` redirects to `/upload?source=website`.

The workspace masthead is in normal flow, not fixed. Masthead and content share a centered maximum of 1440px with 40px side gutters. Navigation wraps. Overview uses an asymmetric .9fr/1fr/1.2fr metric layout, followed by linked workflow stages and a device preview. Common panels use 24px padding; overview panels use 26px. Nested panels flatten into separators rather than stacked card shells. Natural document scrolling remains canonical; tables own horizontal scrolling.

At 1100px the masthead stacks, workflow links become two columns, overview padding becomes 22px, and session context hides. At 760px gutters become 16px, navigation wraps with 42px targets, forms become one column, metrics use two columns with the compact pair spanning the row, and the session loader wraps. At 480px overview and workflow become one column; the compact metric pair remains paired, and benchmark choices stack. At 1600px the masthead minimum height grows from 112px to 128px. The introduction keeps its incumbent narrow-screen globe/copy/action arrangement in one locked viewport.

## Elevation & Depth

Workspace depth is tonal rather than shadow-driven: graphite containers against a near-black canvas, with brighter inset controls and quiet borders. No decorative glass, blur, neon or gradients. The inherited transient toast shadow is `0 20px 60px rgba(0, 0, 0, 0.34)`; this is not a card-elevation scale. Intro depth continues to come from the globe's geometric projection and variable line opacity.

## Shapes

Workspace controls are softly rounded, not square: control radius 10px, fields and choices 9px, main cards 20px and overview panels 22px. Navigation uses a 30px outer rail and 24px active pill (outer rail 16px on narrow screens). Stat cards use 16px, inset tables/workflow tiles 12px, mode buttons 8px, badges 5px, file buttons 6px, choice controls/progress 4px and legend swatches 2px. Nested cards intentionally flatten to zero radius. Circular radios, outcome rings and the brand glyph retain meaningful circular geometry.

The introduction retains the original circular model and entry action and its incumbent square control language. Circular source shapes use `border-radius: 50%`; this percentage stays outside the frontmatter dimension schema. Its old circle exclusivity does not prohibit rounded workspace surfaces.

## Components

### Navigation

Six plain-language route links sit inside the graphite rail. Current navigation is a white filled pill with dark text; the legacy underline is explicitly removed. Hover uses surface3. Desktop links are at least 38px high; narrow links at least 42px. Focus is a 2px focus-color outline offset 4px. The Cortex brand links to Overview.

### Buttons and fields

Primary actions use text-white fill with dark ink and secondary actions use surface2. Both have at least 42px height and 10px 16px padding. Hover raises tonal contrast, without a decorative glow. Disabled buttons use .48 opacity and a not-allowed cursor. Inputs have persistent labels, strong borders, field fill, 13px text and stable validation dimensions. Focus retains the inherited accent border and subtle field tint while the workspace outline supplies a clear keyboard cue.

Collection choices and framework controls expose actual selected state through white segment fills or subdued selected borders/fills. Selected buttons retain `aria-pressed`; source controls lock during collection. File upload remains recommended and live collection explicit. Credentials remain masked with user-controlled reveal, request-scoped and cleared after successful collection or leaving the mode. Preserve existing known-host, PEM-key and public-destination trust-boundary explanations. Public website observations remain in their own form/results within Upload & collect, without device metadata or compliance scoring.

### Panels, tables and status

Main task regions use rounded graphite panels; nested sections use rules and whitespace. Statistics are tonal cards outside panels and divided flat groups inside them. Tables retain semantic markup, 16px cells and horizontal overflow containment. Badges are compact rounded text labels, not the former underlined-only status words. Empty states provide a next action; error feedback retains text and red border treatment. The outcome ring renders actual counts with textual legends rather than implied certification.

### Motion

Workspace routes arrive over 220ms with `cubic-bezier(.16, 1, .3, 1)`, fading from .7 opacity and rising 5px. Button/navigation color/background/border and workflow-hover transitions take 160ms. Inputs retain the inherited 200ms border/background transition. Progress values update without animating layout width; zero is rendered as zero, without a decorative minimum fill. No perpetual workspace animation is introduced. Reduced motion removes workspace animations and transitions and resets scroll behavior to auto. Forced-color mode adds system-color panel borders and a highlighted current-navigation border.

The Canvas globe remains capped near 24 FPS and device pixel ratio 1.25, pauses in hidden tabs and keeps pointer movement outside React state. Intro elements arrive in one orchestrated sequence; the circular action rotates slowly. The preserved 760ms top-to-bottom solid-color wipe is owned by `.intro-wipe`/`workspace-wipe` in `frontend/src/scene.css`. Reduced motion freezes ambient intro animation and opens the workspace immediately while preserving state feedback.

## Do's and Don'ts

### Do:

- Do keep the workspace skin scoped and preserve the opening animation and globe.
- Do use rounded graphite panels and white active navigation for workspace routes.
- Do pair semantic color and chart marks with readable labels and actual evidence.
- Do preserve workflow behavior, keyboard focus, reduced motion and narrow-screen scrolling.

### Don't:

- Don't restore square workspace cards or underline-only active navigation from the old design.
- Don't introduce fake telemetry, decorative neon, purple gradients, glass or glow.
- Don't treat a pass rate or local assessment as production security certification.
- Don't animate tables, errors or controls in ways that displace the user's workflow.
