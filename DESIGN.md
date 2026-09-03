---
version: alpha
name: "Cortex"
description: "A cinematic network-intelligence workspace built around one restrained global signal model."
colors:
  ink: "#090914"
  inkDeep: "#070711"
  surface: "#0F101A"
  surfaceRaised: "#141620"
  border: "#353641"
  text: "#EFEDF1"
  muted: "#AAA7B1"
  cyan: "#78A7AD"
  ember: "#BC664E"
  success: "#86A991"
  warning: "#B99A70"
  danger: "#C16B64"
typography:
  display:
    fontFamily: "Bahnschrift Condensed, Arial Narrow, Segoe UI, sans-serif"
  sans:
    fontFamily: "Segoe UI Variable Text, Segoe UI, system-ui, sans-serif"
  mono:
    fontFamily: "Cascadia Code, SFMono-Regular, Consolas, monospace"
rounded:
  sm: "0px"
  DEFAULT: "1px"
  md: "1px"
  lg: "1px"
spacing:
  control: "0.75rem"
  panel: "1.875rem"
  sectionGap: "2.5rem"
  pageMax: "82.5rem"
components:
  button:
    shape: "square"
    emphasis: "ivory fill or neutral outline"
  navigation:
    shape: "quiet horizontal text rail"
    activeState: "single underline"
  dataRegion:
    shape: "rules and whitespace, not cards"
  input:
    shape: "transparent field with one-pixel border"
  table:
    shape: "full-width ruled data surface"
  toast:
    shape: "neutral rectangular overlay"
---

# Cortex Design System

## Overview

### Creative North Star

Cortex should feel like a scientific network observatory, not a game interface or a generic cyber dashboard. Its signature is one slowly rotating global signal model adapted from the supplied video: a muted cyan geographic mesh, labeled configuration signals, and one ember-colored exception path. The composition follows the supplied Pioneer science reference—a quiet masthead, a large left-aligned statement, one dominant scientific object, and a single circular action—without copying its proprietary imagery or agricultural content.

### Product context and register

- **Audience and job:** Network security teams and SIH judges ingest configurations, inspect compliance results, train recognition rules, and verify system health.
- **Register:** Hybrid cinematic introduction and professional product workspace.
- **Usage:** Desktop-first operational tool with a complete narrow-screen layout.
- **Memorable signature:** The global configuration model in the opening viewport.
- **Restraint:** All expressive color and motion belongs to the model. Forms and data regions are flat, stable, quiet, and typographic.
- **Anti-references:** No neon palette, decorative glow, purple gradients, emoji navigation, fake coordinates, ornamental status dots, icon rail, glass panels, or card-per-block layout.
- **Runtime owner:** `frontend/src/scene.css` owns tokens and shared presentation. `ThreatField.jsx` consumes the cyan and ember visual roles through its Canvas drawing constants.

## Colors

The foundation is solid ink navy rather than a gradient. Ivory establishes reading hierarchy. Desaturated cyan identifies network structure and focus. Ember is reserved for anomalous or exceptional paths; it is never a general decoration. Semantic success, warning, and danger remain muted and always appear with text.

## Typography

Bahnschrift Condensed provides the reference-inspired cinematic statement while remaining locally available and stable. Segoe UI Variable carries product copy and controls. Cascadia Code is limited to device identifiers, framework names, hashes, compact labels, and technical metadata. Headings use uppercase only at the scene and compact section-label levels.

## Layout

The root URL opens with a standalone full-viewport introduction: copy occupies the left half, the global model occupies the right half, and one circular action enters the product. Activating “Open workspace” changes application state after a 760ms authored transition; it does not scroll to content hidden on the same page. Direct links to Results, Training, Devices, and System bypass the introduction and open the routed workspace. Inside the product, a fixed masthead uses text navigation with an underline for the current route. Forms and results use a wide content column with compact editorial headers, separated by horizontal rules and whitespace instead of containers around every block.

On narrow screens, the workspace masthead becomes two rows while the introduction stacks the globe, copy, and action into one locked viewport. Both states remain readable without horizontal overflow. Natural document scrolling is canonical inside the workspace; the introduction itself does not expose product content below the fold.

## Elevation & Depth

Depth comes from the globe's geometric projection and variable line opacity. Product content is flat. Neutral shadow is allowed only on transient toasts. There are no decorative glows, blurred panels, or glass effects.

## Shapes

Controls and data regions are square with at most a one-pixel radius. Circles are reserved for the Cortex brand glyph, the global model, and the single “Open workspace” action. That exclusivity gives circular geometry meaning.

## Components

### Navigation

Navigation uses plain text labels. The current route is communicated by text contrast and one underline, not a colored tile, icon, number, or status dot. The masthead stays visible and keyboard focus remains unobscured.

### Buttons and forms

Primary actions use an ivory fill with ink text. Secondary actions are transparent with a neutral border. Focus uses the muted cyan role without glow. Fields are transparent, persistently labeled, and maintain stable dimensions during loading and validation.

The Upload workspace treats file upload as the recommended path and live collection as an explicit secondary mode. SSH and HTTPS credentials use masked fields with user-controlled reveal actions, exist only for the active request, and are cleared after a successful collection or when the user leaves the mode. Live collection displays its trust boundary in plain language: SSH requires an existing `known_hosts` entry, private keys must be pasted as PEM data, and URL collection rejects non-public destinations unless the bridge operator intentionally enables the private-network override.

### Data regions

All evidence intake lives in Upload & collect. Input-method and network-source buttons
precede the device form. Public website observations use their own form and results
inside this flow, with no device metadata or compliance scoring. Existing `/website`
links redirect to the website source. Selected buttons expose `aria-pressed`; collection
source controls lock while requests are pending. Visual tokens and motion are unchanged.

Legacy `card` classes render as flat ruled sections for compatibility; they must not look like cards. Statistics share one ruled row with dividers. Tables own horizontal scrolling and use native semantic markup. Badges are underlined status words rather than pills.

### Motion

The Canvas globe runs at a maximum of roughly 24 FPS, caps device pixel ratio at 1.25, pauses when the tab is hidden, and stores pointer movement outside React state. Intro elements arrive in one orchestrated sequence; the circular action rotates slowly to signal interactivity. Opening the workspace uses a 760ms top-to-bottom vertical solid-color wipe with a clear beginning and end, owned by `.intro-wipe` and `workspace-wipe` in `frontend/src/scene.css`. Workspace routes use one restrained fade-and-rise entrance. Reduced-motion mode freezes ambient animation and opens the workspace immediately while preserving state feedback.

## Do's and Don'ts

- **Do:** Reserve cyan for network structure, focus, and selected state.
- **Do:** Use ember only for a genuine exception, anomaly, or risk path.
- **Do:** Let typography, spacing, and rules organize operational content.
- **Don't:** Add a card because a block needs spacing.
- **Don't:** add decorative status dots, fake telemetry, gradients, or glow.
- **Don't:** animate tables, validation errors, or form controls in ways that move the workflow.
- **Don't:** use color without a text label or structural cue.
