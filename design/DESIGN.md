---
version: alpha
name: Meerkat Console
description: >-
  The design language for the Meerkat MFT console: a calm, dense, dark-only operations console for administrators
  who move files between systems and must prove that every file arrived unchanged.
---

# Meerkat Console

This file is the source of truth for how the console looks and behaves. It follows the [DESIGN.md format](https://github.com/google-labs-code/design.md): the YAML blocks hold the exact values, and the prose says why. Check it with `npx @google/design.md@0.4.0 lint design/DESIGN.md`, which also checks the contrast of every component's colours. The decisions come from the design review for #5, and the Overview covers what that issue's brief set out.

## Overview

The console is a tool for operations. The people who use it run file movement for an organization: platform engineers, integration teams, and whoever is on call when a nightly run fails. They open it to answer a question fast and get back to work: did last night's run deliver everything, why did this one file fail, can I show an auditor this file arrived unchanged.

It should feel like calm enterprise infrastructure: trustworthy, quiet, and confident. The confidence comes from alignment, spacing, and consistency, never from decoration. There are no gradients, textures, illustrations, or novelty type. Colour appears only where it means something.

- **Dark only.** There is no light theme, and none will be added.
- **Dense.** Compact by default: 13px text and 32px table rows, so a run with hundreds of deliveries fits on screen. A comfortable mode may come later, by moving the base to 14px, without a redesign.
- **Desktop only.** It's built for a full-screen browser on a 1080p display or larger, and it makes full use of 1440p and 6K displays. A mobile app would be a separate product with its own scope.
- **Partial failure is the normal hard case.** A run with 1 failed delivery among 400 must never look like a success. Design every run and list view for that case first: what needs attention leads, and successes recede.
- **Evidence first.** A delivery is only proven when the source has signed its manifest and the destination its receipt. The console makes evidence as visible as status.
- **Flows read as trees.** A flow is a tree of cards (ADR 0006): a trigger, a source, rules, then one path per destination, with failure paths and outcomes. Each path, and so each delivery it produces, must be readable on its own.
- **Built on the public API.** Every screen uses only the public API, like any other client. When a design needs data the API doesn't offer yet, that's a gap to raise for the API, not something the console works around.
- **The console never approves.** Flow approval and credential entry happen only in the signed CLI. The console shows that something waits for approval, who approved it, and the exact command, but it never offers an approve button or takes a credential.

## Colors

Every colour comes from the logo's navy (`#14202E`) and its amber (`#E2A04A`). There is one dark **base layer**, and the work sits on it in rounded **cards**, each a clear step lighter. Inside a card, the steps above it mark hover, selection, and things that float. Each step is the same small increase in lightness, so the hierarchy reads without borders.

- **Primary, amber (`#E2A04A`):** the brand and the one primary action on a screen. It also marks the selected item's leading edge and the keyboard focus ring. Amber never means a status, so no warning, error, or progress state uses it.
- **Surface ladder:**
  - **Base:** the one background behind everything. The sidebar and top bar sit directly on it, with no box of their own.
  - **Recessed:** wells inside a card, such as inputs, code blocks, and the flow canvas.
  - **Card:** the list, the opened item, and the panel.
  - **Hover:** a row, tab, or control being pointed at.
  - **Selected:** the selected row or item, which also gets the amber edge.
  - **Floating:** menus, dialogs, tooltips, and the panel when it overlays the page.
- **Text:** a cool off-white for primary text, and a muted blue-grey for metadata and labels.
- **Status:** green for succeeded, red for failed, violet for warning and retrying, blue for in progress, and slate for cancelled. Violet keeps warnings well clear of the brand's amber. Every status also has an icon and a label, so colour is never the only signal.
- **Colour marks what needs attention.** A status colour goes on the status icon only. The label beside it stays in the primary text colour, and there are no tinted backgrounds. Evidence marks and summary bars stay neutral where things went well, so a page of successes reads calm and a failure is the first colour the eye finds.

Every text colour below is at least 4.5:1 against every surface on the ladder. Every status colour is at least 3:1 against every surface for icons and marks.

```yaml
colors:
  primary: "#E2A04A"
  primary-hover: "#E5AB60"
  on-primary: "#1A1208"
  surface-base: "#0B111A"
  surface-recessed: "#0F1724"
  surface-card: "#141E2D"
  surface-hover: "#192637"
  surface-selected: "#1F2E42"
  surface-floating: "#26374E"
  on-surface: "#E6ECF4"
  on-surface-muted: "#97A8C0"
  success: "#4CC38A"
  error: "#FF7378"
  warning: "#B0A0FF"
  info: "#5EAEF5"
  cancelled: "#9AABC2"
  scrim: "#05080D"
```

## Typography

One family, **Ubuntu Sans**, sets the whole interface, with **Ubuntu Sans Mono** for anything a person might compare or copy: IDs, hashes, error codes, file paths, and commands. Both are self-hosted, because the console's content security policy allows no third-party fonts.

- **Three weights only:** 400 for text, 500 for labels and emphasis, 600 for titles and key numbers.
- **Tabular figures** wherever numbers line up: tables, counts, sizes, timestamps, and durations.
- **The base is 13px** for interface and table text. Labels and table headers are 11px, uppercase, with a little letter spacing.
- **Titles stay small:** 16px for sections and 20px for pages. The data is the content, and the chrome stays quiet. 24px is for key numbers, such as how many deliveries need attention, and 32px is rare.

```yaml
typography:
  label-sm:
    fontFamily: Ubuntu Sans
    fontSize: 11px
    fontWeight: 500
    lineHeight: 1.4
    letterSpacing: 0.04em
  body-sm:
    fontFamily: Ubuntu Sans
    fontSize: 12px
    fontWeight: 400
    lineHeight: 1.45
  body-md:
    fontFamily: Ubuntu Sans
    fontSize: 13px
    fontWeight: 400
    lineHeight: 1.5
  body-md-strong:
    fontFamily: Ubuntu Sans
    fontSize: 13px
    fontWeight: 500
    lineHeight: 1.5
  body-lg:
    fontFamily: Ubuntu Sans
    fontSize: 14px
    fontWeight: 400
    lineHeight: 1.55
  headline-sm:
    fontFamily: Ubuntu Sans
    fontSize: 16px
    fontWeight: 600
    lineHeight: 1.35
  headline-md:
    fontFamily: Ubuntu Sans
    fontSize: 20px
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: -0.01em
  display-sm:
    fontFamily: Ubuntu Sans
    fontSize: 24px
    fontWeight: 600
    lineHeight: 1.2
    fontFeature: '"tnum" 1'
  display-md:
    fontFamily: Ubuntu Sans
    fontSize: 32px
    fontWeight: 600
    lineHeight: 1.15
    letterSpacing: -0.01em
    fontFeature: '"tnum" 1'
  numeric-md:
    fontFamily: Ubuntu Sans
    fontSize: 13px
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: '"tnum" 1'
  code-sm:
    fontFamily: Ubuntu Sans Mono
    fontSize: 11px
    fontWeight: 400
    lineHeight: 1.45
  code-md:
    fontFamily: Ubuntu Sans Mono
    fontSize: 12px
    fontWeight: 400
    lineHeight: 1.5
```

## Layout

The layout follows the master-detail model, as in large cloud consoles, with one firm limit on depth.

- **Base layer:** the global sidebar and the top bar sit directly on the base, with no box. The sidebar holds the workspace switcher, then Flows, Runs, Agents, Audit, and Settings, with an icon and a label each.
- **Cards:** the work floats on the base as rounded cards: the list, the opened item, and the panel. Cards are separated from each other and from the window's edges by the same gap.
- **List:** the section's items, such as runs or agents, with filters above them.
- **Opened item:** selecting an item opens it in a card next to the list. Its sections are **tabs** across the top of the card, such as Overview, Canvas, Versions, and Runs for a flow, or Overview, Deliveries, Identity, and Activity for an agent. Tabs keep the content at full width, where a vertical menu would spend a column on a few short labels.
- **One deeper level:** an item inside an opened item, such as a delivery inside a run, opens in the **panel**, a card on the right, with breadcrumbs. There's never a second panel. Going deeper replaces the panel's content.
- **Addresses:** every list, item, and panel has its own address, so links can be shared and the browser's back button always works.

**Spacing follows the 8-point grid.** Every padding, margin, gap, and control height is a multiple of 8. 4px is allowed only for fine adjustments inside a component, such as between an icon and its label. Using one small set of distances everywhere is what makes the layout feel calm and deliberate.

- **Between cards, and around the window's edge:** 16px.
- **Inside a card:** 16px of padding for the list and the panel, and 24px for the opened item's content.
- **Inside content:** 16px between groups, and 8px within a group.
- **Heights:** 32px for rows, buttons, and inputs. 40px for tabs. 48px for the top bar.

Width is used in this order:
1. **1080p:** the panel slides over the page, with the floating surface and a shadow.
2. **From 1600px wide:** the panel docks beside the opened item as a card, and can stay open.
3. **Wider still:** the remaining width goes to more table columns.

Data views (tables, the flow canvas, timelines) fill their card. Forms, settings, and prose are capped at a 72-character line.

The top bar holds the breadcrumbs on the left, a command palette in the centre on `Ctrl/⌘ K` for jumping to any flow, run, agent, or delivery by name or ID, the orchestrator and relay connection status, the alerts indicator, and the user menu.

```yaml
spacing:
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 32px
  xxl: 48px
  xxxl: 64px
  gap: 16px
  card-padding: 16px
  content-padding: 24px
  row: 32px
  control: 32px
  tab-bar: 40px
  topbar: 48px
  sidebar: 240px
  sidebar-collapsed: 64px
  list-pane: 360px
  panel: 440px
  panel-dock-min-viewport: 1600px
  measure-ch: 72
```

## Elevation & Depth

There is **one base layer**, and the work floats on it as cards. A card is one clear step lighter than the base, with no border and no shadow. Inside a card, things are separated by space, not lines: rows have no fill at rest, and groups are set apart by the 8-point gaps. Avoid putting cards inside cards. A recessed well, a step darker than the card, holds inputs, code blocks, and the flow canvas.

Shadows are used only for things that float above the page: menus, dialogs, tooltips, and the panel when it overlays the page at 1080p. Floating layers use the floating surface, a soft shadow (`0 8px 24px` in the scrim colour at 45%), and a scrim behind modal dialogs.

**Interaction states** stay inside the same language:

- **Hover:** the row, tab, or control gets the hover surface, with its control radius.
- **Selected:** it gets the selected surface and a 2px amber edge on its leading side: the left for items in a list, and the bottom for tabs.
- **Keyboard focus:** a 2px amber ring with a 2px offset, always visible. It's never removed, and never replaced by a hover style.
- **Disabled:** the muted text colour, with no hover or selected state.

## Shapes

Corners are **nested**: the outer shape is the roundest, and each shape inside it is less round, so nested corners sit concentric instead of clashing.

- **Cards and the panel:** 12px.
- **Controls inside cards:** 8px. That covers buttons, inputs, rows and their hover and selected fills, tabs, menu items, code blocks, and the canvas's nodes.
- **Chips:** 6px.
- **Status and evidence marks:** fully round. They're the only round shapes.

```yaml
rounded:
  none: 0px
  chip: 6px
  control: 8px
  card: 12px
  full: 9999px
```

## Components

Component tokens set each component's surface, text, shape, and size. Behaviour and content rules follow below the tokens.

```yaml
components:
  card:
    backgroundColor: "{colors.surface-card}"
    textColor: "{colors.on-surface}"
    rounded: "{rounded.card}"
    padding: 16px
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary}"
    typography: "{typography.body-md-strong}"
    rounded: "{rounded.control}"
    height: 32px
    padding: 16px
  button-primary-hover:
    backgroundColor: "{colors.primary-hover}"
    textColor: "{colors.on-primary}"
  button-secondary:
    backgroundColor: "{colors.surface-selected}"
    textColor: "{colors.on-surface}"
    typography: "{typography.body-md-strong}"
    rounded: "{rounded.control}"
    height: 32px
    padding: 16px
  button-secondary-hover:
    backgroundColor: "{colors.surface-floating}"
    textColor: "{colors.on-surface}"
  nav-item:
    backgroundColor: "{colors.surface-base}"
    textColor: "{colors.on-surface-muted}"
    typography: "{typography.body-md}"
    rounded: "{rounded.control}"
    height: 32px
    padding: 8px
  nav-item-hover:
    backgroundColor: "{colors.surface-card}"
    textColor: "{colors.on-surface}"
  nav-item-selected:
    backgroundColor: "{colors.surface-hover}"
    textColor: "{colors.on-surface}"
  list-row:
    backgroundColor: "{colors.surface-card}"
    textColor: "{colors.on-surface}"
    typography: "{typography.body-md}"
    rounded: "{rounded.control}"
    height: 32px
    padding: 8px
  list-row-hover:
    backgroundColor: "{colors.surface-hover}"
    textColor: "{colors.on-surface}"
  list-row-selected:
    backgroundColor: "{colors.surface-selected}"
    textColor: "{colors.on-surface}"
  table-header:
    backgroundColor: "{colors.surface-card}"
    textColor: "{colors.on-surface-muted}"
    typography: "{typography.label-sm}"
    height: 32px
  tab:
    backgroundColor: "{colors.surface-card}"
    textColor: "{colors.on-surface-muted}"
    typography: "{typography.body-md}"
    rounded: "{rounded.control}"
    height: 40px
    padding: 16px
  tab-hover:
    backgroundColor: "{colors.surface-hover}"
    textColor: "{colors.on-surface}"
  tab-selected:
    backgroundColor: "{colors.surface-card}"
    textColor: "{colors.on-surface}"
    typography: "{typography.body-md-strong}"
  panel:
    backgroundColor: "{colors.surface-card}"
    textColor: "{colors.on-surface}"
    rounded: "{rounded.card}"
    width: 440px
    padding: 16px
  panel-overlay:
    backgroundColor: "{colors.surface-floating}"
    textColor: "{colors.on-surface}"
    rounded: "{rounded.card}"
  menu:
    backgroundColor: "{colors.surface-floating}"
    textColor: "{colors.on-surface}"
    typography: "{typography.body-md}"
    rounded: "{rounded.card}"
    padding: 8px
  menu-item:
    backgroundColor: "{colors.surface-floating}"
    textColor: "{colors.on-surface}"
    rounded: "{rounded.control}"
    height: 32px
  dialog:
    backgroundColor: "{colors.surface-floating}"
    textColor: "{colors.on-surface}"
    rounded: "{rounded.card}"
    padding: 24px
  dialog-scrim:
    backgroundColor: "{colors.scrim}"
  tooltip:
    backgroundColor: "{colors.surface-floating}"
    textColor: "{colors.on-surface}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.control}"
    padding: 8px
  input:
    backgroundColor: "{colors.surface-recessed}"
    textColor: "{colors.on-surface}"
    typography: "{typography.body-md}"
    rounded: "{rounded.control}"
    height: 32px
    padding: 8px
  code-block:
    backgroundColor: "{colors.surface-recessed}"
    textColor: "{colors.on-surface}"
    typography: "{typography.code-md}"
    rounded: "{rounded.control}"
    padding: 8px
  callout:
    backgroundColor: "{colors.surface-hover}"
    textColor: "{colors.on-surface}"
    rounded: "{rounded.control}"
    padding: 16px
  status-label:
    textColor: "{colors.on-surface}"
    typography: "{typography.body-sm}"
  status-icon-success:
    backgroundColor: "{colors.surface-card}"
    textColor: "{colors.success}"
  status-icon-error:
    backgroundColor: "{colors.surface-card}"
    textColor: "{colors.error}"
  status-icon-warning:
    backgroundColor: "{colors.surface-card}"
    textColor: "{colors.warning}"
  status-icon-info:
    backgroundColor: "{colors.surface-card}"
    textColor: "{colors.info}"
  status-icon-cancelled:
    backgroundColor: "{colors.surface-card}"
    textColor: "{colors.cancelled}"
```

### Status

Each delivery and run status has a colour, a Lucide icon, and a label, always shown together. The colour goes on the icon only, and the label is plain text:

| Status | Colour | Icon | Label |
| --- | --- | --- | --- |
| `succeeded` | `success` | `circle-check` | Succeeded |
| `failed` | `error` | `circle-x` | Failed |
| `retry_wait` | `warning` | `rotate-cw` | Retrying |
| `partial_failure` | `warning` | `circle-alert` | Partial failure |
| `pending`, `claimed`, `transferring`, `verifying` | `info` | `clock` | Waiting, Claimed, Transferring, Verifying |
| `cancelled` | `cancelled` | `ban` | Cancelled |

### Evidence

Evidence is shown as **two marks**: the first for the source's signed manifest, the second for the destination's signed receipt. A filled mark means signed, and an outlined mark means missing. Marks and labels are neutral: `verified` and `source_only` in the primary text colour, and `none` in the muted colour. The filled marks tell them apart, and the status beside them carries the colour. The label always sits beside the marks.

### Untrusted text

File names, agent names, and error codes come from agents and administrators. They're always shown as plain text, never as markup. File names can be missing once retention has deleted them, so every view must still make sense without one. A missing name reads "Name deleted by retention" in the muted colour. Error codes appear in the mono face exactly as stored.

### Approval

Where a flow version waits for approval, the console shows the waiting state, who has approved so far, and the exact CLI command in a code block with a copy button. There's never an approve button.

## Motion

Motion is part of the design, not decoration. Every animation answers one of two questions: **where did this come from**, or **what just changed**.

- **Space:** the panel slides in from the right edge, menus open from their trigger, and an opened item grows from the row that was selected.
- **State:** a delivery changing status animates its icon and chip. A transfer in progress shows live progress. Counts, such as deliveries that need attention, tick to their new value instead of jumping. A newly signed statement fills its evidence mark.
- **Never:** lists don't animate in row by row, pages don't make entrances, and nothing moves on its own when nothing has changed.

There are three durations and one easing family:

| Token | Duration | Used for |
| --- | --- | --- |
| `fast` | 120ms | hover, focus, small state changes |
| `base` | 220ms | menus, chips, counts, evidence marks |
| `slow` | 360ms | the panel, opening an item, layout changes |

Easing is `cubic-bezier(0.2, 0, 0, 1)` for things entering or changing, and `cubic-bezier(0.3, 0, 1, 1)` at the fast duration for things leaving.

A **reduce motion** setting in the user's preferences, which follows the operating system's preference by default, replaces every movement with an instant change or a fade of 120ms or less. Live progress still updates, but without animating between values.

## Iconography

Icons come from **Lucide**, the outline style only, at a 1.5px stroke. They are 16px in navigation, rows, and chips, and 20px in the top bar and empty states. In navigation, status, and actions, an icon always has a text label beside it. A bare icon is allowed only in a toolbar of well-known actions, such as copy, open, and more, and it then has a tooltip and an accessible name. Meerkat-specific marks, such as the two evidence marks, are drawn by us in the same stroke.

## Accessibility

WCAG 2.2 AA is a hard rule, built into these tokens rather than fixed screen by screen:

- **Contrast:** at least 4.5:1 for text, and 3:1 for interface parts, status icons, and evidence marks.
- **Keyboard:** everything can be done by keyboard, in a logical order, with the focus ring always visible.
- **No colour alone:** nothing is shown by colour alone.
- **Zoom:** every page works at 200% zoom.
- **Motion:** the reduce motion setting is respected everywhere.

## Do's and Don'ts

- Do use amber once per screen, for the main action, plus the selected item's edge and the focus ring. Don't use it for status, charts, or decoration.
- Do separate areas with space and surface steps. Don't reach for borders, dividers, or boxes around everything.
- Do pair every status colour with its icon and label. Don't rely on colour alone.
- Do keep status colour on the icon. Don't tint chip backgrounds or colour the labels, evidence, or summary bars of things that went well.
- Do show IDs, hashes, error codes, and commands in the mono face, and make them easy to copy.
- Do nest corners: 12px for cards, 8px for anything inside them, and 6px for chips. Don't round anything more for emphasis.
- Do keep every padding, margin, gap, and height on the 8-point grid. Use 4px only inside a component.
- Do keep one base layer with cards on it. Don't put cards inside cards, or give table rows a fill at rest.
- Do keep titles small and let data be the content. Don't add hero areas, illustrations, gradients, or textures.
- Do give every item its own address. Don't open a second panel or stack panels.
- Do show what waits for approval and the exact CLI command. Don't add an approve button or take a credential in the console.
- Do lead every run and list view with what needs attention. Don't let one failure among hundreds of successes look like a success.
- Do list the API calls a new screen needs, and raise any that are missing. Don't design around data the public API doesn't provide.
- Do show untrusted names as plain text, and handle a missing file name. Don't render agent-reported text as markup.
- Do animate to explain space and state, and honour reduce motion. Don't animate for decoration.
- Don't add a light theme.
