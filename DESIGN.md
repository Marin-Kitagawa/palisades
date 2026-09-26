# DESIGN.md - Palisade

<!-- impeccable:design-schema 1 -->

## World

**Fluent (WinUI 2/3), matching RyTuneX's design language.** Layered light surfaces on
a Mica-like #F3F3F3 base, white layer cards with #EBEBEB strokes and 8px radii, Segoe UI
Variable with the system accent #0078D4 as the single saturated hue, WinUI semantic
colors for states. Chosen by the user on 2026-09-26, replacing the tensegrity world
(kept as history in git; the tensegrity surface brief is superseded).

## Mode

**Operate** on every surface: the visitor completes a task (understand state, apply,
keep the receipt). Scanability, native Windows expectations, and the real usage scene
outrank expression.

## Tokens

### Layers
- `BgBaseBrush` #F3F3F3 - window ground (Mica stand-in)
- `LayerBrush` #FFFFFF - cards, content frame, dialogs
- `LayerAltBrush` #FBFBFB - quiet info bars
- `SubtleFillBrush` #0A000000 / `SubtleFillHoverBrush` #14000000 - nav and hover fills

### Strokes
- `CardStrokeBrush` #EBEBEB - card borders
- `ControlStrokeBrush` #E1E1E1 - control borders
- `DividerStrokeBrush` #EEEEEE - 1px separators

### Text
- `TextPrimaryBrush` #1B1B1B, `TextSecondaryBrush` #5D5D5D,
  `TextTertiaryBrush` #8A8A8A, `TextDisabledBrush` #B6B6B6,
  `TextOnAccentBrush` #FFFFFF

### Accent and semantic states
- `AccentBrush` #0078D4, hover #1A86D9, pressed #005FB1, text #0067C0, soft #EAF3FC
- Success #0F7B0F (soft #EFF7EF) - hardened
- Warning #9D5D00 (soft #FDF6EC) - needs administrator
- Error #C42B1C (soft #FDF3F2) - changed externally, failed
- Neutral #5D5D5D (soft #F5F5F5) - not applied

### Faces
- UI: **Segoe UI Variable Display/Text, Segoe UI**
- Measurement: **Cascadia Mono, Consolas** - registry paths, commands, recorded originals
- Icons: **Segoe Fluent Icons, Segoe MDL2 Assets** - nav and info-bar glyphs only

## Scale

Title 28 semibold (page), subtitle 20 semibold (selected measure, dialogs), body 14,
caption 12, mono 11.5. Nav pane: title 14 + caption subtitle.

## Geometry

4px control radii, 8px card/dialog radii, 10px toggle track and state pills, 3px admin
tag. Cards are the container; never nested cards. The content frame carries the WinUI
signature: 8px rounded top-left corner, 1px top stroke, over the pane.
## States

Every state is carried by **dot + word** (never color alone):

| State | Word | Dot |
|---|---|---|
| Taut | hardened / applied | success green |
| Slack | not applied | neutral gray |
| Stressed | changed externally | error red |
| Unavailable | needs administrator | warning amber |

## Navigation

NavigationView pattern: 272px pane, icon + title + caption per item, accent 3px
selection pill, privilege card above, GPLv3/not-an-antivirus footer below.

## Patterns

1. Page header: title + one-sentence subtitle, expert-settings toggle top right.
2. InfoBar band: warning bar for the elevation state (with relaunch action), quiet bar
   for the live status line with refresh action.
3. Measure cards: name + admin tag, consequence (2 lines, ellipsis - full text in the
   detail rail), mono registry summary, state pill, expert toggle.
4. Detail rail: selected measure at full length (consequence, registry, recorded
   original, constraints) + blast-radius figure card.
5. Apply is the one accent control in the command bar; restore and re-apply are subtle.
6. Confirmation and receipt are centered ContentDialog-style cards over smoke; the
   receipt lists every outcome and every warning.
7. The not-an-antivirus boundary is stated in the pane footer and the confirm preamble.

## Motion

None beyond default control transitions. The busy overlay is a thin indeterminate
progress line with a caption.

## Voice

Plain, concrete, unsensational. State words are lowercase. Errors name the problem and
the recovery. No fear language, no shields, no locks.

## Tuning surfaces (Optimize, Policies, Startup, Debloat, Repair, System)

The same Fluent world: page header, grouped cards or tables, toggles and state pills
for reversible toggles, mono for every path and command, semantic colors spent only on
real states. Each row carries the same contract as a measure: what it changes, at what
cost, and whether it can be taken back.
