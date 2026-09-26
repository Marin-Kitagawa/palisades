---
version: 1
slug: "main-window"
primary_target: "main-window"
related_targets: []
---

---
version: 1
slug: "main-window"
primary_target: "main-window"
related_targets: []
---

# Surface brief — main window

## Scope and visitor mode

The Palisade main window: the catalog of 26 hardening measures, its blast-radius network, the apply/restore flow, and the results surface. **Operate** mode. Desktop, Avalonia, Windows 11, single window, resizable. This milestone ships security hardening only; RyTuneX tuning/modules land in later sub-projects against the same world.

## Audience, job, task

Individuals at risk, per PRODUCT.md. Job: find out what is currently applied to this account, understand exactly what each change costs in their own applications, apply a selection, and get it back if a trade-off is unacceptable. Frequency: rarely, deliberately, often while traveling or before handling untrusted files. Long sessions of reading before a short decisive act.

## Proof and content

The 26 measures with their real registry paths, the real dependency edges between them, and the real consequences, in the user's own words. The blast-radius network is the proof: it shows that DisallowRun on PowerShell, ASR rules, and the Office PowerShell policy all constrain each other. Content is authored at full fidelity from the Go source; nothing is illustrative. No invented risk scores anywhere.

## Constraints

GPLv3, credit Security Without Borders. Express and Arial UI faces; Consolas for values, key paths, and every measured label. No color-only state — every state carries text and a glyph. Keyboard-complete. No fear language, no shields, no locks, no padlocks, no neon. Deterministic restore order. Byte-compatible with the Go saved-state registry format.

## Chosen direction and memorable moment

A tensegrity column: 26 carbon rods in a load-bearing network, red cord as the only accent. Applied measures are taut cords; restored measures are slack rods dropping to ash gray; blocked or externally-changed measures are visibly stressed.

**Memorable moment:** dragging the red cord slack on a single rod and watching the load visibly redistribute to its counter-forces down the whole column — the moment a user understands that hardening one thing moves something else, before applying anything.

## Unresolved decisions

Resolved in the approved design; recorded here so this brief is not read as still open.

- **Network layout:** deterministic hand-tuned layout, not a force simulation. A simulation makes the same machine look different twice, and this product's promise is that it is not mysterious.
- **Blast-radius selection:** v1 traces and warns, it does not cascade. Selecting a rod states that it constrains three others; it does not auto-select them. Cascading selection is v2 — in a tool that writes to the registry, silently widening a selection is exactly the behavior that loses trust.
- **Dark or light:** light. The world is a pale concrete ground and slack rods read as ash only against a light field; dark would mean recolouring the concrete and breaking the world. Dense technical text is also more legible on a light ground.
- **Per-measure art:** dropped. A small blocked-out figure per rod would read as decoration rather than evidence.

Still open, and deliberately so: the exact pitch values for the group rail, and whether the 26-cell masthead strip is a row or a column at narrow widths. Both are layout tuning, not decisions.


## Direction contract

**THESIS.** A hardening change is a load redistribution, not a checkbox: every rod has a recorded prior position, and moving one moves the whole column. This surface owns the idea that the network is the interface, and it refuses the category default of a grid of shields with one big PROTECT button — and its opposite, an enterprise settings table where each row is independent, which is the false claim this product would be making.

**OWN-WORLD.** Matte carbon-black rods on pale concrete; red cord as the single saturated accent, used only where tension is being reported; ash gray for slack. Engineering monospaced labels carrying real measured values (registry path lengths, the recorded original, the applied value) on leader lines pinned to nodes, the layout obeying the strut network rather than a page grid. Corners square. No rounded cards, no soft interior padding masquerading as structure. Hierarchy by weight and value contrast, not size alone.

**STORY.** The user arrives at a machine they do not fully trust and a list of 26 things about it they cannot see. They learn that each rod has a known original position, that some rods are already taut, that one rod carries the cable to three others, and that the whole thing can be dropped back exactly. They believe reversibility because they can see the recorded original printed next to the current value on every rod. They act: select, read the consequence sentence, apply, and keep the receipt.

**FIRST VIEWPORT.** A single column of 26 rods standing on a pale concrete ground, filling the window's height, rods in strict vertical pitch with the red cord zigzagging between them. The selected rod sits at the visual center, its consequence sentence set at display size in the upper third — the largest type on the surface — with its registry key path demoted to small monospace beneath. The blast-radius network occupies the right third as a force diagram over the same concrete. The primary action, APPLY, is a square control bottom-left, below the network, styled as a main disconnect rather than a button. Window is 1280x860 at first open.

**FORM.** The tensegrity column, fused from catalog challenger `kinetic-sculpture-automata-tensegrity-breathing-column`; it was not in my grounded list. Form position: won on both weighing axes (audience identification, product clarity) and became the build candidate over the assigned direction. Seed key `a78c5838`, assigned index 7. Three raises applied and named: **pixel-grid discipline** (from eBoy pixorama), **word as matter** (from Alphabet storm), **ink-density hierarchy** (from ASCII phosphor grid).

**FINISH.** unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
