# Palisade — Design Specification

**Date:** 2026-09-26
**Status:** Awaiting user review
**Author:** Designed with the user; architecture and visual world approved section by section.
**Upstream:** `C:\Users\Ahri\Projects\hardentools` (Go, Security Without Borders)

---

## 1. Summary

Palisade is a Windows application that reduces the attack surface of a machine by disabling 26 low-value, frequently-abused Windows and application features — and can put every one of them back exactly as it was.

It is a C# port of the Go project `hardentools`. The port is not a transliteration: it keeps the saved-state registry format byte-compatible so a machine hardened by either tool can be restored by the other, and it fixes eleven defects the Go implementation carries. The user interface is new.

Palisade is **not an antivirus.** It does not detect, block, or remove malware. That boundary is stated in the application, not only in the README, because a security tool that implies protection it cannot deliver causes harm.

---

## 2. Scope

### 2.1 In scope — sub-project 1 of 5

- The shared core: measure model, state detection, apply, restore, saved-state registry format.
- All 26 hardening measures with full metadata.
- The desktop application.
- The command-line interface (`-harden`, `-restore`, defaults only).
- First-run warning, results surface, and per-measure detail.

### 2.2 Explicitly out of scope — sub-projects 2 through 5

These are required by the product plan and are **not** deferred indefinitely. Each is a separate specification and plan.

| # | Sub-project | Source of truth |
|---|---|---|
| 2 | RyTuneX tuning catalog (~185 toggles) | `C:\Users\Ahri\Projects\RyTuneX` |
| 3 | System modules (7 of them) | `C:\Users\Ahri\Projects\RyTuneX` |
| 4 | Policy scanner | `C:\Users\Ahri\Projects\RyTuneX\Helpers\PolicyHelper.cs` |
| 5 | Repair facility | `C:\Users\Ahri\Projects\RyTuneX` |

The core, the measure descriptor model, and the visual world are built in sub-project 1 so that sub-projects 2–5 extend them rather than redesign them.

### 2.3 Non-goals for this sub-project

- No machine-wide or multi-user operation. Changes are scoped to the signed-in account. Hardening another account means running Palisade from that account.
- No installer, no MSIX, no code signing. A portable folder.
- No automatic update mechanism.
- No risk scoring. Palisade does not compute or display a "security score," because it has no defensible basis for one.
- No telemetry of any kind.
- No per-measure illustrations or decorative icon tiles.

---

## 3. Licensing and attribution

Non-negotiable and load-bearing:

- **GPLv3.** `LICENSE.txt` copied verbatim from upstream. Source headers carry the GPL notice.
- **Original authors credited:** Claudio Guarnieri, Mariano Graziano, Florian Probst, Security Without Borders. Credited in the application About surface, in `README.md`, and in the CLI `--help`.
- **Upstream linked** as the authoritative source of the measure list and behaviour.
- **Hammer icon** by Travis Avery from the Noun Project. Any reuse preserves that credit.
- Port provenance is stated plainly: this is a port of hardentools, not a reimplementation from scratch.

---

## 4. Solution architecture

### 4.1 Projects

```
Palisade.slnx
├── src/
│   ├── Palisade.Core/          net10.0-windows    no Avalonia reference
│   ├── Palisade.App/           net10.0-windows    Avalonia 12.1.3
│   └── Palisade.Cli/           net10.0-windows    no Avalonia reference
└── tests/
    ├── Palisade.Core.Tests/    net10.0-windows
    └── Palisade.App.Tests/     net10.0-windows    Avalonia.Headless
```

### 4.2 Stack

| Concern | Choice | Why |
|---|---|---|
| Runtime | .NET 10 (`net10.0-windows`) | Current LTS-line SDK; required for `Microsoft.Win32.Registry` on Windows |
| UI | **Avalonia 12.1.3** | Chosen over WinUI 3 by the user after explicit comparison. Portable distribution with no MSIX, headless-testable UI, full styling control |
| MVVM | CommunityToolkit.Mvvm 8.4.2 | Source generators; matches the user's existing projects |
| Registry | `Microsoft.Win32.Registry` | In-box. No third-party registry library |
| Tests | xunit + Avalonia.Headless | View-model and layout tests without a display |

**Why Avalonia over WinUI 3**, recorded because it is a decision that will be re-litigated: WinUI 3 requires MSIX or an unpackaged-app workaround, cannot be unit-tested headlessly without a display, and constrains custom styling. Palisade must be a portable folder, must be testable in CI, and must own its visual world completely.

### 4.3 The hard boundary

`Palisade.Core` has **no reference to Avalonia** and contains every security-critical operation: state detection, saved-state read and write, apply, restore, and ordering. The App and Cli are both thin shells over it.

This is a testability decision and a safety decision. All of the dangerous logic is reachable from `Palisade.Core.Tests` without a UI, and no view model can grow a private path to the registry.

---

## 5. The measure model

### 5.1 Descriptor plus handler

The Go code implements `HardenInterface` with one Go type per measure — 26 types, each carrying its own `Harden`, `IsHardened`, `Name`, `LongName`, `Description`, and `HardenByDefault`, with shared behaviour copy-pasted between them.

Palisade replaces this with a **data descriptor** plus a small set of **mechanism handlers**:

```csharp
public sealed record MeasureDescriptor(
    MeasureId Id,
    string Name,               // short, column width
    string LongName,
    string Consequence,        // the display-size sentence: what breaks, in the user's applications
    Mechanism Mechanism,
    bool RequiresElevation,
    bool HardenByDefault,
    MeasureGroup Group,
    IReadOnlyList<MeasureConstraint> ConstrainedBy,
    IReadOnlyList<AvailabilityRule> Availability);
```

Adding a 27th measure — which sub-projects 2–5 will do at scale — becomes a data change plus, at most, a new handler. It does not become a new type with copy-pasted methods.

### 5.2 The six mechanisms

All 26 measures are expressed through these six. A seventh requires a design amendment, not a code review.

| Mechanism | What it does | Go types it replaces | Measures |
|---|---|---|---|
| `RegistryDword` | One `REG_DWORD` value → one hardened value | `RegistrySingleValueDWORD` | WSH, UAC, LSA, PUA, Office ActiveX, Show file extensions, Autorun, 5 LibreOffice |
| `RegistryString` | One `REG_SZ` value → one hardened string | `RegistrySingleValueSZ` | LibreOffice update-check measures |
| `VersionedPath` | Expand a versioned application path template, then set values beneath every match | `OfficeRegistryRegExSingleDWORD`, `AdobeRegistryRegExSingleDWORD` | 4 Office, 5 Adobe, OneNote |
| `DisallowRun` | Add or remove entries in the Explorer `DisallowRun` list | `CmdDisallowRunMembers`, `PowerShellDisallowRunMembers` | `cmd.exe`, PowerShell |
| `FileAssociation` | Open-with ProgID restrictions | `ExplorerAssociations` | File associations |
| `NonRegistry` | Change state that is not a registry value, with its own saved-state record | `WindowsASRStruct`, `RecallStruct` | Windows ASR rules, Recall |

Six mechanisms cover all 26 measures. A seventh requires a design amendment, not a code review.

Two Go composite wrappers exist — `RegistryMultiValue` (a bundle of single values) and `MultiHardenInterfaces` (a measure composed of several sub-measures). Both are retained in Core as **composites of the mechanisms above**, not as mechanisms in their own right. `Cmd` and `PowerShell` are each a `MultiHardenInterfaces`; `Autorun` and `Show file extensions` are each a `RegistryMultiValue`.

**Versioned paths are expanded to concrete paths before any write, and the version list is discovered rather than hardcoded.** Upstream carries a fixed list — `standardOfficeVersions` = `12.0, 14.0, 15.0, 16.0` and `standardAdobeVersions` = `DC, 2020, XI` — and formats a path template over it. Palisade enumerates the versions actually installed, produces a concrete path list, and writes only those. Resolving to zero paths is a reported failure with the reason, never a silent success.

**Upstream coverage gap, carried forward honestly:** `standardOfficeApps` is `Excel, PowerPoint, Word`. **Outlook is not hardened**, and neither is Publisher or Access. OneNote is handled separately with `onenote` as its app name. Sub-project 1 reproduces the upstream measure set and does not add Office apps; the gap is documented in the measure's own detail text rather than silently inherited.

### 5.3 Groups

Windows, Microsoft Office, Adobe, LibreOffice, OneNote, System. Used for the group rail in the column and for the measure ordering.

---

## 6. The 26 measures

Verified against `global_vars.go` in the upstream source. `Default` is `hardenByDefault`.

### 6.1 Available without elevation (12)

| Measure | Mechanism | Default | Group |
|---|---|---|---|
| Windows Script Host | `RegistryDword` | yes | Windows |
| Office OLE objects | `VersionedPath` | yes | Microsoft Office |
| Office macros | `VersionedPath` | yes | Microsoft Office |
| Office ActiveX | `RegistryDword` | yes | Microsoft Office |
| Office DDE | `VersionedPath` | yes | Microsoft Office |
| Adobe Reader JavaScript | `VersionedPath` | yes | Adobe |
| Adobe Reader OpenAction | `VersionedPath` | yes | Adobe |
| Adobe Reader Protected Mode | `VersionedPath` | yes | Adobe |
| Adobe Reader Protected View | `VersionedPath` | yes | Adobe |
| Adobe Reader Enhanced Security | `VersionedPath` | yes | Adobe |
| Show file extensions | `RegistryDword` (multi) | yes | Windows |
| OneNote block extensions | `VersionedPath` | yes | OneNote |

### 6.2 Requires elevation (14)

| Measure | Mechanism | Default | Group |
|---|---|---|---|
| Autorun | `RegistryDword` (multi) | yes | Windows |
| PowerShell | `DisallowRun` | yes | Windows |
| Command prompt (`cmd.exe`) | `DisallowRun` | **no** | Windows |
| UAC prompt behaviour | `RegistryDword` | yes | Windows |
| File associations | `FileAssociation` | yes | Windows |
| Windows ASR rules | `NonRegistry` | yes | Windows |
| LSA protection | `RegistryDword` | **no** | System |
| Defender PUA blocking | `RegistryDword` | yes | System |
| LibreOffice macro security | `RegistryDword` | **no** | LibreOffice |
| LibreOffice Ctrl-click hyperlinks | `RegistryDword` | **no** | LibreOffice |
| LibreOffice untrusted referer links | `RegistryDword` | **no** | LibreOffice |
| LibreOffice enforce update checks | `RegistryDword` | **no** | LibreOffice |
| LibreOffice disable update links | `RegistryDword` | **no** | LibreOffice |
| Recall | `NonRegistry` | **no** | Windows |

Eight measures default to off. The Go tool excludes them from its default set; Palisade shows them, states their cost, and leaves the choice with the user.

### 6.3 Known inter-measure constraints

These are real and are what the blast-radius network visualizes:

1. **`cmd.exe` ↔ `DisallowRun` key.** `DisallowRun` is a single list. Adding or removing `cmd.exe` and `powershell.exe` entries share one registry value, so the two measures are not independent.
2. **ASR rules ↔ Defender antivirus.** ASR rule application can fail when Windows Defender antivirus is disabled or a third-party AV is installed. This surfaces as `unavailable` with the reason stated, not as a failed write.
3. **Office PowerShell ↔ Office macro/DDE measures.** All four are policy values under one Office version branch; a version expansion that resolves some and not others produces a partial state that must be reported honestly.
4. **Recall ↔ Windows build.** Recall is absent on builds that never shipped the feature; that is `unavailable`, not `slack`.

---

## 7. Saved state and Go compatibility

### 7.1 Location

`HKEY_CURRENT_USER\SOFTWARE\Security Without Borders\`

### 7.2 Value name format

Verified against `registry_utils.go`. The separator is **four underscores** in the current format and **one underscore** in the legacy format.

| Prefix | Payload | Meaning |
|---|---|---|
| `SavedStateNew_` | `<ROOT>____<KEYPATH>____<VALUENAME>` | Original `REG_DWORD` |
| `SavedStateNewSZ_` | `<ROOT>____<KEYPATH>____<VALUENAME>` | Original `REG_SZ` |
| `SavedStateNotExisting_` | `<ROOT>____<KEYPATH>____<VALUENAME>` | Value did not exist; restore must delete it |
| `SavedStateNonReg_` | `<feature>` | Non-registry state, e.g. Recall feature state. The Go tool persists this under the lowercase name `recall` (`recall_feature.go:50`), so the `MeasureId` is `recall`; the Windows optional feature name `Recall` passed to the PowerShell cmdlet is a separate value and is not the id. |
| `SavedState_` | `<ROOT>_<KEYPATH>_<VALUENAME>` | **Legacy**, single underscore. Read and restored, never written |

Root key names: `CLASSES_ROOT`, `CURRENT_USER`, `LOCAL_MACHINE`, `USERS`, `CURRENT_CONFIG`, `PERFORMANCE_DATA`.

### 7.3 Compatibility requirements

1. Palisade **reads** every prefix above, including the legacy single-underscore form.
2. Palisade **writes only** the four current prefixes, with four underscores.
3. Legacy parsing is guarded: a value name that does not split into a known root, a non-empty key path, and a value name is skipped with a recorded warning — never guessed at, never partially applied.
4. Restoring a machine hardened by the Go tool is a supported, tested operation. This is covered by fixture tests built from the Go code's exact write format.
5. Palisade never deletes a saved-state value it did not successfully verify as restorable.

### 7.4 Restore ordering

Restore order is **deterministic and explicit**: measures are restored in reverse dependency order, computed from the constraint graph, with ties broken by a stable measure id. The Go code restores in map-iteration order, which is nondeterministic in Go and is a genuine source of restore failures when measures share a registry path.

---

## 8. Defects fixed, not reproduced

Eleven. Each is a deliberate divergence from upstream, recorded here so a future maintainer does not "fix" it back.

| # | Defect | Palisade's behaviour |
|---|---|---|
| 1 | File-association `IsHardened` is broken and never reports correctly | Correct detection, covered by tests |
| 2 | `DisallowRun` handle lifetime is unsafe | Deterministic handle lifetime, single owner, closed in `finally` |
| 3 | ASR state restoration is inexact — the original rule set is not fully captured | Exact original state recorded and restored |
| 4 | Restore order is nondeterministic | Explicit reverse-dependency order with stable tie-break |
| 5 | Legacy `SavedState_` parsing is unguarded and can mis-split on underscores in key paths | Guarded split; malformed entries skipped and reported |
| 6 | `markStatus` errors are silently swallowed | Every status write is checked and surfaced |
| 7 | The Go tool calls `os.Exit` after operations, skipping cleanup | No process exit; all resources released through `IDisposable` / `await using` |
| 8 | Fixed-size labels truncate explanatory text | Real text wrapping; prose is never truncated |
| 9 | The versioned-path version list is hardcoded (`12.0/14.0/15.0/16.0`, `DC/2020/XI`), so an unlisted installed version is silently skipped and a zero-path resolution reports success | Versions enumerated from what is installed; zero resolutions is a reported failure naming the reason |
| 10 | A measure that cannot apply looks identical to one that has not been applied | Four-state model (§9) |
| 11 | Elevation is all-or-nothing, with no explanation of what was lost | Declining elevation states exactly which 14 measures are unavailable and why |

---

## 9. Application state model

The single most important behavioural change. The Go tool has two states — hardened or not — which conflates four different situations into one silent checkbox.

| State | Meaning | Column treatment | Colour |
|---|---|---|---|
| `taut` | Applied by Palisade; original recorded | Taut red cord | Red |
| `slack` | At its original state; not applied | Slack ash-gray rod | Ash gray |
| `stressed` | Applied by something else, blocked by policy, or the value changed after Palisade wrote it | Bent rod | Amber |
| `unavailable` | Cannot apply on this machine, with the reason stated in words | Ghosted rod | Concrete gray |

**No state is signalled by colour alone.** Each carries a distinct glyph and a word, as required by §11.

`stressed` is the state that matters most. It is where the Go tool lies to the user: a value that was already restricted by Group Policy, or that another tool changed, reads as "not hardened," and applying over it silently discards whatever was there.

---

## 10. Visual design

Full direction contract: `.impeccable/surfaces/main-window.md`. Product truth: `PRODUCT.md`.

### 10.1 The world

A **tensegrity column**: compression rods held in a network of tension. Applied measures are taut cords. Restored measures are slack rods that have dropped. Blocked or externally-chosen measures are visibly stressed. This world was chosen because it makes the product's actual mechanism visible — a hardening change redistributes load, it is not a checkbox — and because engineering diagrams are the native visual language of the people who read hardening guides.

Three disciplines were raised into it from directions that lost: **pixel-grid discipline** (one hard measured cell per value, exact column pitch, no rounded interior), **word as matter** (the consequence sentence is the largest type in the pane, the registry key path drops to small monospace), and **ink-density hierarchy** (rank by weight and value contrast, not size alone, so a 26-row wall still has one visible focal row).

### 10.2 Colour — Restrained

Neutrals plus one accent.

- Ground: pale concrete
- Structure: matte carbon black
- Accent: red, **only** where tension is being reported
- Amber: **only** for `stressed`, so it means one thing and nothing else
- Slack: ash gray

**Light, not dark** — the material decided it. The world is a pale concrete ground and slack rods read as ash only against a light field; a dark theme would mean recolouring the concrete and breaking the world.

### 10.3 Type

- UI: Segoe UI Variable → Segoe UI → Arial. A workhorse stack, correct for an Operate surface.
- Measured values: Consolas for registry key paths, recorded original values, current values, and every numeric label.
- The consequence sentence is set in the UI face at display size — **not** a display serif, which would be costume in this context.

### 10.4 Layout — 1280×860, all 26 measures visible without scrolling

| Zone | Width | Contents |
|---|---|---|
| Masthead | full, 56 px | `PALISADE` in letterspaced caps; account scope and elevation state; a 26-cell state strip so the whole machine reads in one glance |
| The column | 420 px | 26 rods at 28 px pitch with a group rail; hairline group separators |
| Detail | flexible | Consequence sentence at display size; what it does; what breaks; recorded original vs current value; key path in small monospace; constrained and constraining measures |
| Network | 360 px | The selected rod's load path and counter-forces. Never a 26-node hairball |
| Action bar | 72 px | Selection summary; `APPLY` as a square main-disconnect control; `RESTORE` |

28 px × 26 = 728 px, which fits the 732 px available at the default height. This is a checkable layout claim and there is a headless test asserting it.

### 10.5 Signature interaction

Selecting a rod propagates tension to its counter-forces in the network and marks the constrained rows in the column. Before touching `APPLY`, the user can see what their selection moves.

### 10.6 Motion

The column breathes once on open and on state change: taut cords tighten, slack rods drop. Low amplitude, compositor transforms only, and it holds fully static under `prefers-reduced-motion`.

### 10.7 Explicitly rejected

Shields, padlocks, locks, neon, glow, gradients, glass, risk scores and badges, any "protection" or "secure" language, gamification, per-measure icon tiles, forced 3D picking, and stock enterprise-admin table composition.

---

## 11. Accessibility

- **Keyboard-complete.** Every action reachable and operable without a mouse: selection, group jumps, selection toggling, apply, restore, and dismissal of every dialog. Focus is always visible and never trapped outside a modal.
- **No colour-only state.** Every state carries a glyph and a word (§9).
- **Text wraps.** Explanatory prose is never truncated. The Go tool's fixed-size labels are replaced.
- **Contrast** meets WCAG 2.1 AA for body text and for all four state colours against both the concrete ground and the carbon rods.
- **Reduced motion** is honoured (§10.6).
- **Screen reader names** on every control are the human phrasing — "Disable the Windows command prompt" — not a symbol or a state token.
- Dialogs move focus on open, trap it while open, and restore it on close.

---

## 12. Test strategy

### 12.1 `Palisade.Core.Tests` — the safety net

The most important tests in the project.

1. **Saved-state round-trip.** Write with Palisade, read back, assert byte-identical value names including the four-underscore separator.
2. **Go-format compatibility fixtures.** Saved-state values constructed to the Go tool's exact format, including the legacy single-underscore form, must be readable and restorable.
3. **Guarded legacy parsing.** Malformed legacy names are skipped and reported, never partially applied.
4. **Restore ordering.** Given a constraint graph, restore runs in reverse dependency order; the order is stable across 100 runs.
5. **Per-mechanism detection and apply/restore** for all six mechanisms.
6. **Versioned path resolution.** Patterns resolve to concrete installed paths; an unresolvable pattern is a reported failure.
7. **Four-state derivation** for each of the 26 measures, including the `stressed` cases: Group Policy pre-set, third-party AV present, feature absent from the build.
8. **Privilege split.** With elevation declined, exactly the 14 privileged measures report `unavailable` with a reason.
9. **Idempotence.** Applying twice equals applying once. Restoring twice equals restoring once.

Registry access is abstracted behind an interface so tests run against an in-memory hive with no real registry writes. **No test in this project writes to the real registry.**

### 12.2 `Palisade.App.Tests` — headless Avalonia

1. **Layout claim.** At 1280×860 all 26 rods are realised and visible with no scrolling.
2. **View-model state.** Selection, constraint propagation, and the action bar's enabled/disabled logic.
3. **First-run gate.** No apply path is reachable before the warning is acknowledged.
4. **Dialog focus behaviour.**
5. **Reduced-motion** resolves to the static presentation.

### 12.3 Manual verification the user performs

The agent cannot inspect rendered images. The user reviews the final render against the direction contract in `PRODUCT.md` and `.impeccable/surfaces/main-window.md`. This is a scheduled checkpoint, not an afterthought.

---

## 13. Delivery

- `dotnet publish` self-contained, single folder, no installer, no MSIX.
- The CLI ships in the same folder and is usable when the GUI cannot start — which covers the upstream known issue where the Go tool's Fyne UI fails on RDP sessions and machines without OpenGL 2.0. Avalonia has no such requirement, but the CLI remains a supported path.
- A `--help` on the CLI states what Palisade is and is not, and credits upstream.

---

## 14. Appendix A — Verified upstream constants

From `constants.go` and `registry_utils.go`, recorded so the plan does not re-derive them:

```
hardentoolsKeyPath            = "SOFTWARE\Security Without Borders\"
explorerPoliciesKey           = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
explorerDisallowRunKey        = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"
errorRestoreDisallowRunFailed = "Fully restoring DisableRun settings failed"
logPath                       = "hardentools.log"
```

Palisade keeps the registry paths exactly. It does **not** keep the log filename — it logs to `%LOCALAPPDATA%\Palisade\`, since writing a log to the working directory is an upstream defect that fails under Program Files and on read-only media.

## 15. Appendix B — Decisions made during design, recorded so they are not relitigated

| Decision | Rationale |
|---|---|
| Avalonia over WinUI 3 | Portable folder, headless tests, full styling control |
| Core has no Avalonia reference | All security-critical logic is testable without a UI |
| Descriptor + handler over one type per measure | Sub-projects 2–5 add measures at scale |
| Fix upstream defects rather than reproduce them | A faithful port of a lie is not a port |
| Light theme | The material forces it; slack reads as ash only on a light ground |
| Deterministic network layout, not a force simulation | The same machine must not look different twice |
| v1 traces blast radius but does not cascade selection | Silently widening a selection in a tool that writes to the registry loses trust. Cascading is v2 |
| No per-measure illustrations | Reads as decoration, not evidence |
| Renamed from Hardentools to Palisade | The suite's scope is broader than hardening; the rename is the user's choice |

## 16. Appendix C — Scope check for planning

This specification covers one subsystem: the hardening catalog and the shell that operates it. It is a single implementation plan, but that plan is large and will be **phased** in this order:

1. `Palisade.Core` — model, mechanisms, saved state, restore ordering, with tests. No UI work begins until this is green.
2. The 26 descriptors as data, with detection tests.
3. `Palisade.Cli` — the thin shell, which proves the core end to end.
4. `Palisade.App` — visual world, then the column, detail, network, and action bar.
5. First-run gate, results surface, and the accessibility pass.

Phasing exists so that the riskiest material — the saved-state format and restore correctness — is proven before any visual work is built on top of it.
