# PORTING.md — Palisade.Tuning (RyTuneX port)

## Source and license

- Upstream: `C:\Users\Ahri\Projects\RyTuneX` (WinUI 3, GPLv3). Read-only reference.
- Palisade is GPLv3; every ported file carries both copyright lines
  (Security Without Borders + RyTuneX contributors).

## Architecture

`Palisade.Tuning` is a plain .NET class library (no WinUI/Avalonia/WinForms). It keeps
RyTuneX's command-set fidelity: each toggle is a `TuningOption` record whose
`ApplyCommands` / `RevertCommands` are the verbatim command lines from
`Helpers/OptimizeSystemHelper.cs` (the `Disable*/Enable*` method pairs), run through
`cmd /c` exactly as upstream's `OptimizationOptions.StartInCmd` did.

- `Models/TuningModels.cs` — the `TuningOption` record and categories.
- `Runtime/CommandRunner.cs` — cmd execution with exit codes and output capture.
- `Runtime/TuningStateStore.cs` — applied-state markers under `HKCU\SOFTWARE\Palisade\Tuning`
  (RyTuneX uses an equivalent marker key under `SOFTWARE\RyTuneX\Optimizations`).
- `Catalog/OptimizeCatalog.cs`, `Catalog/ServicesCatalog.cs` — the transcribed toggle
  definitions.
- `TuningEngine.cs` — `TuningCatalog`, `TuningEngine.ApplyAsync/RevertAsync`.

## Ported toggle set (this pass)

36 toggles across AI, Explorer, Performance, Gaming, Security, System, Telemetry,
Services, Network, Personalization — including Windows Recall, Windows AI, telemetry
services/tasks/hosts/firewall, background apps, service host splitting, SysMain,
Windows Search, print spooler, HomeGroup, WMP sharing, Program Compatibility Assistant,
System Restore, WPBT, legacy boot menu, mouse/keyboard latency sets, and Explorer
tweaks. Every command string is upstream's.

## Divergences and stubs

1. **Service control**: upstream `SetServiceStatusAsync` ran `sc` with a registry
   fallback. Palisade emits `sc stop X` + `sc config X start= disabled` (and the
   inverse), which reaches the same end state and shares the fallback's effect.
2. **Telemetry hosts-file block**: upstream edited `drivers\etc\hosts` from C#.
   Ported as an idempotent PowerShell append/remove of the same 16 host entries.
3. **Windows AI CBS package removal** (`RemoveAISystemComponents` — DISM removal of
   CoreAI/AIX packages and machine-learning DLL deletion) is not yet in the toggle's
   command list; it is the most destructive upstream operation and is deferred pending
   a confirmation step. The policy/service/schtasks surface of the same toggle ships.
4. **Not yet ported** (scaffolded, incremental data entries):
   - Remaining OptimizeSystemHelper pairs (Windows Update, network throttling variants,
     privacy/security page pairs beyond the above).
   - `PolicyHelper.cs` (policy scanner, 2657 lines) → `Policy` category.
   - `StartupHelper.cs` (startup items) → `Startup` category.
   - `SystemStateDetector.cs` (system info) → `System` category.
   - Debloat/winget (`WingetPackage` + page logic) → `Debloat` category.
   - Repair page operations → `Repair` category.
5. **WinRT-only surfaces** (app icon cache, Store review prompt, MSIX app info) were
   dropped: UI concerns with no tuning effect.

## UI

`Palisade.App`'s Optimize page binds `TuningCatalog` through `OptimizeViewModel`
(search, per-toggle apply/revert, revert-all, state markers). The visual language is
the Fluent world described in DESIGN.md.

## Tests

`tests/Palisade.Tuning.Tests` — 36 tests covering catalog integrity (unique ids,
non-empty titles/descriptions/commands, known categories) and engine lookup.
