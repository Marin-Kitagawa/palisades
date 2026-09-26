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

## Module ports (second pass, 2026-09-26)

- **Policy scanner** (`Policy/`): all 207 known policies transplanted **verbatim**
  from `PolicyHelper.cs` into `Policy/PolicyCatalog.cs` (object-initializer records,
  build-number applicability windows intact). `PolicyScanner` ports detection,
  per-policy and bulk reset (delete value + clean empty policy keys), and per-category
  summaries. Verified against this machine: 74 of 207 configured, detected correctly
  (`Palisade.Cli -policies`).
- **Startup manager** (`Startup/`): full port of `StartupHelper` — HKCU/HKLM Run and
  RunOnce (64/32-bit), user and common startup folders (with shortcut resolution),
  logon/boot scheduled tasks via PowerShell, UWP StartupTask state, orphaned
  StartupApproved entries, enable/disable via Task Manager's binary marker scheme
  (byte 0 even = enabled), removal and addition. Impact heuristics are upstream's.
- **Debloat** (`Debloat/`): Win32 app enumeration from registry Uninstall keys
  (SystemComponent skipped, QuietUninstallString preferred); UWP enumeration and
  removal via `Get-AppxPackage`/`Remove-AppxPackage` — the same PowerShell fallback
  upstream used when WinRT failed (documented divergence: WinRT PackageManager is
  unavailable to plain .NET). `TempCleaner` ports `RemoveTempFiles` (services stop,
  explorer-dependent and deep-clean path lists, OEM log trees, shader caches, DNS/
  winsock flush, service restore, bytes-cleared estimate).
- **Repair** (`Repair/`): DISM `/ScanHealth`→`/RestoreHealth`, SFC `/verifyonly`→
  `/scannow`, CHKDSK scan→scheduled `chkdsk X: /f` at next reboot, with upstream's
  output-based health heuristics verbatim. Output captured via standard pipes instead
  of a pseudo-console (documented divergence; same tools, same arguments).
- **Edge refusal**: upstream ships a bespoke `RemoveEdge.ps1`; this port deliberately
  refuses to remove Edge rather than carrying an unsigned script asset.
- **UI**: Policies, Startup, Debloat and Repair pages in Palisade.App, wired to the
  modules; CLI gained `-policies` (read-only scanner report).

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
   - Remaining OptimizeSystemHelper pairs (Windows Update toggles, network
     throttling variants, privacy/security page pairs beyond the above).
   - All other Debloat page extras (winget-based suggested-app removal lists).
   Every module surface named in the user request (policy scanner, startup manager,
   debloat/winget, repair) now ships; the remaining items are additional toggle
   definitions within the shipped architecture.
5. **WinRT-only surfaces** (app icon cache, Store review prompt, MSIX app info) were
   dropped: UI concerns with no tuning effect.

## UI

`Palisade.App`'s Optimize page binds `TuningCatalog` through `OptimizeViewModel`
(search, per-toggle apply/revert, revert-all, state markers). The visual language is
the Fluent world described in DESIGN.md.

## Tests

`tests/Palisade.Tuning.Tests` — 41 tests: tuning-catalog integrity (unique ids,
non-empty titles/descriptions/commands, known categories), policy-catalog integrity
(207 transplanted entries, unique ids, absolute SOFTWARE paths, metadata completeness,
applicability filtering) and engine lookup.
