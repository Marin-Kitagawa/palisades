# Palisade Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `Palisade.Core` — the complete, headless-testable hardening engine: 26 measures as data across six mechanisms, byte-compatible saved-state persistence, deterministic restore ordering, and a four-state detection model.

**Architecture:** `Palisade.Core` has no Avalonia reference and contains every security-critical operation. All registry access is abstracted behind `IRegistryKeyFactory` so the entire engine is testable against an in-memory hive; **no test writes to the real registry.** Registry state is persisted in the upstream Go format under `HKCU\SOFTWARE\Security Without Borders\` so a machine hardened by either tool can be restored by the other. Restore order is computed from an explicit constraint graph rather than enumeration order.

**Tech Stack:** C# / .NET 10 (`net10.0-windows`), `Microsoft.Win32.Registry` (in-box), xunit 2.9.3, Microsoft.NET.Test.Sdk 17.14.1, coverlet.collector 6.0.4. No MV toolkit, no DI container, no third-party registry library.

**Spec:** `docs/superpowers/specs/2026-09-26-palisade-design.md`

## Global Constraints

- Target framework is exactly `net10.0-windows`. Nullable reference types enabled. Implicit usings enabled.
- `Palisade.Core` must contain **no reference to Avalonia** and none to `Palisade.App` or `Palisade.Cli`.
- License is GPLv3. Copy `LICENSE.txt` verbatim from `C:\Users\Ahri\Projects\hardentools\LICENSE.txt`. Every `.cs` file starts with the GPL header used upstream, retaining `Copyright (C) 2017-2023 Security Without Borders`.
- `Palisade.Core` targets `net10.0-windows` because it calls `Microsoft.Win32.Registry` directly. `net10.0-windows` without `UseWindowsForms`/`UseWPF` keeps it a plain library with no UI framework.
- Saved-state value names use the **four-underscore** separator (`____`) for all four current prefixes. The legacy `SavedState_` prefix uses a **single** underscore and is read-only.
- Root key name tokens are exactly `CLASSES_ROOT`, `CURRENT_USER`, `LOCAL_MACHINE`, `USERS`, `CURRENT_CONFIG`, `PERFORMANCE_DATA`. No others are accepted.
- The saved-state key path is exactly `SOFTWARE\Security Without Borders\`.
- Measure count is exactly 26: 12 available without elevation, 14 requiring it.
- Exactly 8 measures are `HardenByDefault == false`: `Cmd`, `Lsa`, `LibreOfficeMacroSecurity`, `LibreOfficeCtrlClickHyperlinks`, `LibreOfficeUntrustedRefererLinks`, `LibreOfficeEnforceUpdateChecks`, `LibreOfficeDisableUpdateLinks`, `Recall`.
- **A descriptor's registry payload lives in its typed `Targets` list, not in `Settings`.** `Settings` is reserved for the non-registry-family parameters (path templates, version lists, app lists). One `Settings["HardenedValue"]` per descriptor cannot express the 10 measures that write more than one registry value, and the `26/12/14/8` count tests cannot see the difference — see the Task 2 escalation note below.
- **`Recall`'s `MeasureId.Value` is the lowercase string `recall`**, not `Recall`. `recall_feature.go:50` sets `featureName = "recall"`, so the Go tool persists `SavedStateNonReg_recall` and a capital-R id would silently fail to find it. The Windows optional feature name is separately `Recall` (the PowerShell cmdlet argument, `recall_feature.go:67`); the id and the feature name are different things and must not be conflated.
- **Windows ASR rules are `NonRegistry` with id `WindowsAsrRules`.** ASR has no `saveHardenState` call site (`windows_asr.go:102` is a TODO), so its id is unconstrained upstream. Spec §6.2 line 182 says `RegistryString`, contradicting spec §6.1 line 136 and the Go source; line 182 is the error.
- No test in this project may open a real registry key. The in-memory hive is the only hive tests touch; this is enforced by the `IRegistry` abstraction, not by convention.
- C# style follows the user's existing projects: file-scoped namespaces, primary constructors where they read better, `var` for obvious locals, no XML doc comments on private members.

## Review Focus

Five input classes the spec implies but no task's happy-path tests exercise. Each gets its test in the task that owns the code, named in that task's steps.

1. **A saved-state value name containing a backslash in the value name** — a value literally named `a\b` is legal in the registry. Splitting on the first `\` pair is wrong; the key path may itself contain `\` and the separator is `____`, so splitting on `____` after the root token is the only correct parse.
2. **A legacy `SavedState_` name whose key path contains underscores** — `_` is both the legacy separator and a legal key-path character, so the legacy split is genuinely ambiguous. It must be resolved against the known root token and validated, and an unresolvable name skipped, never guessed.
3. **A measure applied by something else** — Group Policy, a corporate image, or another tool already set the value. `Detect` must return `Stressed`, never `Slack`, and `Apply` must not silently discard the pre-existing value.
4. **A `SavedStateNotExisting_` entry whose target value has since been created** — restore must delete it (that is what was recorded) rather than leave it, and must report that it deleted a value the user had since created.
5. **A DisallowRun subkey where another program added a different entry** — restore must remove only Palisade's entries and leave the other program's, renumbering the survivors, and must not delete the subkey if entries remain. (Amended: DisallowRun is **not** a `REG_MULTI_SZ` — see DisallowRunHandler in Task 6.)
6. **A restore whose target key no longer exists** — harden may create a key, but restore must not. Go distinguishes `CreateKey` (harden) from `OpenKey` (restore, which fails when the key is absent); a Palisade restore that created the key would leave behind state the Go tool would never create. **Restore must probe read-only first and stop without writing if the key is absent.**

---

## File Structure

| File | Responsibility |
|---|---|
| `src/Palisade.Core/Palisade.Core.csproj` | Project file, no Avalonia |
| `src/Palisade.Core/Models/MeasureState.cs` | The four-state enum |
| `src/Palisade.Core/Models/MeasureGroup.cs` | Six measure groups |
| `src/Palisade.Core/Models/Mechanism.cs` | The six mechanisms |
| `src/Palisade.Core/Models/RegistryRoot.cs` | Six root tokens + name↔token mapping |
| `src/Palisade.Core/Models/MeasureDescriptor.cs` | The descriptor record, `MeasureTarget`, `AvailabilityRule`, `MeasureConstraint` |
| `src/Palisade.Core/Models/MeasureCatalog.cs` | The 26 descriptors as data + lookup by id/group |
| `src/Palisade.Core/Registry/IRegistry.cs` | `IRegistry`, `IRegistryKey` — the abstraction every mechanism codes against |
| `src/Palisade.Core/Registry/RegistryKeyNames.cs` | Parse/format the four current prefixes and the legacy prefix |
| `src/Palisade.Core/Registry/SavedStateStore.cs` | Read and write saved state |
| `src/Palisade.Core/Registry/RegistryAccess.cs` | The only file in the project that touches `Microsoft.Win32.Registry` |
| `src/Palisade.Core/Registry/RegistryOptions.cs` | `RegistryOptions` (saved-state path) + `IAppPaths` |
| `src/Palisade.Core/Mechanisms/IMechanismHandler.cs` | Handler contract |
| `src/Palisade.Core/Mechanisms/RegistryDwordHandler.cs` | `RegistryDword`, `MultiRegistryDword` |
| `src/Palisade.Core/Mechanisms/RegistryStringHandler.cs` | `RegistryString` |
| `src/Palisade.Core/Mechanisms/VersionedPathHandler.cs` | `VersionedPath` + version discovery |
| `src/Palisade.Core/Mechanisms/DisallowRunHandler.cs` | `DisallowRun` |
| `src/Palisade.Core/Mechanisms/FileAssociationHandler.cs` | `FileAssociation` |
| `src/Palisade.Core/Mechanisms/NonRegistryHandler.cs` | `NonRegistry` dispatch to an `INonRegistryMeasure` |
| `src/Palisade.Core/Mechanisms/AsrRulesMeasure.cs` | ASR measure: rule set, Windows Defender detection |
| `src/Palisade.Core/Mechanisms/RecallMeasure.cs` | Recall measure: feature presence, `SavedStateNonReg_` |
| `src/Palisade.Core/Mechanisms/MEASURE_APPLICATIONS.md` | Versioned-path templates + root keys, read from here by the handler |
| `src/Palisade.Core/Engine/MeasureDetector.cs` | Four-state derivation |
| `src/Palisade.Core/Engine/RestorePlanner.cs` | Reverse-dependency ordering |
| `src/Palisade.Core/Engine/ApplyEngine.cs` | Orchestrates apply/restore across measures |
| `src/Palisade.Core/Engine/ApplyReport.cs` | Per-measure outcome records |
| `src/Palisade.Core/PalisadeEngine.cs` | Public facade |
| `tests/Palisade.Core.Tests/TestRegistry.cs` | In-memory hive + `IRegistry` fake |
| `tests/Palisade.Core.Tests/…` | One test file per area, mirroring `src/` |

Tests mirror the source layout so a reviewer can find the test for a file without a map.

---

## Task 1: Solution and project skeleton

**Files:**
- Create: `Palisade.slnx`, `src/Palisade.Core/Palisade.Core.csproj`, `tests/Palisade.Core.Tests/Palisade.Core.Tests.csproj`, `LICENSE.txt`, `README.md`

**Interfaces:**
- Produces: `Palisade.Core` class library and `Palisade.Core.Tests` test project, both building green on `net10.0-windows`. Every later task adds files to these two projects.

- [ ] **Step 1: Create the solution and projects**

```bash
cd "C:/Users/Ahri/Documents/Default Project/Palisade"
dotnet new sln -n Palisade --format slnx
dotnet new classlib -n Palisade.Core -o src/Palisade.Core -f net10.0
dotnet new xunit -n Palisade.Core.Tests -o tests/Palisade.Core.Tests -f net10.0
dotnet sln Palisade.slnx add src/Palisade.Core/Palisade.Core.csproj tests/Palisade.Core.Tests/Palisade.Core.Tests.csproj
dotnet add tests/Palisade.Core.Tests/Palisade.Core.Tests.csproj reference src/Palisade.Core/Palisade.Core.csproj
```

- [ ] **Step 2: Edit both `.csproj` files**

`src/Palisade.Core/Palisade.Core.csproj` — set `<TargetFramework>net10.0-windows</TargetFramework>`, keep `Nullable` and `ImplicitUsings` enabled, delete the generated `Class1.cs`.

`tests/Palisade.Core.Tests/Palisade.Core.Tests.csproj` — set `<TargetFramework>net10.0-windows</TargetFramework>`, and set package versions to exactly:

```xml
<PackageReference Include="coverlet.collector" Version="6.0.4" />
<PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.14.1" />
<PackageReference Include="xunit" Version="2.9.3" />
<PackageReference Include="xunit.runner.visualstudio" Version="3.1.4" />
```

Add `<ItemGroup><Using Include="Xunit" /></ItemGroup>` if the template did not.

- [ ] **Step 3: Copy the license and write attribution into the README**

```bash
Copy-Item "C:/Users/Ahri/Projects/hardentools/LICENSE.txt" ./LICENSE.txt
```

`README.md` must state, in the first paragraph: that Palisade is a C# port of `hardentools` by Claudio Guarnieri, Mariano Graziano, and Florian Probst of Security Without Borders; that it is GPLv3; and that it is **not an antivirus**.

- [ ] **Step 4: Verify the build**

Run: `dotnet build Palisade.slnx`
Expected: build succeeded, two projects, zero warnings.

Run: `dotnet test`
Expected: one passing test (the template's). Confirms the test host works on `net10.0-windows`.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "chore: scaffold Palisade.Core and test project"
```

---

## Task 2: The measure model

**Files:**
- Create: `src/Palisade.Core/Models/MeasureState.cs`, `MeasureGroup.cs`, `Mechanism.cs`, `RegistryRoot.cs`, `MeasureDescriptor.cs`, `MeasureCatalog.cs`
- Test: `tests/Palisade.Core.Tests/Models/MeasureCatalogTests.cs`

**Interfaces:**
- Produces, consumed by every later task:
  - `public enum MeasureState { Slack, Taut, Stressed, Unavailable }`
  - `public enum MeasureGroup { Windows, MicrosoftOffice, Adobe, LibreOffice, OneNote, System }`
  - `public enum Mechanism { RegistryDword, RegistryString, VersionedPath, DisallowRun, FileAssociation, NonRegistry }`
  - `public enum RegistryRoot { ClassesRoot, CurrentUser, LocalMachine, Users, CurrentConfig, PerformanceData }`
  - `public static class RootKeyNames { public static string ToToken(RegistryRoot root); public static bool TryParse(string token, out RegistryRoot root); }` — `ToToken` returns the six exact tokens in Global Constraints; `TryParse` returns `false` for any other string.
  - `public sealed record AvailabilityRule(string Kind, IReadOnlyDictionary<string, string> Arguments, string Reason);`
  - `public sealed record MeasureConstraint(MeasureId Target, string Reason);`
  - `public sealed record MeasureTarget(RegistryRoot Root, string Path, string ValueName, string Kind, string HardenedValue, string? AppFilter = null, string? VersionFilter = null);` — one registry value a measure writes. `Kind` is exactly one of `"Dword"`, `"String"`, `"MultiString"`, and drives the actual read/write, so a measure that writes both an `REG_SZ` and an `REG_DWORD` needs no bespoke encoding. `HardenedValue` is the string form of the hardened value; for `"Dword"` it is the decimal digits, and it **may be empty** — `SecureURL\Value` hardens to `""` (`libreoffice.go:48`). `Path` may contain `%s`, the placeholder for the product version.
  - `AppFilter` and `VersionFilter` are per-target allowlists (comma-separated; `null` means no narrowing, i.e. every discovered product). They exist because upstream scopes individual sub-values to specific products: `office.go` writes `AllowDDE` for **Word only, versions 14–16**, and `WorkbookLinkWarnings` for **Excel only, 12–16**. With narrowing only on the descriptor, Task 6 would apply the union of all version and app lists to every sub-value and write **32 registry values where upstream writes 17** - setting DDE keys on 15 products the Go tool deliberately leaves alone. Verified: expanding the catalog DDE targets with these filters yields exactly **17**, matching `office.go`. A `null` filter reproduces the un-narrowed majority; a non-null filter reproduces the exception.
  - `public sealed record MeasureDescriptor(MeasureId Id, string Name, string LongName, string Consequence, Mechanism Mechanism, bool RequiresElevation, bool HardenByDefault, MeasureGroup Group, IReadOnlyDictionary<string, string> Settings, IReadOnlyList<MeasureTarget> Targets, IReadOnlyList<MeasureConstraint> ConstrainedBy, IReadOnlyList<AvailabilityRule> Availability);`

  **`Targets` is the registry payload** and is what makes a descriptor self-contained data rather than a type per measure. It is non-empty for `RegistryDword`, `RegistryString` and `VersionedPath` measures, and empty for `DisallowRun`, `FileAssociation` and `NonRegistry`. `Mechanism` stays the descriptor's classification (used for restore ordering, UI grouping, and the validation test below); `Target.Kind` is what a handler actually dispatches on, which is why a `RegistryString` measure may legitimately carry one `"Dword"` target — LibreOffice writes `REG_SZ "Value"` and `REG_DWORD "Final"` at the same policy path (`libreoffice.go:39` and `libreoffice.go:57`). **`"MultiString"` is carried by no measure, and no MultiString write exists anywhere in the Go tree** — it is a legitimate `REG_MULTI_SZ` kind that the in-memory fake models for completeness, not a requirement of any handler. Do not read its presence in that enumeration as licence to reimplement DisallowRun as a multi-string list: DisallowRun is numbered `REG_SZ` values in a subkey (`cmd.go:170-177`).

  **`Settings` holds only the version and app lists used for expansion.** Reserved keys, all string-typed: `"OfficeVersions"`, `"AdobeVersions"`, `"Apps"` (comma-separated). These are the *universe* of products to discover; a target's `AppFilter`/`VersionFilter` narrows it. The previously listed `"PathTemplate"` key is **removed** — a template belongs on the target that uses it, so DDE's per-sub-value `%s` paths and the versioned-path measures share one expansion path instead of two. The previously listed `"HardenedValue"`, `"MultiValueName"` and bare `"ValueName"` keys are likewise **removed**; that payload lives in `Targets`, and keeping two spellings of the same fact is how they drift apart.
  - `public readonly record struct MeasureId(string Value);` with `public override string ToString() => Value;` and `public static implicit operator string(MeasureId id) => id.Value;` — the implicit operator exists so the saved-state feature names read cleanly, e.g. `saveHardenState(MeasureId.From("recall"), "disabled")`.
  - `public static class MeasureCatalog { public static IReadOnlyList<MeasureDescriptor> All { get; } public static MeasureDescriptor Get(MeasureId id); public static IReadOnlyList<MeasureDescriptor> InGroup(MeasureGroup group); }`

**Note on `MeasureId`:** it wraps a string rather than an enum so that `SavedStateNonReg_` feature names stay byte-identical to the Go tool's. The `Value` strings for non-registry measures are exactly `recall` (lowercase, matching `recall_feature.go:50`) and `WindowsAsrRules`.

**Why `Targets` exists (Task 2 escalation, resolved):** the first Task 2 implementer stopped with `NEEDS_CONTEXT` rather than guess. Verified against the Go source: `show_file_extensions.go:28-43`, `autorun.go:34-49`, `uac.go:28-47` and `defender_pua.go:45-65` each write three distinct registry values, and `office.go`'s DDE measure writes five sub-values across four path templates. A single `Settings["HardenedValue"]` has no room for the second and third, and the `26/12/14/8` count tests pass with that payload silently absent — which would have shipped into Tasks 6–9 as a port that hardens one of three values and reports success. Option A (an encoded sub-value list inside a string key) was rejected because it must survive `\` and `%s` inside path templates and an empty-string hardened value; Option C (composite tables kept in handlers) was rejected because the plan already does that for the file-association table and extending it makes the catalog stop being self-contained.

- [ ] **Step 1: Write the failing catalog tests**

```csharp
using Palisade.Core.Models;

namespace Palisade.Core.Tests.Models;

public class MeasureCatalogTests
{
    [Fact]
    public void Catalog_contains_exactly_26_measures() =>
        Assert.Equal(26, MeasureCatalog.All.Count);

    [Fact]
    public void Catalog_contains_exactly_12_measures_not_requiring_elevation() =>
        Assert.Equal(12, MeasureCatalog.All.Count(m => !m.RequiresElevation));

    [Fact]
    public void Catalog_contains_exactly_14_measures_requiring_elevation() =>
        Assert.Equal(14, MeasureCatalog.All.Count(m => m.RequiresElevation));

    [Fact]
    public void Catalog_contains_exactly_8_measures_not_hardened_by_default() =>
        Assert.Equal(8, MeasureCatalog.All.Count(m => !m.HardenByDefault));

    [Theory]
    [InlineData("Cmd")]
    [InlineData("Lsa")]
    [InlineData("LibreOfficeMacroSecurity")]
    [InlineData("LibreOfficeCtrlClickHyperlinks")]
    [InlineData("LibreOfficeUntrustedRefererLinks")]
    [InlineData("LibreOfficeEnforceUpdateChecks")]
    [InlineData("LibreOfficeDisableUpdateLinks")]
    [InlineData("recall")]
    public void Catalog_marks_the_eight_opt_in_measures_as_not_default(string id)
    {
        var descriptor = MeasureCatalog.Get(new MeasureId(id));
        Assert.False(descriptor.HardenByDefault);
    }

    [Fact]
    public void Every_registry_family_measure_has_at_least_one_target() =>
        Assert.All(
            MeasureCatalog.All.Where(m => m.Mechanism is Mechanism.RegistryDword
                or Mechanism.RegistryString
                or Mechanism.VersionedPath),
            m => Assert.NotEmpty(m.Targets));

    [Fact]
    public void Every_non_registry_family_measure_has_no_targets() =>
        Assert.All(
            MeasureCatalog.All.Where(m => m.Mechanism is Mechanism.DisallowRun
                or Mechanism.FileAssociation
                or Mechanism.NonRegistry),
            m => Assert.Empty(m.Targets));

    [Fact]
    public void Every_target_kind_is_a_known_kind() =>
        Assert.All(
            MeasureCatalog.All.SelectMany(m => m.Targets),
            t => Assert.Contains(t.Kind, new[] { "Dword", "String", "MultiString" }));

    [Fact]
    public void Every_target_has_a_root_a_path_a_value_name_and_a_hardened_value()
    {
        Assert.All(MeasureCatalog.All.SelectMany(m => m.Targets), t =>
        {
            Assert.False(string.IsNullOrWhiteSpace(t.Path));
            Assert.False(string.IsNullOrWhiteSpace(t.ValueName));
            // HardenedValue may legitimately be empty: `SecureURL\Value` hardens to the empty
            // string (libreoffice.go:48). Assert non-null, not non-blank.
            Assert.NotNull(t.HardenedValue);
        });
    }

    [Fact]
    public void LibreOffice_SecureURL_hardens_to_the_empty_string()
    {
        // libreoffice.go:44-51 hardens `SecureURL\Value` to "". Any validation that rejects a
        // blank hardened value silently drops this target, and any string-encoding of the
        // payload cannot distinguish it from a missing one. This is the concrete case that
        // ruled out encoding targets inside a settings string.
        var macro = MeasureCatalog.All.Single(m => m.Group == MeasureGroup.LibreOffice
            && m.Targets.Any(t => t.Path.Contains("MacroSecurityLevel", StringComparison.Ordinal)));
        // Two targets sit under the SecureURL path (SZ "Value" and DWORD "Final"), so filter
        // on the value name rather than asserting the path is unique.
        var secureUrl = Assert.Single(macro.Targets.Where(t =>
            t.Path.Contains("SecureURL", StringComparison.Ordinal) && t.ValueName == "Value"));
        Assert.Equal("String", secureUrl.Kind);
        Assert.Equal(string.Empty, secureUrl.HardenedValue);
        Assert.Equal("0", Assert.Single(macro.Targets.Where(t =>
            t.Path.Contains("SecureURL", StringComparison.Ordinal) && t.ValueName == "Final")).HardenedValue);
    }

    [Fact]
    public void The_four_multi_value_measures_each_keep_all_three_registry_values()
    {
        // Show file extensions, Autorun, UAC and PUA are `RegistryMultiValue` in Go
        // (show_file_extensions.go, autorun.go, uac.go, defender_pua.go) and each write three
        // distinct values. Asserted by count and group rather than by id, so this test does
        // not depend on the catalog's id spelling staying fixed.
        var three = MeasureCatalog.All.Where(m => m.Targets.Count == 3).ToList();
        Assert.Equal(4, three.Count);
        Assert.All(three, m => Assert.True(
            m.Group is MeasureGroup.Windows or MeasureGroup.System,
            $"expected a Windows or System measure, got {m.Group}"));
    }

    [Fact]
    public void All_five_LibreOffice_measures_pair_a_string_value_with_a_final_dword()
    {
        // Each LibreOffice sub-measure writes REG_SZ "Value" and REG_DWORD "Final" at the same
        // policy path, so no single `Mechanism` value describes them — this is the case that
        // forced the typed `Targets` list.
        var libre = MeasureCatalog.All.Where(m => m.Group == MeasureGroup.LibreOffice).ToList();
        Assert.Equal(5, libre.Count);
        Assert.All(libre, m =>
        {
            Assert.Contains(m.Targets, t => t.ValueName == "Value" && t.Kind == "String");
            Assert.Contains(m.Targets, t => t.ValueName == "Final" && t.Kind == "Dword");
        });
    }

    [Fact]
    public void The_three_composite_LibreOffice_measures_keep_both_of_their_sub_measures()
    {
        // Three of the five LibreOffice measures are themselves `RegistryMultiValue` bundles of
        // two sub-measures, so they carry four targets, not two:
        //   MacroSecurityLevel + SecureURL          (libreoffice.go:34-70)
        //   AutoCheckEnabled + CheckInterval        (libreoffice.go:164-200)
        //   Calc\Content\Update\Link + Writer\...   (libreoffice.go:216-252)
        // The other two (HyperlinksWithCtrlClick, BlockUntrustedRefererLinks) are single
        // sub-measures with two targets each. An earlier version of this test asserted a flat
        // 2 for all five, which silently dropped SecureURL, CheckInterval and the Writer link —
        // 6 registry values across 3 measures that Palisade would never harden or restore.
        var libre = MeasureCatalog.All.Where(m => m.Group == MeasureGroup.LibreOffice).ToList();
        var four = libre.Where(m => m.Targets.Count == 4).ToList();
        var two = libre.Where(m => m.Targets.Count == 2).ToList();
        Assert.Equal(3, four.Count);
        Assert.Equal(2, two.Count);
        Assert.Equal(5, four.Count + two.Count);

        // The dropped payloads, named so their return is unambiguous.
        Assert.All(four, m => Assert.Equal(2, m.Targets.Select(t => t.Path).Distinct().Count()));
        Assert.Contains(four.SelectMany(m => m.Targets), t => t.Path.Contains("SecureURL", StringComparison.Ordinal));
        Assert.Contains(four.SelectMany(m => m.Targets), t => t.Path.Contains("CheckInterval", StringComparison.Ordinal));
        Assert.Contains(four.SelectMany(m => m.Targets), t => t.Path.Contains("Writer", StringComparison.Ordinal));
    }

    [Fact]
    public void Narrowed_targets_declare_their_app_and_version_scope()
    {
        // Guards against the widening failure: if every DDE sub-value inherited the
        // descriptor's full version and app lists, Task 6 would write 32 registry values
        // where the Go tool writes 17, setting DDE keys on products upstream leaves alone.
        var narrowed = MeasureCatalog.All.SelectMany(m => m.Targets)
            .Where(t => t.AppFilter is not null || t.VersionFilter is not null).ToList();
        Assert.NotEmpty(narrowed);
        Assert.All(narrowed, t =>
        {
            Assert.NotNull(t.Path);
            Assert.False(string.IsNullOrWhiteSpace(t.AppFilter ?? t.VersionFilter));
        });
    }

    [Fact]
    public void Only_the_DDE_measure_narrows_its_targets()
    {
        // Versioned-path and LibreOffice measures apply to every discovered product upstream,
        // so a filter on them would itself be a divergence. Assert the id, not just the count:
        // `Assert.Single` on the list would pass for a filter that had migrated to another
        // single measure.
        var narrowing = MeasureCatalog.All
            .Where(m => m.Targets.Any(t => t.AppFilter is not null || t.VersionFilter is not null))
            .Select(m => m.Id.Value).ToList();
        Assert.Equal(["OfficeDde"], narrowing);
    }

    [Fact]
    public void DDE_narrowing_pins_the_exact_filter_values_upstream_uses()
    {
        // The filter values are the entire point of the narrowing, and nothing else in the
        // suite observes them: editing the version list from 14/15/16 to 14/15 would drop DDE
        // hardening from 17 registry writes to 11 with every other test still green. Values
        // taken from office.go:154-292.
        var dde = MeasureCatalog.All.Single(m => m.Id.Value == "OfficeDde");

        var allowDde = Assert.Single(dde.Targets.Where(t => t.Path.Contains("AllowDDE", StringComparison.Ordinal)));
        Assert.Equal("Word", allowDde.AppFilter);
        Assert.Equal("14.0,15.0,16.0", allowDde.VersionFilter);

        var workbook = Assert.Single(dde.Targets.Where(t => t.Path.Contains("WorkbookLinkWarnings", StringComparison.Ordinal)));
        Assert.Equal("Excel", workbook.AppFilter);
        Assert.Null(workbook.VersionFilter); // upstream uses the full standard list

        // `DontUpdateLinks` appears twice: once scoped to Word+Excel, once Word-only (Outlook).
        var dontUpdate = dde.Targets.Where(t => t.Path.Contains("DontUpdateLinks", StringComparison.Ordinal)).ToList();
        Assert.Equal(2, dontUpdate.Count);
        Assert.Contains(dontUpdate, t => t.AppFilter == "Word,Excel");
        Assert.All(dontUpdate, t => Assert.Equal("14.0,15.0,16.0", t.VersionFilter));

        // The one fixed DDE path is not versioned, so it is not narrowed either.
        var fixedPath = Assert.Single(dde.Targets.Where(t => t.Path.Contains("Calclinks", StringComparison.OrdinalIgnoreCase)));
        Assert.Null(fixedPath.AppFilter);
        Assert.Null(fixedPath.VersionFilter);
        Assert.DoesNotContain("%s", fixedPath.Path);
    }

    [Fact]
    public void Every_filter_value_is_a_member_of_the_measures_product_universe()
    {
        // A typo in a filter would silently match nothing and quietly un-harden a product.
        Assert.All(MeasureCatalog.All, m =>
        {
            var apps = (m.Settings.GetValueOrDefault("Apps") ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var versions = (m.Settings.GetValueOrDefault("OfficeVersions") ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            Assert.All(m.Targets.Where(t => t.AppFilter is not null),
                t => Assert.All(t.AppFilter!.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries), a => Assert.Contains(a, apps)));
            Assert.All(m.Targets.Where(t => t.VersionFilter is not null),
                t => Assert.All(t.VersionFilter!.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries), v => Assert.Contains(v, versions)));
        });
    }

    [Fact]
    public void Exactly_one_target_hardens_to_the_empty_string()
    {
        // `SecureURL\Value` is the only legitimately empty hardened value (libreoffice.go:48).
        // Pinning the count means a second blank cannot slip in unnoticed now that the
        // non-blank assertion is gone.
        Assert.Equal(1, MeasureCatalog.All.SelectMany(m => m.Targets).Count(t => t.HardenedValue.Length == 0));
    }

    [Fact]
    public void Every_measure_has_at_least_one_availability_rule() =>
        Assert.All(MeasureCatalog.All, m => Assert.NotEmpty(m.Availability));

    [Fact]
    public void Every_measure_has_a_non_empty_consequence_sentence() =>
        Assert.All(MeasureCatalog.All, m => Assert.False(string.IsNullOrWhiteSpace(m.Consequence)));

    [Fact]
    public void Every_measure_has_a_non_empty_availability_reason() =>
        Assert.All(MeasureCatalog.All, m => Assert.All(m.Availability, r => Assert.False(string.IsNullOrWhiteSpace(r.Reason))));

    [Fact]
    public void Measure_ids_are_unique()
    {
        var ids = MeasureCatalog.All.Select(m => m.Id.Value).ToList();
        Assert.Equal(ids.Count, ids.Distinct().Count());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `dotnet test --filter "FullyQualifiedName~MeasureCatalogTests"`
Expected: build failure — `MeasureCatalog` does not exist.

- [ ] **Step 3: Implement the enums, records, and `RootKeyNames`**

One file per type, matching the File Structure table. `ToToken`/`TryParse` cover exactly the six tokens; `TryParse` is `false` for everything else, including the empty string. `MeasureTarget` lives in `MeasureDescriptor.cs` alongside the descriptor that owns it.

- [ ] **Step 4: Implement the 26 descriptors in `MeasureCatalog.cs`**

Each descriptor is one static `readonly` field. Populate `Targets` from the Go source — **this is the step the plan originally got wrong, so read the Go file for every measure rather than assuming one value.** The four `RegistryMultiValue` measures (`show_file_extensions.go`, `autorun.go`, `uac.go`, `defender_pua.go`) get three targets each. The five LibreOffice measures get **two or four** targets each, not a flat two: `HyperlinksWithCtrlClick` and `BlockUntrustedRefererLinks` are single sub-measures (2 each), while `MacroSecurity` (`MacroSecurityLevel` + `SecureURL`, `libreoffice.go:34-70`), `EnforceUpdateChecks` (`AutoCheckEnabled` + `CheckInterval`, `:164-200`) and `DisableUpdateLinks` (`Calc\Content\Update\Link` + `Writer\Content\Update\Link`, `:216-252`) are bundles of two sub-measures and get 4 each. Every LibreOffice sub-measure pairs an `REG_SZ "Value"` with an `REG_DWORD "Final"`, and `SecureURL\Value` hardens to the **empty string** (`:48`) — a blank `HardenedValue` is legitimate, not a missing one. `office.go`'s DDE measure gets a target per sub-value, and the narrow ones carry `AppFilter`/`VersionFilter` — `AllowDDE` is Word-only on 14–16, `WorkbookLinkWarnings` Excel-only on 12–16. `Kind` is `"Dword"`, `"String"` or `"MultiString"` and drives the write. `Settings` carries only `"OfficeVersions"`, `"AdobeVersions"` and `"Apps"`. `DisallowRun`, `FileAssociation` and `NonRegistry` measures have an empty `Targets` list.

Each descriptor is one static `readonly` field. The `Consequence` string is the display-size sentence naming what breaks in the user's own applications — for example `Cmd`'s is "You will not be able to open the Windows command prompt (cmd.exe) any more.", and `OfficeMacros`' is "Macros will not run in Excel, PowerPoint, or Word. Documents that rely on macros will not work."

Every measure carries at least one `AvailabilityRule`. Two are shared constants in the catalog: `"product_not_installed"` and `"product_not_installed"` is not enough for the measures with real runtime conditions — ASR carries `"windows_defender_disabled"`, `OfficeDDE` carries `"dde_not_supported"`. `Reason` on every rule is a full sentence, because the UI renders it verbatim.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `dotnet test --filter "FullyQualifiedName~MeasureCatalogTests"`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: measure model and 26-measure catalog"
```

---

## Task 3: The registry abstraction and the in-memory hive

**Files:**
- Create: `src/Palisade.Core/Registry/IRegistry.cs`, `RegistryOptions.cs`
- Test: `tests/Palisade.Core.Tests/TestRegistry.cs`

**Interfaces:**
- Produces:
  - `public enum RegistryValueKind { Dword, String, MultiString, Binary, None }`
  - `public interface IRegistryKey : IDisposable { RegistryValueKind GetValueKind(string name); bool TryGetDword(string name, out uint value); bool TryGetString(string name, out string value); bool TryGetMultiString(string name, out string[] value); void SetDword(string name, uint value); void SetString(string name, string value); void SetMultiString(string name, IReadOnlyList<string> value); void DeleteValue(string name); IReadOnlyList<string> GetValueNames(); }`
  - `public interface IRegistry { IRegistryKey OpenKey(RegistryRoot root, string subKey, bool writable); bool DeleteKey(RegistryRoot root, string subKey); }` — `OpenKey` **returns `null`** when the key does not exist, and every caller must handle it. This is the single most important convention in the abstraction: "key absent" is normal state, not an error. `DeleteKey` returns `false` when the key was already absent. **`OpenKey(..., writable: true)` creates the key on demand, so it conflates Go's `CreateKey` (harden) with `OpenKey` (restore); the caller owns the distinction** — see Global Constraint 6. `DeleteKey` is required by three upstream call sites: the DisallowRun subkey is deleted when its last entry is removed (`cmd.go:136`, `powershell.go:140`), and the whole saved-state key is deleted on restore (`utils.go:159`). It deletes a **subtree** via `DeleteSubKeyTree` semantics, deliberately diverging from Go's plain `RegDeleteKey` — see Task 3 Step 4 for why, and do not "fix" the fake to match `RegDeleteKey`.
  - `public interface IRegistryKeyFactory { IRegistryKey OpenKey(RegistryRoot root, string subKey, bool writable); bool DeleteKey(RegistryRoot root, string subKey); }`
  - `public sealed record RegistryOptions(string SavedStateKeyPath) { public const string DefaultSavedStateKeyPath = @"SOFTWARE\Security Without Borders\"; public static RegistryOptions Default { get; } = new(DefaultSavedStateKeyPath); }`
  - `public interface IAppPaths { string LogDirectory { get; } }`
  - `public sealed class AppPaths : IAppPaths { public AppPaths(string logDirectory); public string LogDirectory { get; } }`
- Consumes: `RegistryRoot` from Task 2.

**Why `IRegistryKeyFactory` on top of `IRegistry`:** `IRegistry` is the injected abstraction. `IRegistryKeyFactory` exists so `RegistryAccess` and the in-memory fake are interchangeable behind one constructor parameter, without every mechanism taking two dependencies.

- [ ] **Step 1: Write the in-memory hive and its tests**

`TestRegistry.cs` provides `InMemoryRegistry : IRegistry, IRegistryKeyFactory` and `InMemoryRegistryKey : IRegistryKey`, backed by `Dictionary<string, (RegistryValueKind Kind, object Value)>` per key path. `OpenKey` returns `null` for an absent path and creates the entry on first write when `writable` is `true`. A key is a path string, so parent keys need no separate creation.

Tests live in `tests/Palisade.Core.Tests/TestRegistryTests.cs`:

```csharp
[Fact]
public void OpenKey_returns_null_for_an_absent_key()
{
    IRegistry registry = new InMemoryRegistry();
    Assert.Null(registry.OpenKey(RegistryRoot.CurrentUser, @"Software\Nope", writable: false));
}

[Fact]
public void Dword_round_trips()
{
    var registry = new InMemoryRegistry();
    using var key = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!;
    key.SetDword("V", 42);
    Assert.True(key.TryGetDword("V", out var value));
    Assert.Equal(42u, value);
}

[Fact]
public void DeleteValue_removes_the_value()
{
    var registry = new InMemoryRegistry();
    using var key = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!;
    key.SetString("V", "x");
    key.DeleteValue("V");
    Assert.False(key.TryGetString("V", out _));
}

[Fact]
public void GetValueNames_excludes_deleted_values()
{
    var registry = new InMemoryRegistry();
    using var key = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!;
    key.SetString("Keep", "x");
    key.SetString("Drop", "y");
    key.DeleteValue("Drop");
    Assert.Equal(new[] { "Keep" }, key.GetValueNames());
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `dotnet test --filter "FullyQualifiedName~TestRegistryTests"`
Expected: build failure — `InMemoryRegistry` does not exist.

- [ ] **Step 3: Implement `IRegistry.cs` and `RegistryOptions.cs`**

Exactly the signatures above. `RegistryOptions.DefaultSavedStateKeyPath` is the verbatim constant from Global Constraints.

- [ ] **Step 4: Implement the in-memory hive**

`InMemoryRegistry` holds a single `Dictionary<string, InMemoryEntry>` keyed by `"{rootToken}\\{subKey}"`, where `InMemoryEntry` is the mutable value bag for that path. **`OpenKey` with `writable: true` creates the entry on demand. The path dictionary and every value-name dictionary use `StringComparer.OrdinalIgnoreCase`**, because real registry paths and value names are case-insensitive and several upstream Go files disagree on the casing of the same root (`SYSTEM\...` in `lsa_protection.go:28` versus lowercase elsewhere). A case-sensitive fake would fail tests for the wrong reason and encode a constraint the platform does not have. `TryGet*` return `false` for an absent name **and** for a kind mismatch, so a `REG_SZ` read through `TryGetDword` fails rather than coercing. `DeleteKey` removes the entry **and every entry whose path sits beneath it** — matching the dictionary's own `OrdinalIgnoreCase` comparer, not an ordinal `StartsWith`, and requiring a `\` boundary so `Software\A` never takes `Software\AB`. It returns `false` when nothing was removed, so "already absent" stays distinguishable from "deleted", and it must normalise a trailing `\` from `subKey` and reject an empty or `\`-only `subKey` outright.

**Recorded divergence, so the real adapter does not re-decide it:** the fake deletes a *subtree*. Win32's `RegDeleteKey` **fails** with `ERROR_ACCESS_DENIED` when the key has subkeys — subtree removal is `RegDeleteTree`, or `DeleteSubKeyTree` in .NET. Go's `registry.DeleteKey` is plain `RegDeleteKey`, so `utils.go:159` and `cmd.go:136` would return an error on a key with subkeys. None of the three call sites has any, so Go never hits it and Palisade never will either. **Task 11's real adapter must use `DeleteSubKeyTree`**, so the fake and production agree, and should note that this is a deliberate, unreachable-in-practice widening of Go's behaviour.

- [ ] **Step 5: Run to verify it passes**

Run: `dotnet test --filter "FullyQualifiedName~TestRegistryTests"`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: registry abstraction and in-memory hive"
```

---

## Task 4: Saved-state name parsing and formatting

**Files:**
- Create: `src/Palisade.Core/Registry/RegistryKeyNames.cs`
- Test: `tests/Palisade.Core.Tests/Registry/RegistryKeyNamesTests.cs`

**Interfaces:**
- Consumes: `RegistryRoot`, `RootKeyNames` (Task 2).
- Produces:
  - `public static class RegistryKeyNames`
    - `public const string NewDwordPrefix = "SavedStateNew_";`
    - `public const string NewStringPrefix = "SavedStateNewSZ_";`
    - `public const string NotExistingPrefix = "SavedStateNotExisting_";`
    - `public const string NonRegPrefix = "SavedStateNonReg_";`
    - `public const string LegacyPrefix = "SavedState_";`
    - `public const string Separator = "____";`
    - `public const string LegacySeparator = "_";`
    - `public static string Format(RegistryRoot root, string keyPath, string valueName)`
    - `public static string FormatNotExisting(RegistryRoot root, string keyPath, string valueName)`
    - `public static bool TryParse(string valueName, out SavedStateKind kind, out RegistryRoot root, out string keyPath, out string targetValueName, out string? warning)`
    - `public static string FormatNonReg(MeasureId feature)`
    - `public static bool TryParseNonReg(string valueName, out MeasureId feature)`
  - `public enum SavedStateKind { Dword, String, NotExisting, LegacyDword, LegacyString }`
  - `public readonly record struct SavedStateEntry(SavedStateKind Kind, RegistryRoot Root, string KeyPath, string ValueName, string? Warning);`

**The parse contract, which is the whole point of this task:** the four-underscore form is unambiguous, so `TryParse` splits the root token at the **first** `\` and the remainder at the **first** `____`. The legacy single-underscore form is genuinely ambiguous, because `_` is legal inside a key path, so `TryParse` resolves it by matching the longest known root token followed by `\` at the head of the remainder, then treats **everything after the next `_`** as the value name and the middle as the key path. If no root token matches at the head, the entry is unresolvable: `TryParse` returns `true` with `Warning` set to a sentence naming the value, so the caller can report it — and `Root` is then meaningless, which is why the caller must check `Warning` before using the entry.

- [ ] **Step 1: Write the failing parse tests**

```csharp
[Fact]
public void Formats_the_dword_name_with_four_underscores() =>
    Assert.Equal(
        @"SavedStateNew_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer____DisallowRun",
        RegistryKeyNames.Format(RegistryRoot.CurrentUser,
            @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "DisallowRun"));

[Fact]
public void Round_trips_a_dword_name()
{
    Assert.True(RegistryKeyNames.TryParse(
        @"SavedStateNew_LOCAL_MACHINE\Software\Foo\Bar____MyValue",
        out var kind, out var root, out var keyPath, out var valueName, out var warning));
    Assert.Equal(SavedStateKind.Dword, kind);
    Assert.Equal(RegistryRoot.LocalMachine, root);
    Assert.Equal(@"Software\Foo\Bar", keyPath);
    Assert.Equal("MyValue", valueName);
    Assert.Null(warning);
}

[Fact]
public void Parses_a_value_name_that_contains_a_backslash() // Review Focus #1
{
    Assert.True(RegistryKeyNames.TryParse(
        @"SavedStateNew_CURRENT_USER\Software\Foo____Bar\Baz",
        out _, out _, out var keyPath, out var valueName, out _));
    Assert.Equal(@"Software\Foo", keyPath);
    Assert.Equal(@"Bar\Baz", valueName);
}

[Fact]
public void Parses_a_legacy_name_with_single_underscore() // Review Focus #2
{
    Assert.True(RegistryKeyNames.TryParse(
        @"SavedState_CURRENT_USER\Software\Foo_Bar",
        out var kind, out var root, out var keyPath, out var valueName, out _));
    Assert.Equal(SavedStateKind.LegacyDword, kind);
    Assert.Equal(RegistryRoot.CurrentUser, root);
    Assert.Equal(@"Software\Foo", keyPath);
    Assert.Equal("Bar", valueName);
}

[Fact]
public void Reports_a_legacy_name_whose_key_path_contains_underscores() // Review Focus #2
{
    Assert.True(RegistryKeyNames.TryParse(
        @"SavedState_CURRENT_USER\Software\My_Foo_Bar",
        out _, out _, out var keyPath, out var valueName, out _));
    Assert.Equal(@"Software\My_Foo", keyPath);
    Assert.Equal("Bar", valueName);
}

[Fact]
public void Reports_an_unresolvable_name_with_a_warning_instead_of_guessing()
{
    Assert.True(RegistryKeyNames.TryParse(
        "SavedStateNew_NOT_A_ROOT\Software\Foo____Bar",
        out _, out _, out _, out _, out var warning));
    Assert.NotNull(warning);
    Assert.Contains("NOT_A_ROOT", warning);
}

[Fact]
public void Non_registry_names_round_trip()
{
    // Lowercase `recall` because that is what the Go tool persists (recall_feature.go:50).
    var name = RegistryKeyNames.FormatNonReg(new MeasureId("recall"));
    Assert.Equal("SavedStateNonReg_recall", name);
    Assert.True(RegistryKeyNames.TryParseNonReg(name, out var feature));
    Assert.Equal("recall", feature.Value);
}

[Fact]
public void Non_registry_names_match_the_go_tools_spelling_exactly()
{
    // Guards the byte-compat surface: a capitalised id would round-trip fine but would not
    // find the Go tool's `SavedStateNonReg_recall`.
    Assert.Equal("SavedStateNonReg_recall", RegistryKeyNames.FormatNonReg(new MeasureId("recall")));
    Assert.False(RegistryKeyNames.TryParseNonReg("SavedStateNonReg_Recall", out _));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `dotnet test --filter "FullyQualifiedName~RegistryKeyNamesTests"`
Expected: build failure — `RegistryKeyNames` does not exist.

- [ ] **Step 3: Implement `RegistryKeyNames.cs`**

`Format` and `FormatNotExisting` are pure string composition. `TryParse` dispatches on the longest matching prefix first — check `NewStringPrefix` before `NewDwordPrefix` before `NotExistingPrefix` before `LegacyPrefix`, because `SavedStateNewSZ_` and `SavedStateNew_` are both prefixes-adjacent and a naive `StartsWith` on the shorter one would mis-slice the longer.

For the legacy branch, take `remainder` after the prefix; find the root token by testing all six tokens for a match at position 0 followed by `\`; strip it and the `\`; then find the **first** `_` in what is left and split there. Everything after is the value name. If no root token matches, set `Warning` and return `true`.

`TryParseNonReg` returns `false` for anything not starting with `NonRegPrefix` or with an empty feature name after it.

- [ ] **Step 4: Run to verify it passes**

Run: `dotnet test --filter "FullyQualifiedName~RegistryKeyNamesTests"`
Expected: all pass, including the three Review Focus cases.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: saved-state name parsing with guarded legacy handling"
```

---

## Task 5: `SavedStateStore`

**Files:**
- Create: `src/Palisade.Core/Registry/SavedStateStore.cs`
- Test: `tests/Palisade.Core.Tests/Registry/SavedStateStoreTests.cs`

**Interfaces:**
- Consumes: `IRegistryKeyFactory`, `RegistryOptions`, `RegistryKeyNames`, `SavedStateEntry`, `MeasureId` (Tasks 2–4).
- Produces:
  - `public sealed class SavedStateStore(IRegistryKeyFactory registry, RegistryOptions options)`
    - `public void SaveDword(RegistryRoot root, string keyPath, string valueName, uint originalValue)`
    - `public void SaveString(RegistryRoot root, string keyPath, string valueName, string originalValue)`
    - `public void SaveNotExisting(RegistryRoot root, string keyPath, string valueName)`
    - `public void SaveNonReg(MeasureId feature, string state)`
    - `public IReadOnlyList<SavedStateEntry> ReadAll()`
    - `public bool TryGetNonReg(MeasureId feature, out string state)`
    - `public void DeleteNonReg(MeasureId feature)`
    - `public void Clear()` — deletes the whole saved-state key via `IRegistryKeyFactory.DeleteKey`, matching `utils.go:159`, which removes the key outright on restore rather than emptying it. It must be a no-op when the key is already absent, not an error.

- [ ] **Step 1: Write the failing round-trip tests**

```csharp
[Fact]
public void Saves_and_reads_back_a_dword_entry()
{
    var registry = new InMemoryRegistry();
    var store = new SavedStateStore(registry, RegistryOptions.Default);
    store.SaveDword(RegistryRoot.CurrentUser, @"Software\Foo", "Bar", 7);

    var entry = Assert.Single(store.ReadAll());
    Assert.Equal(SavedStateKind.Dword, entry.Kind);
    Assert.Equal(@"Software\Foo", entry.KeyPath);
    Assert.Equal("Bar", entry.ValueName);
}

[Fact]
public void Writes_only_the_four_current_prefixes() // Global Constraints: never write legacy
{
    var registry = new InMemoryRegistry();
    var store = new SavedStateStore(registry, RegistryOptions.Default);
    store.SaveDword(RegistryRoot.CurrentUser, @"Software\Foo", "Bar", 7);
    store.SaveString(RegistryRoot.CurrentUser, @"Software\Foo", "Baz", "x");
    store.SaveNotExisting(RegistryRoot.CurrentUser, @"Software\Foo", "Qux");
    store.SaveNonReg(new MeasureId("recall"), "disabled");

    using var key = registry.OpenKey(RegistryRoot.CurrentUser, RegistryOptions.DefaultSavedStateKeyPath, true)!;
    Assert.All(key.GetValueNames(), n => Assert.DoesNotContain(RegistryKeyNames.LegacyPrefix, n));
    Assert.Contains(key.GetValueNames(), n => n.StartsWith(RegistryKeyNames.NewDwordPrefix));
    Assert.Contains(key.GetValueNames(), n => n.StartsWith(RegistryKeyNames.NewStringPrefix));
    Assert.Contains(key.GetValueNames(), n => n.StartsWith(RegistryKeyNames.NotExistingPrefix));
    Assert.Contains(key.GetValueNames(), n => n.StartsWith(RegistryKeyNames.NonRegPrefix));
}

[Fact]
public void Reads_a_legacy_entry_written_by_the_go_tool()
{
    var registry = new InMemoryRegistry();
    using (var key = registry.OpenKey(RegistryRoot.CurrentUser, RegistryOptions.DefaultSavedStateKeyPath, true)!)
    {
        key.SetDword(@"SavedState_CURRENT_USER\Software\Foo_Bar", 3);
    }
    var store = new SavedStateStore(registry, RegistryOptions.Default);
    var entry = Assert.Single(store.ReadAll());
    Assert.Equal(SavedStateKind.LegacyDword, entry.Kind);
    Assert.Equal(@"Software\Foo", entry.KeyPath);
}

[Fact]
public void Reports_a_malformed_entry_rather_than_dropping_it_silently()
{
    var registry = new InMemoryRegistry();
    using (var key = registry.OpenKey(RegistryRoot.CurrentUser, RegistryOptions.DefaultSavedStateKeyPath, true)!)
    {
        key.SetDword("SavedStateNew_NOPE\Software\Foo____Bar", 1);
    }
    var store = new SavedStateStore(registry, RegistryOptions.Default);
    var entry = Assert.Single(store.ReadAll());
    Assert.NotNull(entry.Warning);
}

[Fact]
public void Non_registry_state_round_trips_and_deletes()
{
    var registry = new InMemoryRegistry();
    var store = new SavedStateStore(registry, RegistryOptions.Default);
    store.SaveNonReg(new MeasureId("recall"), "disabled");
    Assert.True(store.TryGetNonReg(new MeasureId("recall"), out var state));
    Assert.Equal("disabled", state);
    store.DeleteNonReg(new MeasureId("recall"));
    Assert.False(store.TryGetNonReg(new MeasureId("recall"), out _));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `dotnet test --filter "FullyQualifiedName~SavedStateStoreTests"`
Expected: build failure — `SavedStateStore` does not exist.

- [ ] **Step 3: Implement `SavedStateStore`**

`Save*` open the saved-state key with `writable: true` and write one value. Values written are: `Dword` and `NotExisting` as `SetDword` (matching Go — `SavedStateNotExisting_` is a `REG_DWORD` holding 0), `String` and `NonReg` as `SetString`.

`ReadAll` opens the key read-only; if it is `null`, return an empty list. For each name, classify: `NewStringPrefix` → try string; `NewDwordPrefix` → try dword; `NotExistingPrefix` → try dword; `LegacyPrefix` → try dword then string, producing `LegacyDword` or `LegacyString`. Anything that does not start with a known prefix is skipped entirely — it is not ours. Entries that start with a known prefix but fail to parse are returned with `Warning` set, never dropped.

`ReadAll` must open the key `using` and enumerate inside the `using`.

- [ ] **Step 4: Run to verify it passes**

Run: `dotnet test --filter "FullyQualifiedName~SavedStateStoreTests"`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: saved-state store with Go-format compatibility"
```

---

## Task 6: The five registry mechanisms

**Files:**
- Create: `src/Palisade.Core/Mechanisms/IMechanismHandler.cs`, `RegistryDwordHandler.cs`, `RegistryStringHandler.cs`, `DisallowRunHandler.cs`, `FileAssociationHandler.cs`
- Test: `tests/Palisade.Core.Tests/Mechanisms/RegistryMechanismTests.cs`

**Interfaces:**
- Consumes: `IRegistryKeyFactory`, `SavedStateStore`, `RegistryRoot`, `MeasureId` (Tasks 2–5).
- Produces:
  - `public sealed record ResolvedTarget(RegistryRoot Root, string KeyPath, string ValueName, string? MultiValueName, string Kind, string HardenedValue);` — a *resolved* target: one concrete registry value, after any version expansion. Distinct from Task 2's `MeasureTarget`, which is a *declared* target in the catalog. `ResolveTargets` starts from `descriptor.Targets` and, for versioned measures, fans one declared target out into one `ResolvedTarget` per discovered version; for non-versioned measures it maps each `MeasureTarget` straight through, carrying `Kind` and `HardenedValue` across unchanged.
  - `public interface IMechanismHandler`
    - `Mechanism Mechanism { get; }`
    - `IReadOnlyList<ResolvedTarget> ResolveTargets(MeasureDescriptor descriptor, IVersionResolver versions);`
    - `MeasureState Detect(MeasureDescriptor descriptor, IReadOnlyList<ResolvedTarget> targets, IRegistryKeyFactory registry);`
    - `void Apply(MeasureDescriptor descriptor, IReadOnlyList<ResolvedTarget> targets, IRegistryKeyFactory registry, SavedStateStore store);`
    - `void Restore(MeasureDescriptor descriptor, IReadOnlyList<ResolvedTarget> targets, IRegistryKeyFactory registry, SavedStateStore store);`
  - `public interface IVersionResolver { IReadOnlyList<string> ResolveOfficeVersions(); IReadOnlyList<string> ResolveAdobeVersions(); }` — `VersionedPathHandler` codes against this so version discovery is testable and swappable; Task 7 supplies the real one.
  - Test helper, created in `tests/Palisade.Core.Tests/StubVersionResolver.cs` by this task because Task 6's tests need it: `public sealed class StubVersionResolver(IReadOnlyList<string>? officeVersions = null, IReadOnlyList<string>? adobeVersions = null) : IVersionResolver` — the parameterless call returns empty lists, which is what the `RegistryDword` tests want since those measures are not versioned.

**`MultiValueName` is for multi-value measures.** It is `null` for a single-value target. When set, the target's `ValueName` is ignored and the handler manages several values under one key instead — the `Autorun` and `Uac` lists, and the `DisallowRun` subkey. **This is not `REG_MULTI_SZ`.** It names *where* a handler fans out, and the values it writes are still ordinary `REG_SZ`/`REG_DWORD` values. The only genuine `REG_MULTI_SZ` in the tree is none: no `SetMultiString` call exists upstream.

- [ ] **Step 1: Write the failing mechanism tests**

```csharp
[Fact]
public void Dword_detects_slack_when_the_value_is_at_its_original() // Review Focus #3
{
    var registry = new InMemoryRegistry();
    var descriptor = MeasureCatalog.Get(new MeasureId("Lsa"));
    using (var key = registry.OpenKey(RegistryRoot.LocalMachine, @"System\CurrentControlSet\Control\Lsa", false)!)
    {
        key.SetDword("RunAsPPL", 0);
    }
    var handler = new RegistryDwordHandler();
    var targets = handler.ResolveTargets(descriptor, new StubVersionResolver());
    Assert.Equal(MeasureState.Slack, handler.Detect(descriptor, targets, registry));
}

[Fact]
public void Dword_detects_taut_after_apply()
{
    var registry = new InMemoryRegistry();
    var store = new SavedStateStore(registry, RegistryOptions.Default);
    var descriptor = MeasureCatalog.Get(new MeasureId("Lsa"));
    var handler = new RegistryDwordHandler();
    var targets = handler.ResolveTargets(descriptor, new StubVersionResolver());

    handler.Apply(descriptor, targets, registry, store);
    Assert.Equal(MeasureState.Taut, handler.Detect(descriptor, targets, registry));

    handler.Restore(descriptor, targets, registry, store);
    Assert.Equal(MeasureState.Slack, handler.Detect(descriptor, targets, registry));
}

[Fact]
public void Dword_detects_stressed_when_something_else_set_the_value_first() // Review Focus #3
{
    var registry = new InMemoryRegistry();
    var store = new SavedStateStore(registry, RegistryOptions.Default);
    var descriptor = MeasureCatalog.Get(new MeasureId("Lsa"));
    using (var key = registry.OpenKey(RegistryRoot.LocalMachine, @"System\CurrentControlSet\Control\Lsa", true)!)
    {
        key.SetDword("RunAsPPL", 1); // Group Policy, not us.
    }
    var handler = new RegistryDwordHandler();
    var targets = handler.ResolveTargets(descriptor, new StubVersionResolver());
    Assert.Equal(MeasureState.Stressed, handler.Detect(descriptor, targets, registry));
}

[Fact]
public void Applying_over_a_stressed_value_preserves_the_preexisting_value() // Review Focus #3
{
    var registry = new InMemoryRegistry();
    var store = new SavedStateStore(registry, RegistryOptions.Default);
    var descriptor = MeasureCatalog.Get(new MeasureId("Lsa"));
    using (var key = registry.OpenKey(RegistryRoot.LocalMachine, @"System\CurrentControlSet\Control\Lsa", true)!)
    {
        key.SetDword("RunAsPPL", 1);
    }
    var handler = new RegistryDwordHandler();
    var targets = handler.ResolveTargets(descriptor, new StubVersionResolver());
    handler.Apply(descriptor, targets, registry, store);

    handler.Restore(descriptor, targets, registry, store);
    using var key = registry.OpenKey(RegistryRoot.LocalMachine, @"System\CurrentControlSet\Control\Lsa", false)!;
    Assert.True(key.TryGetDword("RunAsPPL", out var restored));
    Assert.Equal(1u, restored); // The pre-existing 1, not 0.
}

[Fact]
public void NotExisting_restore_deletes_a_value_created_after_hardening() // Review Focus #4
{
    var registry = new InMemoryRegistry();
    var store = new SavedStateStore(registry, RegistryOptions.Default);
    var descriptor = MeasureCatalog.Get(new MeasureId("Lsa"));
    var handler = new RegistryDwordHandler();
    var targets = handler.ResolveTargets(descriptor, new StubVersionResolver());

    store.SaveNotExisting(RegistryRoot.LocalMachine, @"System\CurrentControlSet\Control\Lsa", "RunAsPPL");
    using (var key = registry.OpenKey(RegistryRoot.LocalMachine, @"System\CurrentControlSet\Control\Lsa", true)!)
    {
        key.SetDword("RunAsPPL", 5); // Created after we recorded "did not exist".
    }

    handler.Restore(descriptor, targets, registry, store);
    using var check = registry.OpenKey(RegistryRoot.LocalMachine, @"System\CurrentControlSet\Control\Lsa", false)!;
    Assert.False(check.TryGetDword("RunAsPPL", out _));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `dotnet test --filter "FullyQualifiedName~RegistryMechanismTests"`
Expected: build failure — handlers do not exist.

**The two LSA tests above use `SYSTEM\CurrentControlSet\Control\Lsa` / `RunAsPPL` / hardened value `1` / root `LocalMachine`, transcribed verbatim from `lsa_protection.go:26-30`.** `Cmd` and `Lsa` are the two measures every other mechanism test uses, because both are single-value `REG_DWORD` measures with no version expansion — keep them that way so a failure points at the mechanism, not at the fixture.

- [ ] **Step 3: Implement `IMechanismHandler` and the three registry-value handlers**

`RegistryDwordHandler.Mechanism` is `Mechanism.RegistryDword`. `ResolveTargets` maps each `descriptor.Targets` entry to a `ResolvedTarget` one-for-one, carrying `Kind` and `HardenedValue` across — a `RegistryDword` measure with three declared targets resolves to three, and the handler iterates all of them. `Apply` on a `REG_DWORD` target: read the current value; if the key is absent or the value is absent, call `store.SaveNotExisting`; else call `store.SaveDword` with the current value; then `SetDword(target.HardenedValue)`. The hardened value comes from `MeasureTarget.HardenedValue`, **not** from `descriptor.Settings` — the hardened-value payload moved to the typed `Targets` list in Task 2 and a handler that reads it from `Settings` would find nothing.

`Restore` on a `REG_DWORD` target: look up the saved entry by root/key/value. `Dword` → `SetDword` the saved value. `NotExisting` → `DeleteValue`. `LegacyDword` → `SetDword` the legacy value. No saved entry → do nothing, and record nothing. **Never** write a legacy-format name.

`RegistryStringHandler` is the same with `TryGetString`/`SetString` and `SavedStateKind.String`.

`Detect` for a single-value target returns: `Taut` if the current value equals the hardened value; `Slack` if it equals the original recorded in the store, or the key/value is absent; `Stressed` if it is something else. A target list with more than one member is `Taut` only if **every** member is `Taut`, `Stressed` if any member is `Stressed` and none is `Taut`, otherwise `Slack`.

- [ ] **Step 4: Implement `DisallowRunHandler` and `FileAssociationHandler`**

**`DisallowRunHandler` manages numbered `REG_SZ` values in a subkey — it is not a `REG_MULTI_SZ` list.** The upstream shape (`cmd.go`, `powershell.go`) is:

- `HKCU\...\Policies\Explorer` carries a `DWORD DisallowRun = 1` flag that enables the policy.
- The **subkey** `HKCU\...\Policies\Explorer\DisallowRun` carries numbered string values: `"1"="cmd.exe"`, `"2"="powershell_ise.exe"`, `"3"="powershell.exe"` (`cmd.go:170-177`, `powershell.go:180-185`). There is no list value and no index field — the value *names* are the indices.
- Reading walks `i = 1, 2, 3 …` and **stops at the first gap** (`cmd.go:77`), so a hole truncates the list.
- Harden finds the first free index (scanning to 99) and writes there, preserving foreign entries.
- Restore iterates the same way, deletes only *its own* executables, **renumbers the survivors from 1**, and then either keeps the subkey or `DeleteKey`s it when nothing is left (`cmd.go:118-140`).

`ResolveTargets` returns one target whose `ValueName` is the `Explorer\DisallowRun` flag and whose `MultiValueName` is the subkey to manage. `Apply` records the flag's original state, appends at the first free index, and sets the flag to `1`. `Restore` removes only its own entries, compacts, deletes the subkey if it became empty, then restores the flag's original state. This is Review Focus #5.

**Both the handler and its tests must work in numbered-`REG_SZ` space.** A test that seeds `SetMultiString("", …)` would pass against an implementation that is wrong in production, and a compaction step that is never asserted is a compaction step that will silently rot.

`FileAssociationHandler` works against `HKCU\SOFTWARE\Classes` and restricts which ProgIDs may open each extension. The exact per-extension restriction table is the longest piece of hand-authored data in the project; put it in a single `FileAssociationTable` static class inside `FileAssociationHandler.cs` and keep it flat.

Add these two tests, which are the verification for the two requirements above that were previously only prose:

```csharp
[Fact]
public void DisallowRun_restore_removes_only_our_entry() // Review Focus #5
{
    var registry = new InMemoryRegistry();
    var store = new SavedStateStore(registry, RegistryOptions.Default);
    var descriptor = MeasureCatalog.Get(new MeasureId("Cmd"));
    var handler = new DisallowRunHandler();
    var targets = handler.ResolveTargets(descriptor, new StubVersionResolver());

    // A foreign program already owns index 1. Ours must land at index 2, and restore
    // must put the foreign entry back at index 1 — that is what compaction means.
    using (var key = registry.OpenKey(RegistryRoot.CurrentUser,
        @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun", true)!)
    {
        key.SetString("1", "wscript.exe");
    }

    handler.Apply(descriptor, targets, registry, store);
    handler.Restore(descriptor, targets, registry, store);

    using var check = registry.OpenKey(RegistryRoot.CurrentUser,
        @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun", false)!;
    Assert.Equal(new[] { "1" }, check.GetValueNames());       // the gap closed
    Assert.True(check.TryGetString("1", out var remaining));
    Assert.Equal("wscript.exe", remaining);
    Assert.DoesNotContain("cmd.exe", check.GetValueNames());
}

[Fact]
public void DisallowRun_restore_deletes_the_subkey_when_nothing_is_left() // cmd.go:136
{
    var registry = new InMemoryRegistry();
    var store = new SavedStateStore(registry, RegistryOptions.Default);
    var descriptor = MeasureCatalog.Get(new MeasureId("Cmd"));
    var handler = new DisallowRunHandler();
    var targets = handler.ResolveTargets(descriptor, new StubVersionResolver());

    handler.Apply(descriptor, targets, registry, store);
    handler.Restore(descriptor, targets, registry, store);

    // An empty DisallowRun subkey denies nothing, but upstream removes it, and leaving
    // residue the Go tool would not leave is a divergence in its own right.
    Assert.Null(registry.OpenKey(RegistryRoot.CurrentUser,
        @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun", false));
}

[Fact]
public void Restore_does_not_resurrect_a_deleted_key() // Global Constraint 6
{
    var registry = new InMemoryRegistry();
    var store = new SavedStateStore(registry, RegistryOptions.Default);
    var descriptor = MeasureCatalog.Get(new MeasureId("OfficeDde"));
    var handler = new RegistryDwordHandler();
    var targets = handler.ResolveTargets(descriptor, new StubVersionResolver());

    handler.Apply(descriptor, targets, registry, store);
    // Simulate the user or a cleanup tool removing the key after hardening.
    foreach (var target in targets)
        registry.DeleteKey(target.Root, target.KeyPath);

    handler.Restore(descriptor, targets, registry, store);

    // Go's restore opens the key and skips on failure; it never re-creates it.
    Assert.All(targets, t => Assert.Null(registry.OpenKey(t.Root, t.KeyPath, false)));
}

[Fact]
public void FileAssociation_detects_hardened_after_apply() // spec defect #1
{
    var registry = new InMemoryRegistry();
    var store = new SavedStateStore(registry, RegistryOptions.Default);
    var descriptor = MeasureCatalog.Get(new MeasureId("FileAssociations"));
    var handler = new FileAssociationHandler();
    var targets = handler.ResolveTargets(descriptor, new StubVersionResolver());

    Assert.Equal(MeasureState.Slack, handler.Detect(descriptor, targets, registry));
    handler.Apply(descriptor, targets, registry, store);
    Assert.Equal(MeasureState.Taut, handler.Detect(descriptor, targets, registry));
    handler.Restore(descriptor, targets, registry, store);
    Assert.Equal(MeasureState.Slack, handler.Detect(descriptor, targets, registry));
}
```

- [ ] **Step 5: Add the tests for Review Focus #4 and #5, then run everything**

Run: `dotnet test`
Expected: all pass, no test touching a real registry.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: registry, string, DisallowRun and file-association mechanisms"
```

---

## Task 7: Versioned paths and `VersionedPathHandler`

**Files:**
- Create: `src/Palisade.Core/Mechanisms/VersionedPathHandler.cs`, `MEASURE_APPLICATIONS.md`
- Test: `tests/Palisade.Core.Tests/Mechanisms/VersionedPathTests.cs`

**Interfaces:**
- Consumes: `IMechanismHandler`, `IVersionResolver`, `SavedStateStore`, `MeasureDescriptor.Settings` and `MeasureDescriptor.Targets` (Task 2, Task 6).
- Produces:
  - `public sealed class InstalledVersionResolver(IRegistryKeyFactory registry) : IVersionResolver` — enumerates installed Office and Adobe version directories under `%ProgramFiles%` and `%ProgramFiles(x86)%` and returns only the versions actually present. Returns an empty list when the directory is absent, which the handler reports as a failure rather than a silent success.
  - `public sealed record PathResolutionResult(IReadOnlyList<ResolvedTarget> Targets, IReadOnlyList<string> Failures);`
  - `public sealed class VersionedPathHandler { public PathResolutionResult Resolve(MeasureDescriptor descriptor, IVersionResolver versions); }` plus the three `IMechanismHandler` members, where `Detect`/`Apply`/`Restore` operate on `Resolve(...).Targets` and a non-empty `Failures` list makes `Detect` return `Unavailable`.

- [ ] **Step 1: Write the failing versioned-path tests**

```csharp
[Fact]
public void Expands_one_target_per_installed_version_and_app()
{
    var resolver = new StubVersionResolver(officeVersions: new[] { "16.0" }, adobeVersions: Array.Empty<string>());
    var descriptor = MeasureCatalog.Get(new MeasureId("OfficeMacros"));
    var result = new VersionedPathHandler().Resolve(descriptor, resolver);
    Assert.Equal(new[] { "Excel", "PowerPoint", "Word" }.Length, result.Targets.Count);
    Assert.All(result.Targets, t => Assert.Contains(@"16.0", t.KeyPath));
}

[Fact]
public void Reports_a_failure_when_no_version_resolves() // spec defect #9
{
    var resolver = new StubVersionResolver(officeVersions: Array.Empty<string>(), adobeVersions: Array.Empty<string>());
    var descriptor = MeasureCatalog.Get(new MeasureId("OfficeMacros"));
    var result = new VersionedPathHandler().Resolve(descriptor, resolver);
    Assert.Empty(result.Targets);
    Assert.NotEmpty(result.Failures);
}

[Fact]
public void Detects_unavailable_when_nothing_resolved()
{
    var resolver = new StubVersionResolver(officeVersions: Array.Empty<string>(), adobeVersions: Array.Empty<string>());
    var descriptor = MeasureCatalog.Get(new MeasureId("OfficeMacros"));
    var handler = new VersionedPathHandler();
    var result = handler.Resolve(descriptor, resolver);
    Assert.Equal(MeasureState.Unavailable, handler.Detect(descriptor, result.Targets, new InMemoryRegistry()));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `dotnet test --filter "FullyQualifiedName~VersionedPathTests"`
Expected: build failure — `VersionedPathHandler` does not exist.

- [ ] **Step 3: Write `MEASURE_APPLICATIONS.md`**

The authoritative table, transcribed from the Go source, giving for each versioned measure its template, root key, value name, hardened value, version list source, and app list. Each entry cites the Go file and line it came from. Include the upstream version lists verbatim for comparison: `standardOfficeVersions = {12.0, 14.0, 15.0, 16.0}`, `standardAdobeVersions = {DC, 2020, XI}`, `standardOfficeApps = {Excel, PowerPoint, Word}`.

- [ ] **Step 4: Implement `VersionedPathHandler` and `InstalledVersionResolver`**

`Resolve` reads each target's `Path` from `descriptor.Targets` and the product universe from `descriptor.Settings["OfficeVersions"]` / `["Apps"]` / `["AdobeVersions"]`. Expansion is driven by **the placeholders in the target's own `Path`**, never by whether the measure as a whole is versioned:

- A `Path` containing `%s` is versioned. Narrow it by `AppFilter` / `VersionFilter` if either is non-null, cross the result with the universe, substitute `%s`, and return one `ResolvedTarget` per surviving pair. `%s` stands for the version, and the app appears in the surrounding path text.
- A `Path` containing **no** `%s` is fixed. Return **exactly one** `ResolvedTarget`, substituting nothing — even if `AppFilter` or `VersionFilter` is set, and even if the descriptor's `Mechanism` is `VersionedPath`. This is the case for `office.go`'s `fNoCalclinksOnopen_90_1`, whose path is a hardcoded `12.0\Word\Options\vpref`.

The second rule is the one that is easy to get wrong. Expanding a fixed path over the version list would produce one write per version to the *same* registry key — 4 versions x 2 apps = 8 writes to a single `12.0` key. `MeasureCatalog.cs:181` gives that measure `Mechanism.VersionedPath`, which is exactly the signal that invites the wrong implementation, so the placeholder test is on the path and never on the mechanism.

`Resolve` does **not** check whether the resulting registry key exists — that is `Detect`'s job, and conflating the two is what makes the Go tool report success on a machine with a version it does not know.

`InstalledVersionResolver` enumerates directory names under the Office and Adobe install roots, matching the shape the templates expect, and returns the distinct version tokens found.

- [ ] **Step 5: Run to verify it passes**

Run: `dotnet test --filter "FullyQualifiedName~VersionedPathTests"`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: versioned-path expansion with discovered versions"
```

---

## Task 8: `NonRegistry` measures — ASR and Recall

**Files:**
- Create: `src/Palisade.Core/Mechanisms/NonRegistryHandler.cs`, `AsrRulesMeasure.cs`, `RecallMeasure.cs`
- Test: `tests/Palisade.Core.Tests/Mechanisms/NonRegistryTests.cs`

**Interfaces:**
- Consumes: `IMechanismHandler`, `SavedStateStore`, `IRegistryKeyFactory` (Tasks 3–6).
- Produces:
  - `public interface INonRegistryMeasure`
    - `MeasureId Id { get; }`
    - `IReadOnlyList<AvailabilityRule> Availability { get; }`
    - `bool IsAvailable();`
    - `MeasureState Detect(SavedStateStore store);`
    - `void Apply(SavedStateStore store);`
    - `void Restore(SavedStateStore store);`
  - `public sealed class AsrRulesMeasure(IRegistryKeyFactory registry) : INonRegistryMeasure`
  - `public sealed class RecallMeasure(IRegistryKeyFactory registry) : INonRegistryMeasure`
  - `public sealed class NonRegistryHandler(IReadOnlyDictionary<MeasureId, INonRegistryMeasure> measures) : IMechanismHandler`

- [ ] **Step 1: Write the failing tests**

```csharp
[Fact]
public void Recall_is_unavailable_when_the_feature_is_absent_from_the_build()
{
    var registry = new InMemoryRegistry();
    var measure = new RecallMeasure(registry);
    Assert.False(measure.IsAvailable());
}

[Fact]
public void Recall_applies_and_restores_via_non_reg_state()
{
    var registry = new InMemoryRegistry();
    var store = new SavedStateStore(registry, RegistryOptions.Default);
    var measure = new RecallMeasure(registry);   // Stubbed present by seeding the feature key.
    measure.Apply(store);
    Assert.Equal(MeasureState.Taut, measure.Detect(store));
    measure.Restore(store);
    Assert.Equal(MeasureState.Slack, measure.Detect(store));
}

[Fact]
public void Asr_is_unavailable_when_windows_defender_antivirus_is_disabled()
{
    var registry = new InMemoryRegistry();
    using (var key = registry.OpenKey(RegistryRoot.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender", true)!)
    {
        key.SetDword("DisableAntiSpyware", 1);
    }
    var measure = new AsrRulesMeasure(registry);
    Assert.False(measure.IsAvailable());
}

[Fact]
public void Asr_records_the_exact_original_rule_set() // spec defect #3
{
    var registry = new InMemoryRegistry();
    var store = new SavedStateStore(registry, RegistryOptions.Default);
    var measure = new AsrRulesMeasure(registry);
    measure.Apply(store);
    Assert.True(store.TryGetNonReg(measure.Id, out var state));
    Assert.NotEmpty(state); // The recorded original, not a sentinel.
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `dotnet test --filter "FullyQualifiedName~NonRegistryTests"`
Expected: build failure — the measures do not exist.

- [ ] **Step 3: Implement the two measures**

`RecallMeasure.IsAvailable` checks for the Recall feature's presence in the registry. `Apply` records the current state through `store.SaveNonReg(Id, currentState)` and then disables; `Restore` reads that record and reinstates it. The record is the *actual* prior state, never a fixed sentinel — that is defect #3's fix applied to Recall.

`AsrRulesMeasure.IsAvailable` is `false` when `DisableAntiSpyware` is set or when no Defender presence is detectable. `Apply` reads **every** ASR rule GUID value under the ASR key, records the complete set including which were absent, writes the hardened rule set, and records that set as the non-registry saved state. `Restore` reinstates exactly the recorded set, including deleting rules that were absent before.

`NonRegistryHandler` dispatches by `descriptor.Id`; an id with no registered measure returns `Unavailable`.

- [ ] **Step 4: Run to verify it passes**

Run: `dotnet test --filter "FullyQualifiedName~NonRegistryTests"`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: ASR and Recall non-registry measures"
```

---

## Task 9: Four-state detection and restore ordering

**Files:**
- Create: `src/Palisade.Core/Engine/MeasureDetector.cs`, `RestorePlanner.cs`
- Test: `tests/Palisade.Core.Tests/Engine/DetectionTests.cs`, `RestorePlannerTests.cs`

**Interfaces:**
- Consumes: `MeasureCatalog`, `IMechanismHandler` per mechanism, `AvailabilityRule`, `MeasureConstraint` (Tasks 2, 6–8).
- Produces:
  - `public sealed record AvailabilityOutcome(string Reason, IReadOnlyList<string> BlockedBy);`
  - `public sealed record DetectionResult(MeasureId Id, MeasureState State, AvailabilityOutcome? Unavailable, IReadOnlyList<MeasureId> ConstrainedBy);`
  - `public sealed class MeasureDetector(IReadOnlyDictionary<Mechanism, IMechanismHandler> handlers, IReadOnlyDictionary<MeasureId, INonRegistryMeasure> nonRegistry, Func<bool> isElevated)`
    - `IReadOnlyList<DetectionResult> DetectAll();`
    - `DetectionResult Detect(MeasureDescriptor descriptor);`
  - `public static class RestorePlanner`
    - `public static IReadOnlyList<MeasureId> Order(IEnumerable<MeasureDescriptor> descriptors);`
  - Test helper, created in `tests/Palisade.Core.Tests/Engine/EngineFactory.cs` by this task and reused by Task 10 and Task 12: `internal static class EngineFactory { public static MeasureDetector BuildDetector(IRegistry? registry = null, bool isElevated = true); public static PalisadeEngine BuildEngine(IRegistry? registry = null, bool isElevated = true); }` — the single place the handler dictionary and non-registry dictionary are assembled for tests, so a later change to composition is made once.

`RestorePlanner` is a **static** class with one member. It is not injected anywhere; `ApplyEngine` calls `RestorePlanner.Order(...)` directly. Consumers that need a single measure's constraints read `descriptor.ConstrainedBy` directly rather than through a planner method.

- [ ] **Step 1: Write the failing detection tests**

```csharp
[Fact]
public void Without_elevation_exactly_the_14_privileged_measures_are_unavailable()
{
    var detector = BuildDetector(isElevated: false);
    var results = detector.DetectAll();
    Assert.Equal(14, results.Count(r => r.State == MeasureState.Unavailable));
    Assert.All(
        results.Where(r => r.State == MeasureState.Unavailable),
        r => Assert.False(string.IsNullOrWhiteSpace(r.Unavailable!.Reason)));
}

[Fact]
public void Elevation_reason_names_the_measure() // spec defect #11
{
    var detector = BuildDetector(isElevated: false);
    var cmd = detector.Detect(MeasureCatalog.Get(new MeasureId("Cmd")));
    Assert.Equal(MeasureState.Unavailable, cmd.State);
    Assert.Contains("cmd", cmd.Unavailable!.Reason, StringComparison.OrdinalIgnoreCase);
}

[Fact]
public void Restore_order_is_stable_across_100_runs() // spec defect #4
{
    var orders = Enumerable.Range(0, 100)
        .Select(_ => string.Join(",", RestorePlanner.Order(MeasureCatalog.All).Select(i => i.Value)))
        .Distinct()
        .ToList();
    Assert.Single(orders);
}

[Fact]
public void Restore_order_respects_every_declared_constraint() // spec defect #4
{
    var order = RestorePlanner.Order(MeasureCatalog.All).Select(i => i.Value).ToList();
    foreach (var descriptor in MeasureCatalog.All)
    {
        foreach (var constraint in descriptor.ConstrainedBy)
        {
            Assert.True(
                order.IndexOf(constraint.Target.Value) < order.IndexOf(descriptor.Id.Value),
                $"{constraint.Target} is constrained by {descriptor.Id}, so it must be restored first");
        }
    }
}

[Fact]
public void Restore_order_is_a_permutation_of_the_catalog()
{
    var order = RestorePlanner.Order(MeasureCatalog.All).Select(i => i.Value).OrderBy(v => v, StringComparer.Ordinal).ToList();
    var expected = MeasureCatalog.All.Select(m => m.Id.Value).OrderBy(v => v, StringComparer.Ordinal).ToList();
    Assert.Equal(expected, order);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `dotnet test --filter "FullyQualifiedName~DetectionTests|FullyQualifiedName~RestorePlannerTests"`
Expected: build failure — detector and planner do not exist.

- [ ] **Step 3: Implement `MeasureDetector`**

For each descriptor: if `RequiresElevation` and not elevated, return `Unavailable` with a reason naming the measure. Otherwise evaluate the descriptor's `Availability` rules; the first failing rule produces `Unavailable` with that rule's `Reason` and the ids that caused it. Otherwise dispatch to the mechanism handler and combine per-target states with the rule from Task 6 Step 3.

`RestorePlanner.Order` builds the constraint edges from every descriptor's `ConstrainedBy`, then produces a reverse-topological order: a measure that is constrained by another is restored **before** the one constraining it, because undoing the dependent first is what leaves the shared registry value in a valid state. Ties break on `MeasureId.Value` ordinal comparison, which is what makes the order stable. Implement with Kahn's algorithm over the reversed edges and a `SortedSet<string>` of ready nodes, so the tie-break is structural rather than an accident of insertion order.

- [ ] **Step 4: Run to verify it passes**

Run: `dotnet test`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: four-state detection and deterministic restore ordering"
```

---

## Task 10: `ApplyEngine` and the public facade

**Files:**
- Create: `src/Palisade.Core/Engine/ApplyReport.cs`, `ApplyEngine.cs`, `src/Palisade.Core/PalisadeEngine.cs`
- Test: `tests/Palisade.Core.Tests/Engine/ApplyEngineTests.cs`

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `public enum ApplyOutcome { Applied, AlreadyApplied, Restored, NotRestored, Unavailable, Failed }`
  - `public sealed record MeasureResult(MeasureId Id, ApplyOutcome Outcome, string? Detail);`
  - `public sealed record ApplyReport(IReadOnlyList<MeasureResult> Results, IReadOnlyList<string> Warnings, bool RequiresRestart);`
  - `public sealed class ApplyEngine(MeasureDetector detector, IReadOnlyDictionary<Mechanism, IMechanismHandler> handlers, IReadOnlyDictionary<MeasureId, INonRegistryMeasure> nonRegistry, SavedStateStore store)` — no `RestorePlanner` and no elevation predicate. Ordering comes from the static `RestorePlanner.Order`, and elevation was already resolved by the detector this engine holds. Two sources of truth for elevation is how a measure gets applied without ever having been checked.
    - `ApplyReport Apply(IReadOnlyCollection<MeasureId> ids);`
    - `ApplyReport RestoreAll();`
    - `ApplyReport ReapplyDefaults();` — restore every non-default measure to its original, then apply the default set. This is the Go tool's "Harden again (all default settings)" and it is the operation that must leave a machine in a fully-determined state after a version upgrade.
  - `public sealed class PalisadeEngine`
    - `public PalisadeEngine(IRegistryKeyFactory registry, RegistryOptions options, IAppPaths paths, Func<bool> isElevated)`
    - `public IReadOnlyList<MeasureDescriptor> Catalog { get; }`
    - `public IReadOnlyList<DetectionResult> Detect();`
    - `public ApplyReport Apply(IReadOnlyCollection<MeasureId> ids);`
    - `public ApplyReport RestoreAll();`
    - `public ApplyReport ReapplyDefaults();`

`PalisadeEngine`'s constructor is the single composition root for the whole library. Later plans construct it and nothing else.

- [ ] **Step 1: Write the failing engine tests**

```csharp
[Fact]
public void Apply_is_idempotent() // spec §12.1.9
{
    var engine = BuildEngine();
    var ids = MeasureCatalog.All.Where(m => m.HardenByDefault && !m.RequiresElevation)
        .Select(m => m.Id).ToList();
    engine.Apply(ids);
    var second = engine.Apply(ids);
    Assert.All(second.Results, r => Assert.Equal(ApplyOutcome.AlreadyApplied, r.Outcome));
}

[Fact]
public void Restore_is_idempotent()
{
    var engine = BuildEngine();
    engine.RestoreAll();
    var second = engine.RestoreAll();
    Assert.All(second.Results, r => Assert.Equal(ApplyOutcome.NotRestored, r.Outcome));
}

[Fact]
public void Reapply_defaults_leaves_no_measure_in_a_stressed_state()
{
    var engine = BuildEngine();
    var report = engine.ReapplyDefaults();
    Assert.DoesNotContain(report.Results, r => r.Outcome == ApplyOutcome.Failed);
    var after = engine.Detect();
    Assert.DoesNotContain(after, r => r.Id.Value == "recall" && r.State == MeasureState.Stressed);
}

[Fact]
public void Restore_all_returns_every_applied_measure_to_slack()
{
    var engine = BuildEngine();
    engine.Apply(MeasureCatalog.All.Where(m => !m.RequiresElevation).Select(m => m.Id).ToList());
    engine.RestoreAll();
    var after = engine.Detect().Where(r => !r.Id.Value.StartsWith("LibreOffice")).ToList();
    Assert.All(after, r => Assert.True(
        r.State is MeasureState.Slack or MeasureState.Unavailable,
        $"{r.Id} was {r.State}"));
}

[Fact]
public void Report_carries_a_warning_for_every_malformed_saved_entry() // spec defect #5
{
    var registry = new InMemoryRegistry();
    using (var key = registry.OpenKey(RegistryRoot.CurrentUser, RegistryOptions.DefaultSavedStateKeyPath, true)!)
    {
        key.SetDword("SavedStateNew_NOPE\Software\Foo____Bar", 1);
    }
    var engine = new PalisadeEngine(registry, RegistryOptions.Default, new AppPaths("."), () => true);
    var report = engine.RestoreAll();
    Assert.NotEmpty(report.Warnings);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `dotnet test --filter "FullyQualifiedName~ApplyEngineTests"`
Expected: build failure — engine does not exist.

- [ ] **Step 3: Implement `ApplyReport` and `ApplyEngine`**

`Apply` iterates ids in `RestorePlanner.Order` order restricted to that set, skipping `Unavailable` with an `Unavailable` outcome carrying the detector's reason, and skipping `Stressed` unless the caller explicitly asked for it — **the engine never overwrites a `Stressed` measure without an explicit flag**, because that is defect #3. `RestoreAll` reads the saved state, restores in `RestorePlanner.Order` order, and reports `NotRestored` for anything with no saved entry. `RequiresRestart` is set when any applied measure is in the restart-required set. Every malformed saved-state entry becomes a `Warning` carrying the entry's `Warning` sentence — never a silent drop.

- [ ] **Step 4: Implement `PalisadeEngine`**

A thin facade. The constructor builds the handler dictionary, the non-registry dictionary, the store, the detector, and the engine. It contains no logic beyond that wiring.

- [ ] **Step 5: Run the whole suite**

Run: `dotnet test`
Expected: all pass. Confirm no test opened a real registry key by checking that no test file references `Microsoft.Win32.Registry`.

Run: `Select-String -Path tests/**/*.cs -Pattern "Microsoft.Win32.Registry"` → expect no matches.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: apply engine and PalisadeEngine facade"
```

---

## Task 11: `RegistryAccess` — the only real-registry adapter

**Files:**
- Create: `src/Palisade.Core/Registry/RegistryAccess.cs`
- Test: `tests/Palisade.Core.Tests/Registry/RegistryAccessTests.cs` (guarded, skipped by default)

**Interfaces:**
- Consumes: `IRegistryKeyFactory`, `RegistryRoot` (Tasks 2–3).
- Produces: `public sealed class RegistryAccess : IRegistry, IRegistryKeyFactory` with `OpenKey(RegistryRoot root, string subKey, bool writable)` translating a `RegistryRoot` to the corresponding `Microsoft.Win32.RegistryKey` and returning a `RegistryKeyWrapper` that adapts the `IRegistryKey` surface. `OpenKey` returns `null` when the underlying open throws `SecurityException` **or** `IOException` for a missing key — both are normal absence.

- [ ] **Step 1: Write the guarded integration test**

A `[Fact]` with a `Skippable`-style guard is not available without an extra package, so gate on an environment variable instead:

```csharp
[Fact]
public void Opens_a_real_key_read_only()
{
    if (Environment.GetEnvironmentVariable("PALISADE_INTEGRATION") != "1")
    {
        return; // No real-registry access in the normal suite.
    }
    using var key = new RegistryAccess().OpenKey(RegistryRoot.CurrentUser, @"Software", false);
    Assert.NotNull(key);
}

[Fact]
public void Returns_null_for_a_missing_key()
{
    Assert.Null(new RegistryAccess().OpenKey(
        RegistryRoot.CurrentUser, @"Software\Palisade\NoSuchKey_9F2C", writable: false));
}
```

The second test is safe unconditionally: it asserts absence, and the key name is one this project never creates.

- [ ] **Step 2: Run to verify the first test is skipped in effect**

Run: `dotnet test --filter "FullyQualifiedName~RegistryAccessTests"`
Expected: pass — both tests pass, the first by returning early.

- [ ] **Step 3: Implement `RegistryAccess`**

This is the only file in `src/Palisade.Core` that mentions `Microsoft.Win32.Registry`. `IRegistryKey.TryGet*` must catch `IOException` and return `false`, because a value of the wrong kind or a racing deletion surfaces as an exception, not a null.

- [ ] **Step 4: Verify the no-real-registry rule holds across the whole project**

Run: `Select-String -Path "src/Palisade.Core/**/*.cs" -Pattern "Microsoft.Win32.Registry" -List`
Expected: exactly one file, `RegistryAccess.cs`.

Run: `dotnet test`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: real-registry adapter isolated to a single file"
```

---

## Task 12: Full-catalog detection suite

**Files:**
- Create: `tests/Palisade.Core.Tests/Catalog/AllMeasuresTests.cs`

**Interfaces:**
- Consumes: `PalisadeEngine`, `MeasureCatalog` (all prior tasks).
- Produces: no production code. This task exists to prove every one of the 26 measures resolves, detects, and reports a coherent outcome — the spec requires per-measure coverage and it is the task most likely to surface a wrong descriptor.

- [ ] **Step 1: Write the per-measure test**

```csharp
public class AllMeasuresTests
{
    public static TheoryData<string> AllMeasureIds()
    {
        var data = new TheoryData<string>();
        foreach (var m in MeasureCatalog.All) data.Add(m.Id.Value);
        return data;
    }

    [Theory]
    [MemberData(nameof(AllMeasureIds))]
    public void Every_measure_detects_to_a_known_state_without_elevation(string id)
    {
        var engine = BuildEngine(isElevated: false);
        var result = Assert.Single(engine.Detect().Where(r => r.Id.Value == id));
        Assert.True(Enum.IsDefined(result.State));
        if (result.State == MeasureState.Unavailable)
            Assert.False(string.IsNullOrWhiteSpace(result.Unavailable!.Reason));
    }

    [Theory]
    [MemberData(nameof(AllMeasureIds))]
    public void Every_measure_detects_to_a_known_state_with_elevation(string id)
    {
        var engine = BuildEngine(isElevated: true);
        var result = Assert.Single(engine.Detect().Where(r => r.Id.Value == id));
        Assert.True(Enum.IsDefined(result.State));
    }

    [Theory]
    [MemberData(nameof(AllMeasureIds))]
    public void Every_measures_detect_survives_an_apply_and_restore_cycle(string id)
    {
        var engine = BuildEngine(isElevated: true);
        engine.Apply(new[] { new MeasureId(id) });
        engine.RestoreAll();
        var result = Assert.Single(engine.Detect().Where(r => r.Id.Value == id));
        Assert.True(result.State is MeasureState.Slack or MeasureState.Unavailable,
            $"{id} was {result.State} after restore");
    }
}
```

- [ ] **Step 2: Run and fix descriptors until green**

Run: `dotnet test --filter "FullyQualifiedName~AllMeasuresTests"`
Expected: failures here mean a descriptor's target path, value name, or hardened value is wrong. Fix the descriptor in `MeasureCatalog.cs` against the Go source — do not weaken the test. Expect this task to take several iterations; that is its purpose.

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "test: per-measure detection coverage for all 26 measures"
```

---

## Execution Notes

- Tasks 1–5 are strictly sequential: each consumes the previous one's types.
- Task 6 needs Task 3's hive and Task 4's names. Task 7 needs Task 6's `IMechanismHandler`. Task 8 needs Task 6's contract. Tasks 9–10 need all handlers.
- Task 12 is the gate. Nothing is "done" until all 26 measures pass detection, apply, and restore.
- `Palisade.Cli` and `Palisade.App` are separate plans (2 and 3) and depend only on `PalisadeEngine`'s public surface, which Task 10 freezes.

## Plan Self-Review

- **Spec coverage:** §4 architecture → Task 1. §5 model → Task 2. §6 the 26 measures → Tasks 2 and 12. §7 saved state and Go compatibility → Tasks 4, 5, 11. §7.4 restore ordering → Task 9. §8 defect #1 (file-association `IsHardened`) → Task 6 Step 4 and Task 12's per-measure detect test. #3 (ASR inexact restore) → Task 8. #4 (nondeterministic restore) → Task 9. #5 (unguarded legacy parsing) → Task 5. #9 (hardcoded version list) → Task 7. #10 (two-state model) → Tasks 6 and 9. #11 (opaque elevation) → Task 9. Defects #2, #6, #7 are properties of the design itself rather than separate work: `IRegistryKey : IDisposable` with `using` everywhere is #2; the `ApplyReport.Warnings` channel plus Task 10's malformed-entry test is #6; `PalisadeEngine` returning a report instead of exiting the process is #7. Defect #8 (truncated text) is a UI concern and belongs to Plan 3. §9 four states → Tasks 6 and 9. §12.1 Core tests → Tasks 4–12. §13 delivery → deferred to Plan 2.
- **Step scan:** every code step names a file and a signature. No step says "handle edge cases" or "write tests for the above."
- **Type consistency:** verified. `MeasureDescriptor` gained `Settings` in Task 2 after this review caught Task 6 depending on a key the descriptor did not have — the eight reserved `Settings` keys are now fixed in Task 2. `StubVersionResolver` is declared in Task 6 (its first use) and `EngineFactory` in Task 9 (its first use), so no test references an undefined helper. `MeasureId`, `IMechanismHandler`, `SavedStateStore`, `RegistryOptions`, `IRegistryKeyFactory` are each defined once and consumed by name thereafter.
- **Review Focus:** all five lines have named tests in Tasks 4, 6, and 10, each marked `// Review Focus #n`.
- **Proportion:** the plan is longer than the spec's Core-relevant sections, which is expected — it decomposes 26 measures into verifiable increments. It contains no implementation bodies; the only code blocks are test assertions, package versions, and property values.
