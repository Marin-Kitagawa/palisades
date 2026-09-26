// Hardentools
// Copyright (C) 2017-2023 Security Without Borders
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

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

    // The brief's original form of this test was a [Theory] over the three kinds asserting
    // `Assert.Equal(kind, t.Kind)` for *every* target, which no data can satisfy: it can only
    // pass if all targets share one kind, and two other tests in this file require a
    // "String" target and a "Dword" target to coexist. Asserted as a membership check, which
    // is what the test's name states.
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

            // Not blank: `SecureURL` hardens to the empty string, which is a real hardened
            // value and must stay distinguishable from a missing one.
            Assert.NotNull(t.HardenedValue);
        });
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
        // libreoffice.go:39 writes REG_SZ "Value" and libreoffice.go:57 writes REG_DWORD
        // "Final" at the same policy path, so no single `Mechanism` value describes them —
        // this is the case that forced the typed `Targets` list.
        var libre = MeasureCatalog.All.Where(m => m.Group == MeasureGroup.LibreOffice).ToList();
        Assert.Equal(5, libre.Count);
        Assert.All(libre, m =>
        {
            Assert.Contains(m.Targets, t => t.ValueName == "Value" && t.Kind == "String");
            Assert.Contains(m.Targets, t => t.ValueName == "Final" && t.Kind == "Dword");
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
        // on the value name rather than asserting the path is unique. The predicate overload
        // of Assert.Single is used rather than a Where clause, which xUnit2031 rejects.
        var secureUrl = Assert.Single(macro.Targets, t =>
            t.Path.Contains("SecureURL", StringComparison.Ordinal) && t.ValueName == "Value");
        Assert.Equal("String", secureUrl.Kind);
        Assert.Equal(string.Empty, secureUrl.HardenedValue);
        var secureUrlFinal = Assert.Single(macro.Targets, t =>
            t.Path.Contains("SecureURL", StringComparison.Ordinal) && t.ValueName == "Final");
        Assert.Equal("Dword", secureUrlFinal.Kind);
        Assert.Equal("0", secureUrlFinal.HardenedValue);
    }

    [Fact]
    public void The_three_composite_LibreOffice_measures_keep_both_of_their_sub_measures()
    {
        // MacroSecurityLevel (+ SecureURL), AutoCheckEnabled (+ CheckInterval) and Calc Link
        // (+ Writer Link) are each a Go `RegistryMultiValue` with two SZ and two DWORD
        // entries, so each carries four targets across two policy paths. The other two
        // LibreOffice measures write a single sub-measure and keep two targets.
        var libre = MeasureCatalog.All.Where(m => m.Group == MeasureGroup.LibreOffice).ToList();
        Assert.Equal(5, libre.Count);

        var composite = libre.Where(m => m.Targets.Count == 4).ToList();
        var single = libre.Where(m => m.Targets.Count == 2).ToList();
        Assert.Equal(3, composite.Count);
        Assert.Equal(2, single.Count);

        Assert.All(composite, m =>
        {
            Assert.Equal(2, m.Targets.Select(t => t.Path).Distinct(StringComparer.Ordinal).Count());
            Assert.Equal(2, m.Targets.Count(t => t.ValueName == "Value" && t.Kind == "String"));
            Assert.Equal(2, m.Targets.Count(t => t.ValueName == "Final" && t.Kind == "Dword"));
        });

        var paths = string.Join("\n", composite.SelectMany(m => m.Targets).Select(t => t.Path));
        Assert.Contains(@"\SecureURL", paths, StringComparison.Ordinal);
        Assert.Contains(@"\CheckInterval", paths, StringComparison.Ordinal);
        Assert.Contains(@"org.openoffice.Office.Writer\Content\Update\Link", paths, StringComparison.Ordinal);
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
        // `Assert.Single` would pass for a filter that had migrated to another single measure.
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

        // These are value *names*; the path is a `%s` template shared by several sub-values.
        var allowDde = Assert.Single(dde.Targets, t => t.ValueName == "AllowDDE");
        Assert.Equal("Word", allowDde.AppFilter);
        Assert.Equal("14.0,15.0,16.0", allowDde.VersionFilter);

        var workbook = Assert.Single(dde.Targets, t => t.ValueName == "WorkbookLinkWarnings");
        Assert.Equal("Excel", workbook.AppFilter);
        Assert.Null(workbook.VersionFilter); // upstream uses the full standard list

        // `DontUpdateLinks` appears twice: once scoped to Word+Excel, once Word-only (Outlook).
        // Compared as a set — an allowlist's order carries no meaning, and pinning it would
        // make this test brittle for no benefit.
        static HashSet<string> Set(string? csv) => (csv ?? "")
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToHashSet(StringComparer.Ordinal);

        var dontUpdate = dde.Targets.Where(t => t.ValueName == "DontUpdateLinks").ToList();
        Assert.Equal(2, dontUpdate.Count);
        Assert.Contains(dontUpdate, t => Set(t.AppFilter).SetEquals(["Word", "Excel"]));
        Assert.Contains(dontUpdate, t => Set(t.AppFilter).SetEquals(["Word"]));
        Assert.All(dontUpdate, t => Assert.Equal("14.0,15.0,16.0", t.VersionFilter));

        // The one fixed DDE path is not versioned, so it is not narrowed either.
        var fixedPath = Assert.Single(dde.Targets, t => t.ValueName == "fNoCalclinksOnopen_90_1");
        Assert.Null(fixedPath.AppFilter);
        Assert.Null(fixedPath.VersionFilter);
        Assert.DoesNotContain("%s", fixedPath.Path);
    }

    [Fact]
    public void Every_filter_value_is_a_member_of_the_measures_product_universe()
    {
        // A typo in a filter would silently match nothing and quietly un-harden a product.
        static string[] Split(string? value) => (value ?? "")
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        Assert.All(MeasureCatalog.All, m =>
        {
            var apps = Split(m.Settings.GetValueOrDefault("Apps"));
            var versions = Split(m.Settings.GetValueOrDefault("OfficeVersions"));
            Assert.All(m.Targets.Where(t => t.AppFilter is not null),
                t => Assert.All(Split(t.AppFilter), a => Assert.Contains(a, apps)));
            Assert.All(m.Targets.Where(t => t.VersionFilter is not null),
                t => Assert.All(Split(t.VersionFilter), v => Assert.Contains(v, versions)));
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
