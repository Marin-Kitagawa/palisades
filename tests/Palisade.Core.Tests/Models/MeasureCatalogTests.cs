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
        // libreoffice.go:44-51 writes `SecureURL` to the empty string; libreoffice.go:62-69
        // then clears its `Final` flag to 0 so the user may still change it. The empty
        // hardened value is what rules out encoding targets inside a settings string.
        var macro = MeasureCatalog.All.Single(m => m.Id == new MeasureId("LibreOfficeMacroSecurity"));
        Assert.Contains(macro.Targets, t =>
            t.Path.EndsWith(@"\SecureURL", StringComparison.Ordinal)
            && t.ValueName == "Value"
            && t.Kind == "String"
            && t.HardenedValue == string.Empty);
        Assert.Contains(macro.Targets, t =>
            t.Path.EndsWith(@"\SecureURL", StringComparison.Ordinal)
            && t.ValueName == "Final"
            && t.Kind == "Dword"
            && t.HardenedValue == "0");
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
