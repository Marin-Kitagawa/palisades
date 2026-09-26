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

using Palisade.Core.Mechanisms;
using Palisade.Core.Models;
using Palisade.Core.Registry;

namespace Palisade.Core.Tests.Mechanisms;

public class VersionedPathTests
{
    [Fact]
    public void Expands_one_target_per_installed_version_and_app()
    {
        var resolver = new StubVersionResolver(officeVersions: new[] { "16.0" }, adobeVersions: Array.Empty<string>());
        var descriptor = MeasureCatalog.Get(new MeasureId("OfficeMacros"));
        var result = new VersionedPathHandler().Resolve(descriptor, resolver);
        Assert.Equal(new[] { "Excel", "PowerPoint", "Word" }.Length, result.Targets.Count);
        Assert.All(result.Targets, t => Assert.Contains(@"16.0", t.KeyPath, StringComparison.Ordinal));
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
        var registry = new InMemoryRegistry();
        var resolver = new StubVersionResolver(officeVersions: Array.Empty<string>(), adobeVersions: Array.Empty<string>());
        var descriptor = MeasureCatalog.Get(new MeasureId("OfficeMacros"));
        var handler = new VersionedPathHandler();
        var result = handler.Resolve(descriptor, resolver);
        Assert.Equal(MeasureState.Unavailable, handler.Detect(descriptor, result.Targets, registry));
    }

    [Fact]
    public void A_fixed_path_resolves_to_exactly_one_target_even_on_a_versioned_measure()
    {
        // `fNoCalclinksOnopen_90_1` sits on a hardcoded 12.0 path with no `%s`
        // (office.go:286-292). Expanding it over the version list would write once per
        // version to the same key — eight identical writes on the DDE measure.
        var resolver = new StubVersionResolver(officeVersions: new[] { "12.0", "14.0", "15.0", "16.0" }, adobeVersions: Array.Empty<string>());
        var descriptor = MeasureCatalog.Get(new MeasureId("OfficeDde"));
        var result = new VersionedPathHandler().Resolve(descriptor, resolver);

        var fixedTargets = result.Targets.Where(t =>
            t.KeyPath.Contains("vpref", StringComparison.Ordinal)).ToList();
        Assert.Single(fixedTargets);
        Assert.DoesNotContain("%s", fixedTargets[0].KeyPath, StringComparison.Ordinal);
        Assert.Equal("fNoCalclinksOnopen_90_1", fixedTargets[0].ValueName);
    }

    [Fact]
    public void DDE_resolves_to_exactly_the_17_values_upstream_writes()
    {
        // The narrowing arithmetic, end to end: 3 AllowDDE + 4 WorkbookLinkWarnings
        // + 6 DontUpdateLinks(Options) + 3 DontUpdateLinks(WordMail) + 1 fixed = 17
        // (office.go:154-292).
        var resolver = new StubVersionResolver(
            officeVersions: new[] { "12.0", "14.0", "15.0", "16.0" },
            adobeVersions: Array.Empty<string>());
        var descriptor = MeasureCatalog.Get(new MeasureId("OfficeDde"));
        var result = new VersionedPathHandler().Resolve(descriptor, resolver);

        Assert.Empty(result.Failures);
        Assert.Equal(17, result.Targets.Count);
        Assert.Equal(3, result.Targets.Count(t => t.ValueName == "AllowDDE"));
        Assert.Equal(4, result.Targets.Count(t => t.ValueName == "WorkbookLinkWarnings"));
        Assert.Equal(6, result.Targets.Count(t => t.ValueName == "DontUpdateLinks" && t.KeyPath.EndsWith("Options", StringComparison.Ordinal)));
        Assert.Equal(3, result.Targets.Count(t => t.ValueName == "DontUpdateLinks" && t.KeyPath.EndsWith("WordMail", StringComparison.Ordinal)));
        Assert.Single(result.Targets, t => t.ValueName == "fNoCalclinksOnopen_90_1");
    }

    [Fact]
    public void Version_filters_narrow_the_universe_without_reordering_it()
    {
        var resolver = new StubVersionResolver(
            officeVersions: new[] { "12.0", "14.0", "15.0", "16.0" },
            adobeVersions: Array.Empty<string>());
        var descriptor = MeasureCatalog.Get(new MeasureId("OfficeDde"));
        var result = new VersionedPathHandler().Resolve(descriptor, resolver);

        // AllowDDE is Word-only on 14-16, so 12.0 never appears under it.
        Assert.All(
            result.Targets.Where(t => t.ValueName == "AllowDDE"),
            t => Assert.DoesNotContain("12.0", t.KeyPath, StringComparison.Ordinal));
        // WorkbookLinkWarnings has no version filter, so 12.0 does appear.
        Assert.Contains(
            result.Targets.Where(t => t.ValueName == "WorkbookLinkWarnings"),
            t => t.KeyPath.Contains("12.0", StringComparison.Ordinal));
    }

    [Fact]
    public void Adobe_measures_expand_over_the_discovered_adobe_versions()
    {
        var resolver = new StubVersionResolver(
            officeVersions: Array.Empty<string>(),
            adobeVersions: new[] { "DC", "2020", "XI" });
        var descriptor = MeasureCatalog.Get(new MeasureId("AdobeEnhancedSecurity"));
        var result = new VersionedPathHandler().Resolve(descriptor, resolver);

        // Two targets per version, and no app substitution anywhere.
        Assert.Equal(6, result.Targets.Count);
        Assert.All(result.Targets, t => Assert.Contains("TrustManager", t.KeyPath, StringComparison.Ordinal));
        Assert.Equal(3, result.Targets.Count(t => t.ValueName == "bEnhancedSecurityInBrowser"));
        Assert.Equal(3, result.Targets.Count(t => t.ValueName == "bEnhancedSecurityStandalone"));
    }

    [Fact]
    public void Detect_apply_and_restore_survive_a_full_cycle_on_a_discovered_version()
    {
        var registry = new InMemoryRegistry();
        var store = new SavedStateStore(registry, RegistryOptions.Default);
        var descriptor = MeasureCatalog.Get(new MeasureId("OfficeMacros"));
        var handler = new VersionedPathHandler();
        var resolver = new StubVersionResolver(officeVersions: new[] { "16.0" }, adobeVersions: Array.Empty<string>());

        var targets = handler.ResolveTargets(descriptor, resolver);
        Assert.Equal(MeasureState.Slack, handler.Detect(descriptor, targets, registry));
        handler.Apply(descriptor, targets, registry, store);
        Assert.Equal(MeasureState.Taut, handler.Detect(descriptor, targets, registry));
        handler.Restore(descriptor, targets, registry, store);
        Assert.Equal(MeasureState.Slack, handler.Detect(descriptor, targets, registry));
    }
}
