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

using Palisade.Core.Engine;
using Palisade.Core.Models;
using Palisade.Core.Registry;

namespace Palisade.Core.Tests.Engine;

public class ApplyEngineTests
{
    [Fact]
    public void Apply_is_idempotent() // spec §12.1.9
    {
        var engine = EngineFactory.BuildEngine();
        var ids = MeasureCatalog.All.Where(m => m.HardenByDefault && !m.RequiresElevation)
            .Select(m => m.Id).ToList();
        engine.Apply(ids);
        var second = engine.Apply(ids);
        Assert.All(second.Results, r => Assert.Equal(ApplyOutcome.AlreadyApplied, r.Outcome));
    }

    [Fact]
    public void Restore_is_idempotent()
    {
        var engine = EngineFactory.BuildEngine();
        engine.RestoreAll();
        var second = engine.RestoreAll();
        Assert.All(second.Results, r => Assert.Equal(ApplyOutcome.NotRestored, r.Outcome));
    }

    [Fact]
    public void Reapply_defaults_leaves_no_measure_in_a_stressed_state()
    {
        var engine = EngineFactory.BuildEngine();
        var report = engine.ReapplyDefaults();
        Assert.DoesNotContain(report.Results, r => r.Outcome == ApplyOutcome.Failed);
        var after = engine.Detect();
        Assert.DoesNotContain(after, r => r.Id.Value == "recall" && r.State == MeasureState.Stressed);
    }

    [Fact]
    public void Restore_all_returns_every_applied_measure_to_slack()
    {
        var engine = EngineFactory.BuildEngine();
        engine.Apply(MeasureCatalog.All.Where(m => !m.RequiresElevation).Select(m => m.Id).ToList());
        engine.RestoreAll();
        var after = engine.Detect().Where(r => !r.Id.Value.StartsWith("LibreOffice", StringComparison.Ordinal)).ToList();
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
            key.SetDword(@"SavedStateNew_NOPE\Software\Foo____Bar", 1);
        }

        var engine = new PalisadeEngine(registry, RegistryOptions.Default, new AppPaths("."), () => true);
        var report = engine.RestoreAll();
        Assert.NotEmpty(report.Warnings);
    }

    [Fact]
    public void Apply_skips_a_stressed_measure_instead_of_overwriting_it() // spec defect #3
    {
        var registry = new InMemoryRegistry();
        using (var key = registry.OpenKey(RegistryRoot.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", true)!)
        {
            key.SetDword("RunAsPPL", 1); // Group Policy, not Palisade.
        }

        var engine = EngineFactory.BuildEngine(registry, isElevated: true);
        var report = engine.Apply([new MeasureId("Lsa")]);

        var result = Assert.Single(report.Results);
        Assert.Equal(ApplyOutcome.Failed, result.Outcome);
        Assert.Contains("not overwritten", result.Detail, StringComparison.Ordinal);

        using (var check = registry.OpenKey(RegistryRoot.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", false)!)
        {
            Assert.True(check.TryGetDword("RunAsPPL", out var value));
            Assert.Equal(1u, value); // The pre-existing value, untouched.
        }

        Assert.False(registry
            .OpenKey(RegistryRoot.CurrentUser, RegistryOptions.DefaultSavedStateKeyPath, false)?
            .GetValueNames()
            .Any() ?? false); // Nothing was recorded, so nothing can be wrongly restored later.
    }

    [Fact]
    public void Apply_and_restore_report_unavailable_measures_with_the_detectors_reason()
    {
        var engine = EngineFactory.BuildEngine(registry: null, isElevated: true);
        var report = engine.Apply([new MeasureId("recall")]); // Absent from the fake build.
        var result = Assert.Single(report.Results);
        Assert.Equal(ApplyOutcome.Unavailable, result.Outcome);
        Assert.False(string.IsNullOrWhiteSpace(result.Detail));
    }

    [Fact]
    public void Restored_machine_reports_no_saved_state_afterwards()
    {
        var engine = EngineFactory.BuildEngine(isElevated: true);
        engine.Apply([new MeasureId("Lsa")]);
        Assert.True(engine.Store.ReadAll().Count > 0);

        engine.RestoreAll();

        Assert.Empty(engine.Store.ReadAll());
    }
}
