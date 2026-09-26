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

public class NonRegistryTests
{
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
        var measure = new RecallMeasure(registry); // Apply does not gate on availability; the engine does.
        measure.Apply(store);
        Assert.Equal(MeasureState.Taut, measure.Detect(store));
        measure.Restore(store);
        Assert.Equal(MeasureState.Slack, measure.Detect(store));
    }

    [Fact]
    public void Recall_records_the_actual_prior_state_not_a_sentinel() // spec defect #3
    {
        var registry = new InMemoryRegistry();
        var store = new SavedStateStore(registry, RegistryOptions.Default);
        using (var policy = registry.OpenKey(RegistryRoot.LocalMachine,
            @"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", true)!)
        {
            policy.SetDword("DisableAIDataAnalysis", 1); // Already disabled before we ran.
        }

        new RecallMeasure(registry).Apply(store);
        Assert.True(store.TryGetNonReg(new MeasureId("recall"), out var recorded));
        Assert.Equal("disabled", recorded);
    }

    [Fact]
    public void Recall_is_available_when_the_feature_marker_is_present()
    {
        var registry = new InMemoryRegistry();
        using (registry.OpenKey(RegistryRoot.LocalMachine,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsAI", true))
        {
        }

        Assert.True(new RecallMeasure(registry).IsAvailable());
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
    public void Asr_is_unavailable_when_no_defender_presence_is_detectable()
    {
        var registry = new InMemoryRegistry();
        Assert.False(new AsrRulesMeasure(registry).IsAvailable());
    }

    [Fact]
    public void Asr_is_available_when_defender_is_present_and_not_disabled()
    {
        var registry = new InMemoryRegistry();
        using (registry.OpenKey(RegistryRoot.LocalMachine, @"SOFTWARE\Microsoft\Windows Defender", true))
        {
        }

        Assert.True(new AsrRulesMeasure(registry).IsAvailable());
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
        Assert.Equal(14, state.Split(';').Length); // Upstream's ruleIDArray has 14 GUIDs; its 15-element action arrays are an upstream quirk.
    }

    [Fact]
    public void Asr_restore_reinstates_the_recorded_rules_and_removes_what_was_absent()
    {
        var registry = new InMemoryRegistry();
        var store = new SavedStateStore(registry, RegistryOptions.Default);
        var measure = new AsrRulesMeasure(registry);
        const string rulesPath = @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules";

        // One rule was already enabled before hardening, with a non-hardened action.
        using (var key = registry.OpenKey(RegistryRoot.LocalMachine, rulesPath, true)!)
        {
            key.SetDword("7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", 6);
        }

        measure.Apply(store);
        using (var check = registry.OpenKey(RegistryRoot.LocalMachine, rulesPath, false)!)
        {
            Assert.Equal(14, check.GetValueNames().Count); // All fourteen hardened.
        }

        measure.Restore(store);
        using (var after = registry.OpenKey(RegistryRoot.LocalMachine, rulesPath, false)!)
        {
            Assert.Single(after.GetValueNames());
            Assert.True(after.TryGetDword("7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", out var restored));
            Assert.Equal(6u, restored);
        }

        Assert.False(store.TryGetNonReg(measure.Id, out _));
    }

    [Fact]
    public void NonRegistry_handler_dispatches_by_id_and_reports_an_unknown_one_unavailable()
    {
        var registry = new InMemoryRegistry();
        using (registry.OpenKey(RegistryRoot.LocalMachine,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsAI", true)) // Feature marker: Recall exists on this build.
        {
        }

        var measures = new Dictionary<MeasureId, INonRegistryMeasure> { [new MeasureId("recall")] = new RecallMeasure(registry) };
        var handler = new NonRegistryHandler(measures);

        var recall = MeasureCatalog.Get(new MeasureId("recall"));
        Assert.Equal(MeasureState.Slack, handler.Detect(recall, [], registry));

        var asr = MeasureCatalog.Get(new MeasureId("WindowsAsrRules"));
        Assert.Equal(MeasureState.Unavailable, handler.Detect(asr, [], registry));
    }
}
