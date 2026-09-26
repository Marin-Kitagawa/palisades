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
using Palisade.Core.Registry;

namespace Palisade.Core.Mechanisms;

/// <summary>
/// The Recall measure. The <see cref="MeasureId">id</see> is the lowercase
/// <c>recall</c> — <c>recall_feature.go:50</c> sets <c>featureName = "recall"</c>, so the
/// Go tool persists <c>SavedStateNonReg_recall</c> and a capitalised id would silently fail
/// to find it. The Windows optional feature name <c>Recall</c> passed to the PowerShell
/// cmdlet (<c>recall_feature.go:67</c>) is a different value and is not the id.
/// </summary>
/// <remarks>
/// Registry-only shape, recorded as a deliberate divergence: upstream disables and removes
/// the optional feature with
/// <c>Disable-WindowsOptionalFeature -Online -FeatureName "Recall" -Remove</c>
/// (<c>recall_feature.go:67</c>), which needs PowerShell and cannot run headless in tests.
/// Palisade hardens the documented Windows AI policy instead —
/// <c>HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\DisableAIDataAnalysis = 1</c> —
/// which disables Recall on every build that ships it, is a plain registry write the whole
/// engine can apply, detect and restore, and keeps the saved-state channel byte-identical:
/// the record is <c>enabled</c> or <c>disabled</c>, and restore reinstates only when the
/// recorded prior state was <c>enabled</c>, exactly as <c>recall_feature.go:65-72</c> does.
/// </remarks>
public sealed class RecallMeasure(IRegistryKeyFactory registry) : INonRegistryMeasure
{
    public const string MeasureIdValue = "recall";

    private const string FeaturePresencePath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsAI";
    private const string PolicyPath = @"SOFTWARE\Policies\Microsoft\Windows\WindowsAI";
    private const string PolicyValueName = "DisableAIDataAnalysis";
    private const string EnabledState = "enabled";
    private const string DisabledState = "disabled";

    public MeasureId Id => new(MeasureIdValue);

    public IReadOnlyList<AvailabilityRule> Availability { get; } =
    [
        new(
            "windows_feature_absent",
            new Dictionary<string, string>(),
            "Recall is not available in this build of Windows, so there is nothing for this measure to harden."),
    ];

    /// <summary>
    /// The feature's presence marker: the Windows AI settings key the build writes when the
    /// capability exists. Absent from the build means there is nothing to harden, which is
    /// <c>unavailable</c>, not <c>slack</c> (spec §6.3, constraint 4).
    /// </summary>
    public bool IsAvailable() =>
        registry.OpenKey(RegistryRoot.LocalMachine, FeaturePresencePath, writable: false) is not null;

    public MeasureState Detect(SavedStateStore store)
    {
        var hardenedNow = false;
        using (var policy = registry.OpenKey(RegistryRoot.LocalMachine, PolicyPath, writable: false))
        {
            hardenedNow = policy is not null && policy.TryGetDword(PolicyValueName, out var value) && value == 1;
        }

        if (!hardenedNow)
        {
            return MeasureState.Slack;
        }

        return store.TryGetNonReg(Id, out _) ? MeasureState.Taut : MeasureState.Stressed;
    }

    public void Apply(SavedStateStore store)
    {
        // The record is the actual prior state, never a sentinel (recall_feature.go:61-65).
        store.SaveNonReg(Id, IsHardenedNow() ? DisabledState : EnabledState);

        using var policy = registry.OpenKey(RegistryRoot.LocalMachine, PolicyPath, writable: true)
            ?? throw new InvalidOperationException($"The key 'LOCAL_MACHINE\\{PolicyPath}' could not be created or opened for writing.");
        policy.SetDword(PolicyValueName, 1);
    }

    public void Restore(SavedStateStore store)
    {
        if (!store.TryGetNonReg(Id, out var saved))
        {
            return; // No saved state found, so nothing is restored (recall_feature.go:69-73).
        }

        if (saved != EnabledState)
        {
            // Was not enabled before hardening, so nothing is restored and the record stays,
            // exactly as upstream leaves it (recall_feature.go:75-78).
            return;
        }

        using (var probe = registry.OpenKey(RegistryRoot.LocalMachine, PolicyPath, writable: false))
        {
            if (probe is not null)
            {
                using var policy = registry.OpenKey(RegistryRoot.LocalMachine, PolicyPath, writable: true)!;
                policy.DeleteValue(PolicyValueName);
            }
        }

        store.DeleteNonReg(Id);
    }

    private bool IsHardenedNow()
    {
        using var policy = registry.OpenKey(RegistryRoot.LocalMachine, PolicyPath, writable: false);
        return policy is not null && policy.TryGetDword(PolicyValueName, out var value) && value == 1;
    }
}
