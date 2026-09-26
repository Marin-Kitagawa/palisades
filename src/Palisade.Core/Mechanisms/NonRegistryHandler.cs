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
/// A measure whose state is not a registry value under a catalog target: it changes
/// something else (a Windows optional feature, a Defender rule set) and records its original
/// state through the saved-state store's <c>SavedStateNonReg_</c> channel. The record is the
/// <em>actual</em> prior state, never a fixed sentinel (spec defect #3).
/// </summary>
public interface INonRegistryMeasure
{
    MeasureId Id { get; }

    /// <summary>The availability rules this measure can genuinely evaluate for itself.</summary>
    IReadOnlyList<AvailabilityRule> Availability { get; }

    bool IsAvailable();

    MeasureState Detect(SavedStateStore store);

    void Apply(SavedStateStore store);

    void Restore(SavedStateStore store);
}

/// <summary>
/// Dispatches the <c>NonRegistry</c> mechanism to the measure registered for the
/// descriptor's id. An id with no registered measure detects as <c>Unavailable</c> rather
/// than crashing; applying one is a programming error and throws.
/// </summary>
public sealed class NonRegistryHandler(IReadOnlyDictionary<MeasureId, INonRegistryMeasure> measures) : IMechanismHandler
{
    public Mechanism Mechanism => Mechanism.NonRegistry;

    public IReadOnlyList<ResolvedTarget> ResolveTargets(MeasureDescriptor descriptor, IVersionResolver versions) => [];

    public MeasureState Detect(MeasureDescriptor descriptor, IReadOnlyList<ResolvedTarget> targets, IRegistryKeyFactory registry)
    {
        if (!measures.TryGetValue(descriptor.Id, out var measure))
        {
            return MeasureState.Unavailable;
        }

        if (!measure.IsAvailable())
        {
            return MeasureState.Unavailable;
        }

        return measure.Detect(new SavedStateStore(registry, RegistryOptions.Default));
    }

    public void Apply(MeasureDescriptor descriptor, IReadOnlyList<ResolvedTarget> targets, IRegistryKeyFactory registry, SavedStateStore store)
    {
        Require(descriptor.Id).Apply(store);
    }

    public void Restore(MeasureDescriptor descriptor, IReadOnlyList<ResolvedTarget> targets, IRegistryKeyFactory registry, SavedStateStore store)
    {
        Require(descriptor.Id).Restore(store);
    }

    private INonRegistryMeasure Require(MeasureId id) =>
        measures.TryGetValue(id, out var measure)
            ? measure
            : throw new InvalidOperationException($"No non-registry measure is registered for '{id.Value}'.");
}
