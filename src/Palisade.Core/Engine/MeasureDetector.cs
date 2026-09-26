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
using Palisade.Core.Mechanisms;
using Palisade.Core.Registry;

namespace Palisade.Core.Engine;

/// <summary>Why a measure is unavailable, in words the UI renders verbatim.</summary>
/// <param name="Reason">A full sentence naming the measure and the blocker.</param>
/// <param name="BlockedBy">The ids that caused the block, when the blocker is another measure.</param>
public sealed record AvailabilityOutcome(string Reason, IReadOnlyList<string> BlockedBy);

/// <summary>One measure's derived state, with the reason when it is unavailable.</summary>
public sealed record DetectionResult(
    MeasureId Id,
    MeasureState State,
    AvailabilityOutcome? Unavailable,
    IReadOnlyList<MeasureId> ConstrainedBy);

/// <summary>
/// Derives the four-state model for every measure. Elevation is resolved once, here — an
/// engine that took a second elevation predicate could apply a measure that was never
/// checked. Availability is evidence-based: a rule fails only when there is positive
/// evidence of the blocker, because upstream checks none of these conditions before writing
/// (<c>office.go</c> and <c>adobe.go</c> write the standard lists unconditionally), and a
/// rule invented into a hard blocker would make the tool refuse machines upstream operates
/// on. The non-registry measures are the exception: their availability is genuinely
/// detectable, and their own <see cref="INonRegistryMeasure.IsAvailable"/> decides.
/// </summary>
public sealed class MeasureDetector(
    IReadOnlyDictionary<Mechanism, IMechanismHandler> handlers,
    IReadOnlyDictionary<MeasureId, INonRegistryMeasure> nonRegistry,
    Func<bool> isElevated,
    IRegistryKeyFactory registry)
{
    private readonly IRegistryKeyFactory _registry = registry;

    /// <summary>
    /// The hive the detector dispatches against. Exposed so the apply engine can resolve
    /// targets without a second registry parameter — there is one hive per engine and this
    /// is it.
    /// </summary>
    public IRegistryKeyFactory Registry => _registry;

    public IReadOnlyList<DetectionResult> DetectAll() =>
        MeasureCatalog.All.Select(Detect).ToList();

    public DetectionResult Detect(MeasureDescriptor descriptor)
    {
        var constrainedBy = descriptor.ConstrainedBy.Select(constraint => constraint.Target).ToList();

        if (descriptor.RequiresElevation && !isElevated())
        {
            return new DetectionResult(
                descriptor.Id,
                MeasureState.Unavailable,
                new AvailabilityOutcome(ElevationReason(descriptor), []),
                constrainedBy);
        }

        if (descriptor.Mechanism == Mechanism.NonRegistry)
        {
            if (!nonRegistry.TryGetValue(descriptor.Id, out var measure))
            {
                return new DetectionResult(
                    descriptor.Id,
                    MeasureState.Unavailable,
                    new AvailabilityOutcome($"No non-registry measure is registered for '{descriptor.Id.Value}', so its state cannot be changed on this machine.", []),
                    constrainedBy);
            }

            if (!measure.IsAvailable())
            {
                return new DetectionResult(
                    descriptor.Id,
                    MeasureState.Unavailable,
                    new AvailabilityOutcome(FirstReason(descriptor), []),
                    constrainedBy);
            }
        }

        foreach (var rule in descriptor.Availability)
        {
            if (!IsSatisfied(rule))
            {
                return new DetectionResult(
                    descriptor.Id,
                    MeasureState.Unavailable,
                    new AvailabilityOutcome(rule.Reason, []),
                    constrainedBy);
            }
        }

        if (!handlers.TryGetValue(descriptor.Mechanism, out var handler))
        {
            return new DetectionResult(
                descriptor.Id,
                MeasureState.Unavailable,
                new AvailabilityOutcome($"No handler is registered for the mechanism '{descriptor.Mechanism}' of '{descriptor.Id.Value}'.", []),
                constrainedBy);
        }

        var targets = handler.ResolveTargets(descriptor, new InstalledVersionResolver(_registry));
        var state = handler.Detect(descriptor, targets, _registry);
        return new DetectionResult(
            descriptor.Id,
            state,
            state == MeasureState.Unavailable
                ? new AvailabilityOutcome(FirstReason(descriptor), [])
                : null,
            constrainedBy);
    }

    /// <summary>
    /// The elevation reason names the measure (spec defect #11): the UI states exactly what
    /// was lost, per measure, not one blanket sentence.
    /// </summary>
    private static string ElevationReason(MeasureDescriptor descriptor) =>
        $"'{descriptor.LongName}' requires administrator rights, which were not granted, so it cannot be applied on this machine.";

    private static string FirstReason(MeasureDescriptor descriptor) =>
        descriptor.Availability.Count > 0
            ? descriptor.Availability[0].Reason
            : $"The state of '{descriptor.Id.Value}' could not be resolved on this machine.";

    /// <summary>
    /// A rule is "satisfied" when nothing blocks the measure. Only
    /// <c>windows_defender_disabled</c> has positive evidence to check: an explicit
    /// <c>DisableAntiSpyware</c> policy, or no Defender presence at all. The other kinds —
    /// <c>product_not_installed</c>, <c>windows_feature_absent</c>,
    /// <c>dde_not_supported</c> — are advisory metadata for the UI on registry-family
    /// measures: upstream probes nothing, and neither does the detector; a measure on a
    /// machine without the product simply writes keys that were never there, which is what
    /// the Go tool does.
    /// </summary>
    private bool IsSatisfied(AvailabilityRule rule) => rule.Kind switch
    {
        "windows_defender_disabled" => DefenderAvailable(),
        _ => true,
    };

    private bool DefenderAvailable()
    {
        using (var policy = _registry.OpenKey(RegistryRoot.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender", writable: false))
        {
            if (policy is not null && policy.TryGetDword("DisableAntiSpyware", out var disabled) && disabled == 1)
            {
                return false;
            }
        }

        using (var presence = _registry.OpenKey(RegistryRoot.LocalMachine, @"SOFTWARE\Microsoft\Windows Defender", writable: false))
        {
            return presence is not null;
        }
    }
}
