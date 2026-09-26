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

/// <summary>
/// Orchestrates apply and restore across measures. It holds no elevation predicate — the
/// detector it holds already resolved elevation, and a second source of truth for the same
/// fact is how a measure gets applied without ever having been checked — and it does not
/// hold a planner: restore ordering comes from the static <see cref="RestorePlanner.Order"/>
/// called over the descriptors.
/// </summary>
public sealed class ApplyEngine(
    MeasureDetector detector,
    IReadOnlyDictionary<Mechanism, IMechanismHandler> handlers,
    IReadOnlyDictionary<MeasureId, INonRegistryMeasure> nonRegistry,
    SavedStateStore store)
{
    private readonly IRegistryKeyFactory _registry = detector.Registry;

    /// <summary>
    /// Hardens the requested measures in constraint order. A measure the detector reports
    /// <c>Unavailable</c> is skipped with that reason; one already <c>Taut</c> is
    /// <see cref="ApplyOutcome.AlreadyApplied"/>; one <c>Stressed</c> — its value set by
    /// Group Policy or another tool — is <em>never</em> overwritten, because that would
    /// silently discard a pre-existing value (spec defect #3); the report says so instead.
    /// </summary>
    public ApplyReport Apply(IReadOnlyCollection<MeasureId> ids)
    {
        var requested = ids.ToHashSet();
        var ordered = RestorePlanner.Order(MeasureCatalog.All.Where(descriptor => requested.Contains(descriptor.Id)));

        var results = new List<MeasureResult>();
        var warnings = new List<string>();
        var requiresRestart = false;

        foreach (var descriptor in ordered.Select(MeasureCatalog.Get))
        {
            try
            {
                var detection = detector.Detect(descriptor);
                if (detection.State == MeasureState.Unavailable)
                {
                    results.Add(new MeasureResult(descriptor.Id, ApplyOutcome.Unavailable, detection.Unavailable?.Reason));
                    continue;
                }

                if (detection.State == MeasureState.Taut)
                {
                    results.Add(new MeasureResult(descriptor.Id, ApplyOutcome.AlreadyApplied, null));
                    continue;
                }

                if (detection.State == MeasureState.Stressed)
                {
                    results.Add(new MeasureResult(
                        descriptor.Id,
                        ApplyOutcome.Failed,
                        $"'{descriptor.LongName}' is currently set by something other than Palisade, such as Group Policy or another tool. Its value was not overwritten."));
                    continue;
                }

                var handler = handlers[descriptor.Mechanism];
                var targets = handler.ResolveTargets(descriptor, new InstalledVersionResolver(_registry));
                handler.Apply(descriptor, targets, _registry, store);
                results.Add(new MeasureResult(descriptor.Id, ApplyOutcome.Applied, null));
                requiresRestart = true;
            }
            catch (Exception error) when (error is not OutOfMemoryException and not StackOverflowException)
            {
                results.Add(new MeasureResult(descriptor.Id, ApplyOutcome.Failed, error.Message));
            }
        }

        return new ApplyReport(results, warnings, requiresRestart);
    }

    /// <summary>
    /// Puts every measure with a recorded original back, in restore order, then removes the
    /// saved state the way <c>utils.go:159</c> removes the whole key once a restore ends.
    /// Saved entries no measure claims — for a version that no longer resolves, or written
    /// by a Go release this build does not know — are restored by the orphan pass before the
    /// key is removed, so nothing restorable is lost.
    /// </summary>
    public ApplyReport RestoreAll()
    {
        var initialEntries = store.ReadAll();
        var warnings = initialEntries
            .Where(entry => entry.Warning is not null)
            .Select(entry => entry.Warning!)
            .ToList();

        var results = new List<MeasureResult>();
        var requiresRestart = false;

        foreach (var descriptor in RestorePlanner.Order(MeasureCatalog.All).Select(MeasureCatalog.Get))
        {
            try
            {
                if (descriptor.Mechanism == Mechanism.NonRegistry)
                {
                    if (!nonRegistry.TryGetValue(descriptor.Id, out var measure) || !store.TryGetNonReg(descriptor.Id, out _))
                    {
                        results.Add(new MeasureResult(descriptor.Id, ApplyOutcome.NotRestored, null));
                        continue;
                    }

                    measure.Restore(store);
                    results.Add(new MeasureResult(descriptor.Id, ApplyOutcome.Restored, null));
                    requiresRestart = true;
                    continue;
                }

                var handler = handlers[descriptor.Mechanism];
                var targets = handler.ResolveTargets(descriptor, new InstalledVersionResolver(_registry));
                if (!HasSavedEntry(targets))
                {
                    results.Add(new MeasureResult(descriptor.Id, ApplyOutcome.NotRestored, null));
                    continue;
                }

                handler.Restore(descriptor, targets, _registry, store);
                results.Add(new MeasureResult(descriptor.Id, ApplyOutcome.Restored, null));
                requiresRestart = true;
            }
            catch (Exception error) when (error is not OutOfMemoryException and not StackOverflowException)
            {
                results.Add(new MeasureResult(descriptor.Id, ApplyOutcome.Failed, error.Message));
            }
        }

        RestoreOrphanEntries();

        // utils.go:159 via markStatus(false): the whole key goes once a restore ends. The
        // records it held are spent; the Go tool deletes it unconditionally too.
        store.Clear();

        return new ApplyReport(results, warnings, requiresRestart);
    }

    /// <summary>
    /// The Go tool's "harden again (all default settings)": everything is restored to its
    /// original first — which is what lifts the non-default measures the user opted into —
    /// and then the default set is applied, so the machine ends in a fully determined state
    /// after a version upgrade.
    /// </summary>
    public ApplyReport ReapplyDefaults()
    {
        var restored = RestoreAll();
        var applied = Apply(MeasureCatalog.All.Where(descriptor => descriptor.HardenByDefault).Select(descriptor => descriptor.Id).ToList());
        return new ApplyReport(
            restored.Results.Concat(applied.Results).ToList(),
            restored.Warnings.Concat(applied.Warnings).ToList(),
            restored.RequiresRestart || applied.RequiresRestart);
    }

    private bool HasSavedEntry(IReadOnlyList<ResolvedTarget> targets)
    {
        using var saved = SavedStateSnapshot.Load(_registry);
        return targets.Any(target => saved.HasEntry(target));
    }

    /// <summary>
    /// Restores every saved entry no measure claimed, which is what Go's
    /// <c>restoreSavedRegistryKeys</c> does for the whole key: the entry is probed read-only
    /// first and skipped when its key is gone, because a restore never creates a key.
    /// </summary>
    private void RestoreOrphanEntries()
    {
        using var saved = SavedStateSnapshot.Load(_registry);
        foreach (var (target, entry) in saved.All())
        {
            // The probe read-only first: a restore never creates a key, so an entry whose
            // key has disappeared is skipped, not written into existence.
            using (var probe = _registry.OpenKey(entry.Root, entry.KeyPath, writable: false))
            {
                if (probe is null)
                {
                    continue;
                }
            }

            switch (entry.Kind)
            {
                case SavedStateKind.Dword:
                case SavedStateKind.LegacyDword:
                    if (saved.TryReadOriginalDword(target, out var dword))
                    {
                        using (var key = _registry.OpenKey(entry.Root, entry.KeyPath, writable: true))
                        {
                            key?.SetDword(entry.ValueName, dword);
                        }
                    }

                    break;
                case SavedStateKind.String:
                    if (saved.TryReadOriginalString(target, out var text))
                    {
                        using (var key = _registry.OpenKey(entry.Root, entry.KeyPath, writable: true))
                        {
                            key?.SetString(entry.ValueName, text);
                        }
                    }

                    break;
                case SavedStateKind.NotExisting:
                    using (var key = _registry.OpenKey(entry.Root, entry.KeyPath, writable: true))
                    {
                        key?.DeleteValue(entry.ValueName);
                    }

                    break;
                case SavedStateKind.LegacyString:
                    break;
            }
        }
    }
}
