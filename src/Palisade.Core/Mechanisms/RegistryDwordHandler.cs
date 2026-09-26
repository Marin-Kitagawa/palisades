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

using System.Globalization;
using Palisade.Core.Models;
using Palisade.Core.Registry;

namespace Palisade.Core.Mechanisms;

/// <summary>
/// The registry-value machinery shared by the <c>RegistryDword</c>, <c>RegistryString</c>
/// and <c>VersionedPath</c> mechanisms. Public because the four public handlers derive from
/// it; nothing outside this assembly has business with it directly. Targets are dispatched
/// on their own <see cref="ResolvedTarget.Kind"/>, not on the descriptor's mechanism: a
/// <c>RegistryString</c> measure (the LibreOffice family) legitimately carries
/// <c>REG_DWORD</c> <c>Final</c> targets alongside its <c>REG_SZ</c> <c>Value</c> targets.
/// </summary>
public abstract class RegistryValueHandlerBase : IMechanismHandler
{
    public abstract Mechanism Mechanism { get; }

    public virtual IReadOnlyList<ResolvedTarget> ResolveTargets(MeasureDescriptor descriptor, IVersionResolver versions) =>
        descriptor.Targets
            .Select(target => new ResolvedTarget(
                target.Root, target.Path, target.ValueName, MultiValueName: null, target.Kind, target.HardenedValue))
            .ToList();

    public virtual MeasureState Detect(MeasureDescriptor descriptor, IReadOnlyList<ResolvedTarget> targets, IRegistryKeyFactory registry)
    {
        using var saved = SavedStateSnapshot.Load(registry);
        return Combine(targets.Select(target => DetectTarget(target, registry, saved)).ToList());
    }

    public virtual void Apply(MeasureDescriptor descriptor, IReadOnlyList<ResolvedTarget> targets, IRegistryKeyFactory registry, SavedStateStore store)
    {
        foreach (var target in targets)
        {
            ApplyTarget(target, registry, store);
        }
    }

    public virtual void Restore(MeasureDescriptor descriptor, IReadOnlyList<ResolvedTarget> targets, IRegistryKeyFactory registry, SavedStateStore store)
    {
        using var saved = SavedStateSnapshot.Load(registry);
        var restored = new List<SavedStateEntry>();
        foreach (var target in targets)
        {
            if (saved.TryGetEntry(target, out var entry) && RestoreTarget(target, entry, registry, saved))
            {
                restored.Add(entry);
            }
        }

        // Consume the records that were actually restored, so a second measure sharing one
        // record (the DisallowRun flag does) cannot re-apply it after the first restore
        // already put the machine back. Records that could not be restored stay.
        saved.Consume(restored);
    }

    /// <summary>
    /// The four-state derivation for one target. <c>Taut</c> only when the value equals the
    /// hardened value <em>and</em> a saved entry records that Palisade put it there — a value
    /// that equals the hardened value without a record was set by Group Policy or another
    /// tool, and that is <c>Stressed</c>, never <c>Taut</c>. <c>Slack</c> when the key or the
    /// value is absent, or when the value equals the recorded original. Anything else is
    /// <c>Stressed</c>.
    /// </summary>
    private static MeasureState DetectTarget(ResolvedTarget target, IRegistryKeyFactory registry, SavedStateSnapshot saved)
    {
        using var key = registry.OpenKey(target.Root, target.KeyPath, writable: false);
        if (key is null)
        {
            return MeasureState.Slack;
        }

        if (target.Kind == "Dword")
        {
            if (!key.TryGetDword(target.ValueName, out var current))
            {
                return MeasureState.Slack;
            }

            if (current == ParseDword(target))
            {
                return saved.HasEntry(target) ? MeasureState.Taut : MeasureState.Stressed;
            }

            if (saved.TryGetOriginalDword(target, out var original) && original == current)
            {
                return MeasureState.Slack;
            }

            return saved.HasEntry(target) ? MeasureState.Stressed : MeasureState.Slack;
        }

        if (target.Kind == "String")
        {
            if (!key.TryGetString(target.ValueName, out var current))
            {
                return MeasureState.Slack;
            }

            if (current == target.HardenedValue)
            {
                return saved.HasEntry(target) ? MeasureState.Taut : MeasureState.Stressed;
            }

            if (saved.TryGetOriginalString(target, out var original) && original == current)
            {
                return MeasureState.Slack;
            }

            return saved.HasEntry(target) ? MeasureState.Stressed : MeasureState.Slack;
        }

        // "MultiString" is carried by no measure and no Go call site writes one; a descriptor
        // that grew one has to say so here rather than be silently misdetected.
        throw new NotSupportedException($"Target '{target.KeyPath}\\{target.ValueName}' declares kind '{target.Kind}', which no measure carries.");
    }

    private static void ApplyTarget(ResolvedTarget target, IRegistryKeyFactory registry, SavedStateStore store)
    {
        // Hardening may create the key — Go's CreateKey at every harden site does.
        using var key = registry.OpenKey(target.Root, target.KeyPath, writable: true)
            ?? throw new InvalidOperationException($"The key '{target.Root}\\{target.KeyPath}' could not be created or opened for writing.");

        if (target.Kind == "Dword")
        {
            // Record the current value, or that there was none, before overwriting it.
            // The hardened value comes from the typed target, never from Settings.
            if (key.TryGetDword(target.ValueName, out var current))
            {
                store.SaveDword(target.Root, target.KeyPath, target.ValueName, current);
            }
            else
            {
                store.SaveNotExisting(target.Root, target.KeyPath, target.ValueName);
            }

            key.SetDword(target.ValueName, ParseDword(target));
            return;
        }

        if (target.Kind == "String")
        {
            if (key.TryGetString(target.ValueName, out var current))
            {
                store.SaveString(target.Root, target.KeyPath, target.ValueName, current);
            }
            else
            {
                store.SaveNotExisting(target.Root, target.KeyPath, target.ValueName);
            }

            key.SetString(target.ValueName, target.HardenedValue);
            return;
        }

        throw new NotSupportedException($"Target '{target.KeyPath}\\{target.ValueName}' declares kind '{target.Kind}', which no measure carries.");
    }

    /// <summary>
    /// Restores one target from its recorded entry, and reports whether it was actually
    /// restored. The key is probed read-only first: a restore never creates a key, because
    /// Go's restore opens and skips on failure while only harden ever creates
    /// (Global Constraint 6).
    /// </summary>
    private static bool RestoreTarget(ResolvedTarget target, SavedStateEntry entry, IRegistryKeyFactory registry, SavedStateSnapshot saved)
    {
        using (var probe = registry.OpenKey(entry.Root, entry.KeyPath, writable: false))
        {
            if (probe is null)
            {
                return false;
            }
        }

        switch (entry.Kind)
        {
            case SavedStateKind.Dword:
            case SavedStateKind.LegacyDword:
                {
                    if (!saved.TryReadOriginalDword(entry, out var dword))
                    {
                        return false;
                    }

                    using (var key = registry.OpenKey(entry.Root, entry.KeyPath, writable: true))
                    {
                        key?.SetDword(target.ValueName, dword);
                    }

                    return true;
                }
            case SavedStateKind.String:
                {
                    if (!saved.TryReadOriginalString(entry, out var text))
                    {
                        return false;
                    }

                    using (var key = registry.OpenKey(entry.Root, entry.KeyPath, writable: true))
                    {
                        key?.SetString(target.ValueName, text);
                    }

                    return true;
                }
            case SavedStateKind.NotExisting:
                {
                    // What was recorded is that the value did not exist. If the user or another
                    // tool created it since, restore deletes it — that is what was recorded.
                    using (var key = registry.OpenKey(entry.Root, entry.KeyPath, writable: true))
                    {
                        key?.DeleteValue(target.ValueName);
                    }

                    return true;
                }
            case SavedStateKind.LegacyString:
                // Unreachable: no legacy string entry can exist (registry_utils.go reads the
                // legacy form only as an integer). Handled explicitly so a switch over
                // SavedStateKind never falls into an arm by accident.
                return false;
            default:
                return false;
        }
    }

    /// <summary>
    /// A target list is <c>Taut</c> only when every member is; it is <c>Stressed</c> when any
    /// member is and none is <c>Taut</c>; otherwise <c>Slack</c>. A single-target list
    /// therefore reduces to that target's own state.
    /// </summary>
    internal static MeasureState Combine(IReadOnlyList<MeasureState> states)
    {
        if (states.Count == 0 || states.All(state => state == MeasureState.Slack))
        {
            return MeasureState.Slack;
        }

        if (states.All(state => state == MeasureState.Taut))
        {
            return MeasureState.Taut;
        }

        if (states.Any(state => state == MeasureState.Stressed) && !states.Any(state => state == MeasureState.Taut))
        {
            return MeasureState.Stressed;
        }

        return MeasureState.Slack;
    }

    internal static uint ParseDword(ResolvedTarget target) =>
        uint.Parse(target.HardenedValue, CultureInfo.InvariantCulture);
}

/// <summary>
/// The <c>RegistryDword</c> mechanism. Every current target of every measure on this
/// mechanism is a <c>REG_DWORD</c>, but the handler still dispatches per target kind, so a
/// future mixed-kind descriptor cannot silently write the wrong registry type.
/// </summary>
public sealed class RegistryDwordHandler : RegistryValueHandlerBase
{
    public override Mechanism Mechanism => Mechanism.RegistryDword;
}

/// <summary>
/// The <c>RegistryString</c> mechanism: the LibreOffice family. Each measure writes an
/// <c>REG_SZ</c> <c>Value</c> and an <c>REG_DWORD</c> <c>Final</c> at one policy path, so the
/// handler dispatches on the per-target kind exactly as its DWORD sibling does.
/// </summary>
public sealed class RegistryStringHandler : RegistryValueHandlerBase
{
    public override Mechanism Mechanism => Mechanism.RegistryString;
}
