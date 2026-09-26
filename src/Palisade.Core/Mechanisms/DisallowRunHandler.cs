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
/// The <c>DisallowRun</c> mechanism: numbered <c>REG_SZ</c> values in the
/// <c>Explorer\DisallowRun</c> subkey, plus the <c>DisallowRun</c> <c>REG_DWORD</c> flag on
/// the parent key that enables the policy. This is not a <c>REG_MULTI_SZ</c> list — the
/// value <em>names</em> are the indices (<c>cmd.go:170-177</c>, <c>powershell.go:180-185</c>).
/// Harden appends its executables at the first free index, preserving foreign entries;
/// restore removes only its own, renumbers the survivors from 1, and removes the subkey and
/// the flag when nothing is left (<c>cmd.go:118-140</c>).
/// </summary>
public sealed class DisallowRunHandler : IMechanismHandler
{
    private const string ExplorerPoliciesPath = @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";
    private const string DisallowRunSubKey = ExplorerPoliciesPath + @"\DisallowRun";
    private const string FlagValueName = "DisallowRun";
    private const int MaxIndex = 99;

    public Mechanism Mechanism => Mechanism.DisallowRun;

    /// <summary>
    /// One target: the flag on the Explorer policies key, with the subkey named as the place
    /// the handler fans out. The executables themselves come from
    /// <c>descriptor.Settings["Apps"]</c> and are not per-target data.
    /// </summary>
    public IReadOnlyList<ResolvedTarget> ResolveTargets(MeasureDescriptor descriptor, IVersionResolver versions) =>
    [
        new ResolvedTarget(RegistryRoot.CurrentUser, ExplorerPoliciesPath, FlagValueName, DisallowRunSubKey, "Dword", "1"),
    ];

    public MeasureState Detect(MeasureDescriptor descriptor, IReadOnlyList<ResolvedTarget> targets, IRegistryKeyFactory registry)
    {
        var apps = AppsOf(descriptor);
        using var subkey = registry.OpenKey(RegistryRoot.CurrentUser, DisallowRunSubKey, writable: false);
        if (subkey is null)
        {
            return MeasureState.Slack;
        }

        var contents = subkey.GetValueNames()
            .Select(name => subkey.TryGetString(name, out var value) ? value : null)
            .Where(value => value is not null)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var present = apps.Count(app => contents.Contains(app));
        if (present == 0)
        {
            return MeasureState.Slack;
        }

        var flagSet = false;
        using (var explorer = registry.OpenKey(RegistryRoot.CurrentUser, ExplorerPoliciesPath, writable: false))
        {
            flagSet = explorer is not null && explorer.TryGetDword(FlagValueName, out var flag) && flag == 1;
        }

        return present == apps.Count && flagSet ? MeasureState.Taut : MeasureState.Stressed;
    }

    public void Apply(MeasureDescriptor descriptor, IReadOnlyList<ResolvedTarget> targets, IRegistryKeyFactory registry, SavedStateStore store)
    {
        var apps = AppsOf(descriptor);

        // CreateKey parity: harden creates the subkey on demand.
        using (var subkey = registry.OpenKey(RegistryRoot.CurrentUser, DisallowRunSubKey, writable: true)
            ?? throw new InvalidOperationException($"The key 'CURRENT_USER\\{DisallowRunSubKey}' could not be created or opened for writing."))
        {
            var occupied = subkey.GetValueNames().ToHashSet(StringComparer.OrdinalIgnoreCase);
            var next = 1;
            foreach (var app in apps)
            {
                // The first free index, recomputed per executable so a foreign entry is never
                // overwritten. (Go computes one starting point and writes two executables at
                // start and start+1, which overwrites a foreign entry sitting past a gap;
                // preserving foreign entries is the point of this port of the mechanism.)
                while (occupied.Contains(IndexName(next)) && next <= MaxIndex)
                {
                    next++;
                }

                subkey.SetString(IndexName(next), app);
                occupied.Add(IndexName(next));
                next++;
            }
        }

        using (var explorer = registry.OpenKey(RegistryRoot.CurrentUser, ExplorerPoliciesPath, writable: true)
            ?? throw new InvalidOperationException($"The key 'CURRENT_USER\\{ExplorerPoliciesPath}' could not be created or opened for writing."))
        {
            RecordFlagOriginalState(registry, store);
            explorer.SetDword(FlagValueName, 1);
        }
    }

    public void Restore(MeasureDescriptor descriptor, IReadOnlyList<ResolvedTarget> targets, IRegistryKeyFactory registry, SavedStateStore store)
    {
        var apps = AppsOf(descriptor);
        var subkeyGone = false;

        using (var probe = registry.OpenKey(RegistryRoot.CurrentUser, DisallowRunSubKey, writable: false))
        {
            if (probe is null)
            {
                // The list is already gone; nothing of ours can remain in it.
                subkeyGone = true;
            }
            else
            {
                using var subkey = registry.OpenKey(RegistryRoot.CurrentUser, DisallowRunSubKey, writable: true)!;

                // Delete only our own executables, walking the numbered indices and stopping
                // at the first gap, as Go does (cmd.go:77): a hole truncates the list.
                for (var index = 1; index <= MaxIndex && subkey.TryGetString(IndexName(index), out var content); index++)
                {
                    if (apps.Contains(content, StringComparer.OrdinalIgnoreCase))
                    {
                        subkey.DeleteValue(IndexName(index));
                    }
                }

                // Compact: renumber the survivors from 1, foreign entries included, so the
                // gap our deletion left closes (cmd.go:118-140).
                var survivors = subkey.GetValueNames()
                    .OrderBy(name => int.TryParse(name, out var number) ? number : int.MaxValue, Comparer<int>.Default)
                    .ThenBy(name => name, StringComparer.OrdinalIgnoreCase)
                    .Select(name => (Name: name, Content: subkey.TryGetString(name, out var value) ? value : string.Empty))
                    .ToList();

                foreach (var (name, _) in survivors)
                {
                    subkey.DeleteValue(name);
                }

                for (var index = 0; index < survivors.Count; index++)
                {
                    subkey.SetString(IndexName(index + 1), survivors[index].Content);
                }

                subkeyGone = survivors.Count == 0;
            }
        }

        // The flag is only put back once the list is gone: with foreign entries left the
        // policy must stay enabled for them, exactly as upstream keeps it (cmd.go:136).
        if (subkeyGone)
        {
            registry.DeleteKey(RegistryRoot.CurrentUser, DisallowRunSubKey);
            RestoreFlag(registry, store);
        }
    }

    /// <summary>
    /// The flag's original state is recorded once: when a first record already exists —
    /// because the other DisallowRun measure hardened first in the same run — that record is
    /// the true original and overwriting it with the value the first measure just wrote
    /// would lose it.
    /// </summary>
    private static void RecordFlagOriginalState(IRegistryKeyFactory registry, SavedStateStore store)
    {
        using var saved = SavedStateSnapshot.Load(registry);
        var flagTarget = new ResolvedTarget(RegistryRoot.CurrentUser, ExplorerPoliciesPath, FlagValueName, null, "Dword", "1");
        if (saved.HasEntry(flagTarget))
        {
            return;
        }

        using var explorer = registry.OpenKey(RegistryRoot.CurrentUser, ExplorerPoliciesPath, writable: false);
        if (explorer is not null && explorer.TryGetDword(FlagValueName, out var current))
        {
            store.SaveDword(RegistryRoot.CurrentUser, ExplorerPoliciesPath, FlagValueName, current);
        }
        else
        {
            store.SaveNotExisting(RegistryRoot.CurrentUser, ExplorerPoliciesPath, FlagValueName);
        }
    }

    private static void RestoreFlag(IRegistryKeyFactory registry, SavedStateStore store)
    {
        var flagTarget = new ResolvedTarget(RegistryRoot.CurrentUser, ExplorerPoliciesPath, FlagValueName, null, "Dword", "1");
        using var saved = SavedStateSnapshot.Load(registry);
        if (!saved.TryGetEntry(flagTarget, out var entry))
        {
            return; // We never recorded a flag, so we do not touch one.
        }

        using var explorer = registry.OpenKey(RegistryRoot.CurrentUser, ExplorerPoliciesPath, writable: true);
        if (explorer is null)
        {
            return; // A restore never creates a key.
        }

        switch (entry.Kind)
        {
            case SavedStateKind.Dword:
            case SavedStateKind.LegacyDword:
                if (saved.TryGetOriginalDword(flagTarget, out var original))
                {
                    explorer.SetDword(FlagValueName, original);
                }

                break;
            case SavedStateKind.NotExisting:
                explorer.DeleteValue(FlagValueName);
                break;
        }

        saved.Consume([entry]);
    }

    private static IReadOnlyList<string> AppsOf(MeasureDescriptor descriptor)
    {
        var raw = descriptor.Settings.GetValueOrDefault("Apps");
        return string.IsNullOrWhiteSpace(raw)
            ? []
            : raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static string IndexName(int index) => index.ToString(System.Globalization.CultureInfo.InvariantCulture);
}
