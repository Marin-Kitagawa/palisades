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
/// A read of the saved-state key for the duration of one detect or restore: the parsed
/// entries keyed so a resolved target can find its record, plus live handles on the
/// saved-state key so the recorded <em>values</em> (not just the names) can be read. The
/// handlers read the default saved-state path directly because the Go tool hardcodes it too
/// (<c>registry_utils.go</c>).
/// </summary>
internal sealed class SavedStateSnapshot : IDisposable
{
    private readonly Dictionary<(RegistryRoot Root, string KeyPath, string ValueName), (SavedStateEntry Entry, string RawName)> _entries =
        new(new KeyComparer());

    private readonly IRegistryKeyFactory _registry;
    private readonly IRegistryKey? _savedKey;

    private SavedStateSnapshot(IRegistryKeyFactory registry, IRegistryKey? savedKey)
    {
        _registry = registry;
        _savedKey = savedKey;
    }

    public static SavedStateSnapshot Load(IRegistryKeyFactory registry)
    {
        var savedKey = registry.OpenKey(RegistryRoot.CurrentUser, RegistryOptions.DefaultSavedStateKeyPath, writable: false);
        var snapshot = new SavedStateSnapshot(registry, savedKey);
        if (savedKey is not null)
        {
            foreach (var name in savedKey.GetValueNames())
            {
                if (RegistryKeyNames.TryParse(name, out var kind, out var root, out var keyPath, out var valueName, out var warning)
                    && warning is null)
                {
                    snapshot._entries[(root, keyPath, valueName)] = (
                        new SavedStateEntry(kind, root, keyPath, valueName, Warning: null), name);
                }
            }
        }

        return snapshot;
    }

    public bool HasEntry(ResolvedTarget target) => _entries.ContainsKey(Key(target));

    /// <summary>
    /// Every parsed entry in the snapshot, as a target the orphan pass can restore through.
    /// The engine loads the snapshot fresh after the per-measure restores have consumed
    /// their own records, so everything still here was claimed by no measure.
    /// </summary>
    public IEnumerable<(ResolvedTarget Target, SavedStateEntry Entry)> All() =>
        _entries.Values.Select(found => (
            new ResolvedTarget(
                found.Entry.Root,
                found.Entry.KeyPath,
                found.Entry.ValueName,
                MultiValueName: null,
                Kind: found.Entry.Kind == SavedStateKind.String ? "String" : "Dword",
                HardenedValue: string.Empty),
            found.Entry));

    public bool TryGetEntry(ResolvedTarget target, out SavedStateEntry entry)
    {
        if (_entries.TryGetValue(Key(target), out var found))
        {
            entry = found.Entry;
            return true;
        }

        entry = default;
        return false;
    }

    public bool TryGetOriginalDword(ResolvedTarget target, out uint value)
    {
        value = 0;
        return TryGetEntry(target, out var entry)
            && entry.Kind is SavedStateKind.Dword or SavedStateKind.LegacyDword
            && _savedKey is not null
            && _savedKey.TryGetDword(_entries[Key(target)].RawName, out value);
    }

    public bool TryGetOriginalString(ResolvedTarget target, out string value)
    {
        value = string.Empty;
        return TryGetEntry(target, out var entry)
            && entry.Kind == SavedStateKind.String
            && _savedKey is not null
            && _savedKey.TryGetString(_entries[Key(target)].RawName, out var read)
            && (value = read ?? string.Empty) is not null;
    }

    /// <summary>Entry-shaped reads used by the mechanism handlers and the orphan pass.</summary>
    public bool TryReadOriginalDword(ResolvedTarget target, out uint value) =>
        TryGetOriginalDword(target, out value);

    public bool TryReadOriginalDword(SavedStateEntry entry, out uint value) =>
        TryGetOriginalDword(ToTarget(entry), out value);

    public bool TryReadOriginalString(ResolvedTarget target, out string value) =>
        TryGetOriginalString(target, out value);

    public bool TryReadOriginalString(SavedStateEntry entry, out string value) =>
        TryGetOriginalString(ToTarget(entry), out value);

    private static ResolvedTarget ToTarget(SavedStateEntry entry) =>
        new(
            entry.Root,
            entry.KeyPath,
            entry.ValueName,
            MultiValueName: null,
            Kind: entry.Kind == SavedStateKind.String ? "String" : "Dword",
            HardenedValue: string.Empty);

    /// <summary>
    /// Deletes the saved-state records of the entries that were successfully restored, so
    /// they cannot be applied a second time by another measure sharing the same record (the
    /// DisallowRun flag is one record shared by the cmd.exe and PowerShell measures).
    /// Records that could not be restored stay in the store and are reported by a later full
    /// restore, which is what "never delete a record you did not verify as restorable" asks
    /// for at this layer; the whole key is removed by the engine once a full restore ends.
    /// </summary>
    public void Consume(IReadOnlyList<SavedStateEntry> restored)
    {
        if (restored.Count == 0 || _savedKey is null)
        {
            return;
        }

        using var writable = _registry.OpenKey(RegistryRoot.CurrentUser, RegistryOptions.DefaultSavedStateKeyPath, writable: true);
        if (writable is null)
        {
            return;
        }

        foreach (var entry in restored)
        {
            if (_entries.TryGetValue((entry.Root, entry.KeyPath, entry.ValueName), out var found))
            {
                writable.DeleteValue(found.RawName);
            }
        }
    }

    public void Dispose() => _savedKey?.Dispose();

    private static (RegistryRoot, string, string) Key(ResolvedTarget target) =>
        (target.Root, target.KeyPath, target.ValueName);

    /// <summary>Registry paths and value names are case-insensitive; the lookup must be too.</summary>
    private sealed class KeyComparer : IEqualityComparer<(RegistryRoot Root, string KeyPath, string ValueName)>
    {
        public bool Equals((RegistryRoot Root, string KeyPath, string ValueName) x, (RegistryRoot Root, string KeyPath, string ValueName) y) =>
            x.Root == y.Root
            && string.Equals(x.KeyPath, y.KeyPath, StringComparison.OrdinalIgnoreCase)
            && string.Equals(x.ValueName, y.ValueName, StringComparison.OrdinalIgnoreCase);

        public int GetHashCode((RegistryRoot Root, string KeyPath, string ValueName) key) =>
            HashCode.Combine(key.Root,
                StringComparer.OrdinalIgnoreCase.GetHashCode(key.KeyPath),
                StringComparer.OrdinalIgnoreCase.GetHashCode(key.ValueName));
    }
}
