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

namespace Palisade.Core.Tests;

/// <summary>
/// The only hive the test suite touches. A key is nothing but a path string, so there are
/// no parent keys to create: a value written under <c>Software\A\B</c> simply lives at that
/// path. <c>OpenKey</c> returns <c>null</c> for an absent path, and creates the entry on
/// demand when <c>writable</c> is set.
/// </summary>
public sealed class InMemoryRegistry : IRegistry, IRegistryKeyFactory
{
    private readonly Dictionary<string, InMemoryEntry> _entries = new(StringComparer.OrdinalIgnoreCase);

    public IRegistryKey? OpenKey(RegistryRoot root, string subKey, bool writable)
    {
        var path = Path(root, subKey);
        if (!_entries.TryGetValue(path, out var entry))
        {
            if (!writable)
            {
                return null;
            }

            entry = new InMemoryEntry();
            _entries[path] = entry;
        }

        return new InMemoryRegistryKey(entry);
    }

    /// <summary>
    /// Registry paths and value names are case-insensitive, and the Go sources disagree on
    /// the casing of the same root (<c>SYSTEM\...</c> in <c>lsa_protection.go:28</c> versus
    /// lowercase elsewhere), so both dictionaries here compare with
    /// <see cref="StringComparer.OrdinalIgnoreCase"/>.
    /// </summary>
    private static string Path(RegistryRoot root, string subKey) =>
        $"{RootKeyNames.ToToken(root)}\\{subKey}";

    /// <summary>The mutable value bag for one key path.</summary>
    public sealed class InMemoryEntry
    {
        public Dictionary<string, (RegistryValueKind Kind, object Value)> Values { get; } =
            new(StringComparer.OrdinalIgnoreCase);
    }
}

/// <summary>
/// One open key over an <see cref="InMemoryRegistry.InMemoryEntry"/>. Reads are a snapshot of
/// the live bag, so a value written through a second handle for the same path is visible
/// here immediately — the fake is the hive, not a copy of it.
/// </summary>
public sealed class InMemoryRegistryKey(InMemoryRegistry.InMemoryEntry entry) : IRegistryKey
{
    public RegistryValueKind GetValueKind(string name) =>
        entry.Values.TryGetValue(name, out var stored) ? stored.Kind : RegistryValueKind.None;

    public bool TryGetDword(string name, out uint value)
    {
        if (TryGet(name, RegistryValueKind.Dword, out var stored) && stored.Value is uint dword)
        {
            value = dword;
            return true;
        }

        value = 0;
        return false;
    }

    public bool TryGetString(string name, out string value)
    {
        if (TryGet(name, RegistryValueKind.String, out var stored) && stored.Value is string text)
        {
            value = text;
            return true;
        }

        value = string.Empty;
        return false;
    }

    public bool TryGetMultiString(string name, out string[] value)
    {
        if (TryGet(name, RegistryValueKind.MultiString, out var stored) && stored.Value is string[] list)
        {
            // A fresh array per read, so a caller cannot edit the hive through the result.
            value = list.ToArray();
            return true;
        }

        value = [];
        return false;
    }

    public void SetDword(string name, uint value) => entry.Values[name] = (RegistryValueKind.Dword, value);

    public void SetString(string name, string value) => entry.Values[name] = (RegistryValueKind.String, value);

    public void SetMultiString(string name, IReadOnlyList<string> value) =>
        entry.Values[name] = (RegistryValueKind.MultiString, value.ToArray());

    /// <summary>
    /// Deleting a name that is not there is a no-op, not an exception. The Go tool logs the
    /// failure and carries on (<c>registry_utils.go:577-580</c>), and restore on a machine
    /// that has already lost the value must not abort.
    /// </summary>
    public void DeleteValue(string name) => entry.Values.Remove(name);

    /// <summary>Sorted, so the order never depends on the dictionary's internal layout.</summary>
    public IReadOnlyList<string> GetValueNames() =>
        entry.Values.Keys.OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToList();

    public void Dispose()
    {
        // Nothing to release: the hive is a dictionary the registry itself owns, which is
        // why a handle stays readable after it is disposed.
    }

    private bool TryGet(string name, RegistryValueKind kind, out (RegistryValueKind Kind, object Value) stored)
    {
        if (entry.Values.TryGetValue(name, out stored) && stored.Kind == kind)
        {
            return true;
        }

        stored = default;
        return false;
    }
}
