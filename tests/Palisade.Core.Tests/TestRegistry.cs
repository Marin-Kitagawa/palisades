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
    /// <summary>
    /// The comparer every path in this hive uses. The subtree scan in
    /// <see cref="DeleteKey"/> has to agree with it: a descendant stored as
    /// <c>software\microsoft\...</c> is beneath a parent asked for as
    /// <c>SOFTWARE\MICROSOFT\...</c>, and an ordinal prefix test would leave it behind.
    /// </summary>
    private static readonly StringComparer PathComparer = StringComparer.OrdinalIgnoreCase;

    private readonly Dictionary<string, InMemoryEntry> _entries = new(PathComparer);

    /// <summary>
    /// <c>writable</c> governs only whether an absent path is created on the spot. It is not
    /// an access check, so a handle opened read-only can still be written through: the
    /// plan's own Task 6 tests seed a hive through <c>writable: false</c> handles, and a
    /// fake that threw there would fail them for a reason of its own making.
    /// </summary>
    public IRegistryKey? OpenKey(RegistryRoot root, string subKey, bool writable)
    {
        var path = KeyPath(root, subKey);
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
    /// Removes the key and its whole subtree, and returns whether anything was removed. A key is
    /// a path string, so a descendant is one that extends the parent's path with a
    /// <c>\</c>-prefixed segment.
    /// The subtree is <c>RegDeleteTree</c> behaviour - <c>DeleteSubKeyTree</c> in .NET - and not
    /// <c>RegDeleteKey</c>, which fails with <c>ERROR_ACCESS_DENIED</c> on a key that has
    /// subkeys. Go's <c>registry.DeleteKey</c> is plain <c>RegDeleteKey</c>, so the three
    /// upstream call sites would error on a key with subkeys; none of them has any, so Go never
    /// reaches the case. The divergence from Go is deliberate and unreachable in practice.
    /// Task 11's real adapter must call <c>DeleteSubKeyTree</c>, not <c>DeleteSubKey</c>, so the
    /// fake and production agree.
    /// </summary>
    public bool DeleteKey(RegistryRoot root, string subKey)
    {
        // The trailing separator is trimmed rather than compensated for when appending, because
        // the saved-state path ends in one (constants.go:20) and appending another would look
        // for a doubled backslash and match no descendant at all. Trimming also settles the
        // prefix: the composed path can no longer end in a separator, so the descendant scan
        // only ever needs one.
        //
        // An empty or separator-only subKey is refused outright. It would compose a root path
        // such as "CURRENT_USER\", which is a prefix of every key under the root, so the delete
        // would take the whole root with it and report success. Real RegDeleteKey(HKCU, "") fails,
        // so refusing is also the faithful answer.
        var trimmed = subKey.TrimEnd('\\');
        if (trimmed.Length == 0)
        {
            return false;
        }

        var path = KeyPath(root, trimmed);
        var prefix = path + "\\";

        // Materialised before removing: the keys cannot be enumerated while being mutated.
        var doomed = _entries.Keys
            .Where(candidate => PathComparer.Equals(candidate, path) || IsBeneath(candidate, prefix))
            .ToList();

        foreach (var candidate in doomed)
        {
            _entries.Remove(candidate);
        }

        // A descendant can exist with no entry for its parent, because nothing enforces one.
        // Removing it is still a removal, so this reports what happened rather than whether
        // the exact path was present.
        return doomed.Count > 0;
    }

    /// <summary>
    /// A prefix test in the same comparison the path dictionary uses, so the subtree scan
    /// cannot silently disagree with it.
    /// </summary>
    private static bool IsBeneath(string path, string prefix) =>
        path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Registry paths and value names are case-insensitive, and the Go sources disagree on
    /// the casing of the same root (<c>SYSTEM\...</c> in <c>lsa_protection.go:28</c> versus
    /// lowercase elsewhere), so both dictionaries here compare with
    /// <see cref="StringComparer.OrdinalIgnoreCase"/>.
    /// </summary>
    private static string KeyPath(RegistryRoot root, string subKey) =>
        $"{RootKeyNames.ToToken(root)}\\{subKey}";

    /// <summary>The mutable value bag for one key path.</summary>
    public sealed class InMemoryEntry
    {
        public Dictionary<string, (RegistryValueKind Kind, object Value)> Values { get; } =
            new(StringComparer.OrdinalIgnoreCase);
    }
}

/// <summary>
/// One open key over an <see cref="InMemoryRegistry.InMemoryEntry"/>. The handle holds the
/// live value bag rather than a copy of it, so a value written through a second handle for
/// the same path shows up here immediately: the fake is the hive, not a snapshot of it.
/// </summary>
public sealed class InMemoryRegistryKey(InMemoryRegistry.InMemoryEntry entry) : IRegistryKey
{
    private bool _disposed;

    public RegistryValueKind GetValueKind(string name)
    {
        ThrowIfDisposed();
        return entry.Values.TryGetValue(name, out var stored) ? stored.Kind : RegistryValueKind.None;
    }

    public bool TryGetDword(string name, out uint value)
    {
        ThrowIfDisposed();
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
        ThrowIfDisposed();
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
        ThrowIfDisposed();
        if (TryGet(name, RegistryValueKind.MultiString, out var stored) && stored.Value is string[] list)
        {
            // A fresh array per read, so a caller cannot edit the hive through the result.
            value = list.ToArray();
            return true;
        }

        value = [];
        return false;
    }

    public void SetDword(string name, uint value)
    {
        ThrowIfDisposed();
        entry.Values[name] = (RegistryValueKind.Dword, value);
    }

    public void SetString(string name, string value)
    {
        ThrowIfDisposed();
        entry.Values[name] = (RegistryValueKind.String, value);
    }

    public void SetMultiString(string name, IReadOnlyList<string> value)
    {
        ThrowIfDisposed();
        entry.Values[name] = (RegistryValueKind.MultiString, value.ToArray());
    }

    /// <summary>
    /// Deleting a name that is not there is a no-op, not an exception. The Go tool logs the
    /// failure and carries on (<c>registry_utils.go:577-580</c>), and restore on a machine
    /// that has already lost the value must not abort.
    /// </summary>
    public void DeleteValue(string name)
    {
        ThrowIfDisposed();
        entry.Values.Remove(name);
    }

    /// <summary>Sorted, so the order never depends on the dictionary's internal layout.</summary>
    public IReadOnlyList<string> GetValueNames()
    {
        ThrowIfDisposed();
        return entry.Values.Keys.OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>
    /// There is still no handle to release: the hive is a dictionary the registry itself owns.
    /// What disposal buys is that the handle stops answering, so a use-after-dispose throws here
    /// as it would on a real <c>RegistryKey</c> instead of quietly returning a value that would
    /// only fail once the same code ran for real. Disposing twice is not an error.
    /// </summary>
    public void Dispose() => _disposed = true;

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

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
