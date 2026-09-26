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

using Microsoft.Win32;
using System.Security;
using Palisade.Core.Models;
using Palisade.Core.Registry;

namespace Palisade.Core.Registry;

/// <summary>
/// The only file in <c>Palisade.Core</c> that touches <c>Microsoft.Win32.Registry</c>. It
/// adapts the real Windows registry to the <see cref="IRegistry"/> contract the whole engine
/// codes against, so the in-memory hive and production are interchangeable behind one
/// constructor parameter.
/// </summary>
/// <remarks>
/// <see cref="OpenKey"/> with <c>writable: true</c> creates the key on demand ” the
/// contract's documented conflation of Go's <c>CreateKey</c> (harden) and <c>OpenKey</c>
/// (restore) ” and returns <c>null</c> when the underlying open throws
/// <see cref="SecurityException"/> or <see cref="IOException"/>, because both are normal
/// absence, not errors. <see cref="DeleteKey"/> removes a whole subtree via
/// <c>DeleteSubKeyTree</c>, deliberately diverging from Go's plain <c>RegDeleteKey</c>,
/// which fails with <c>ERROR_ACCESS_DENIED</c> on a key that has subkeys; the fake agrees.
/// </remarks>
public sealed class RegistryAccess : IRegistry, IRegistryKeyFactory
{
    public IRegistryKey? OpenKey(RegistryRoot root, string subKey, bool writable)
    {
        try
        {
            using var baseKey = BaseKey(root);
            var key = writable
                ? baseKey.CreateSubKey(subKey, writable: true)
                : baseKey.OpenSubKey(subKey, writable: false);
            return key is null ? null : new RegistryKeyWrapper(key);
        }
        catch (Exception error) when (error is SecurityException or IOException or UnauthorizedAccessException or ArgumentException)
        {
            return null;
        }
    }

    public bool DeleteKey(RegistryRoot root, string subKey)
    {
        try
        {
            using var baseKey = BaseKey(root);
            baseKey.DeleteSubKeyTree(subKey, throwOnMissingSubKey: false);
            return true;
        }
        catch (Exception error) when (error is SecurityException or IOException or UnauthorizedAccessException or ArgumentException)
        {
            return false;
        }
    }

    private static Microsoft.Win32.RegistryKey BaseKey(RegistryRoot root) => root switch
    {
        RegistryRoot.ClassesRoot => Microsoft.Win32.Registry.ClassesRoot,
        RegistryRoot.CurrentUser => Microsoft.Win32.Registry.CurrentUser,
        RegistryRoot.LocalMachine => Microsoft.Win32.Registry.LocalMachine,
        RegistryRoot.Users => Microsoft.Win32.Registry.Users,
        RegistryRoot.CurrentConfig => Microsoft.Win32.Registry.CurrentConfig,
        RegistryRoot.PerformanceData => Microsoft.Win32.Registry.PerformanceData,
        _ => throw new ArgumentOutOfRangeException(nameof(root), root, "Not one of the six registry roots."),
    };

    /// <summary>
    /// Adapts one open <c>Microsoft.Win32.RegistryKey</c> to <see cref="IRegistryKey"/>. The
    /// <c>TryGet</c> members catch <see cref="IOException"/> and return <c>false</c>: a
    /// value of the wrong kind or a racing deletion surfaces as an exception here, not as a
    /// null, and the detector needs "not set", not a crash.
    /// </summary>
    private sealed class RegistryKeyWrapper(Microsoft.Win32.RegistryKey key) : IRegistryKey
    {
        public RegistryValueKind GetValueKind(string name) => key.GetValueKind(name) switch
        {
            Microsoft.Win32.RegistryValueKind.DWord => RegistryValueKind.Dword,
            Microsoft.Win32.RegistryValueKind.String or Microsoft.Win32.RegistryValueKind.ExpandString => RegistryValueKind.String,
            Microsoft.Win32.RegistryValueKind.MultiString => RegistryValueKind.MultiString,
            Microsoft.Win32.RegistryValueKind.Binary => RegistryValueKind.Binary,
            Microsoft.Win32.RegistryValueKind.None => RegistryValueKind.None,
            _ => RegistryValueKind.Binary,
        };

        public bool TryGetDword(string name, out uint value)
        {
            try
            {
                if (key.GetValue(name) is int dword)
                {
                    value = unchecked((uint)dword);
                    return true;
                }
            }
            catch (Exception error) when (error is IOException or SecurityException)
            {
                // Absent or unreadable: "not set", not a crash.
            }

            value = 0;
            return false;
        }

        public bool TryGetString(string name, out string value)
        {
            try
            {
                if (key.GetValue(name, null) is string text)
                {
                    value = text;
                    return true;
                }
            }
            catch (Exception error) when (error is IOException or SecurityException)
            {
            }

            value = string.Empty;
            return false;
        }

        public bool TryGetMultiString(string name, out string[] value)
        {
            try
            {
                if (key.GetValue(name, null) is string[] list)
                {
                    value = list;
                    return true;
                }
            }
            catch (Exception error) when (error is IOException or SecurityException)
            {
            }

            value = [];
            return false;
        }

        public void SetDword(string name, uint value) =>
            key.SetValue(name, unchecked((int)value), Microsoft.Win32.RegistryValueKind.DWord);

        public void SetString(string name, string value) =>
            key.SetValue(name, value, Microsoft.Win32.RegistryValueKind.String);

        public void SetMultiString(string name, IReadOnlyList<string> value) =>
            key.SetValue(name, value.ToArray(), Microsoft.Win32.RegistryValueKind.MultiString);

        public void DeleteValue(string name)
        {
            try
            {
                key.DeleteValue(name, throwOnMissingValue: false);
            }
            catch (Exception error) when (error is IOException or SecurityException)
            {
                // Already gone is a no-op, matching the abstraction's contract.
            }
        }

        public IReadOnlyList<string> GetValueNames() => key.GetValueNames();

        public void Dispose() => key.Dispose();
    }
}
