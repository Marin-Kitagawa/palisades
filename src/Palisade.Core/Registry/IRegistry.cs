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

namespace Palisade.Core.Registry;

/// <summary>
/// The value kinds this layer can carry. <see cref="Binary"/> is recognised but never
/// produced by a measure, and <see cref="None"/> means the value name is absent.
/// </summary>
public enum RegistryValueKind
{
    Dword,
    String,
    MultiString,
    Binary,
    None,
}

/// <summary>
/// One open registry key. <c>TryGet*</c> returns <c>false</c> both when the name is absent
/// and when the value is present under a different kind: a <c>REG_SZ</c> read through
/// <see cref="TryGetDword"/> fails rather than coercing, which is what lets the detector
/// tell "not set" from "set to something else".
/// </summary>
public interface IRegistryKey : IDisposable
{
    RegistryValueKind GetValueKind(string name);

    bool TryGetDword(string name, out uint value);

    bool TryGetString(string name, out string value);

    bool TryGetMultiString(string name, out string[] value);

    void SetDword(string name, uint value);

    void SetString(string name, string value);

    void SetMultiString(string name, IReadOnlyList<string> value);

    void DeleteValue(string name);

    IReadOnlyList<string> GetValueNames();
}

/// <summary>
/// The injected registry abstraction. <see cref="OpenKey"/> returns <c>null</c> for an
/// absent key — that is normal state, not an error, and every caller must handle it.
/// </summary>
public interface IRegistry
{
    IRegistryKey? OpenKey(RegistryRoot root, string subKey, bool writable);
}

/// <summary>
/// The single dependency a mechanism takes, so <c>RegistryAccess</c> and the in-memory
/// hive are interchangeable behind one constructor parameter.
/// </summary>
public interface IRegistryKeyFactory
{
    IRegistryKey? OpenKey(RegistryRoot root, string subKey, bool writable);
}
