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

namespace Palisade.Core.Models;

public enum RegistryRoot
{
    ClassesRoot,
    CurrentUser,
    LocalMachine,
    Users,
    CurrentConfig,
    PerformanceData,
}

/// <summary>
/// The six root key name tokens, transcribed from <c>registry_utils.go</c> lines 246-292.
/// The Go tool writes these exact strings into saved-state value names, so they are a
/// byte-compatibility surface: no abbreviation such as HKCU is ever emitted or accepted.
/// </summary>
public static class RootKeyNames
{
    public static string ToToken(RegistryRoot root) => root switch
    {
        RegistryRoot.ClassesRoot => "CLASSES_ROOT",
        RegistryRoot.CurrentUser => "CURRENT_USER",
        RegistryRoot.LocalMachine => "LOCAL_MACHINE",
        RegistryRoot.Users => "USERS",
        RegistryRoot.CurrentConfig => "CURRENT_CONFIG",
        RegistryRoot.PerformanceData => "PERFORMANCE_DATA",
        _ => throw new ArgumentOutOfRangeException(nameof(root), root, "Unknown registry root."),
    };

    public static bool TryParse(string token, out RegistryRoot root)
    {
        switch (token)
        {
            case "CLASSES_ROOT":
                root = RegistryRoot.ClassesRoot;
                return true;
            case "CURRENT_USER":
                root = RegistryRoot.CurrentUser;
                return true;
            case "LOCAL_MACHINE":
                root = RegistryRoot.LocalMachine;
                return true;
            case "USERS":
                root = RegistryRoot.Users;
                return true;
            case "CURRENT_CONFIG":
                root = RegistryRoot.CurrentConfig;
                return true;
            case "PERFORMANCE_DATA":
                root = RegistryRoot.PerformanceData;
                return true;
            default:
                root = default;
                return false;
        }
    }
}
