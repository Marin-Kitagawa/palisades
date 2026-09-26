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

namespace Palisade.Core.Registry;

/// <summary>
/// Where the tool keeps its saved state. The default path is a byte-compatibility surface:
/// a machine hardened by the Go tool must restore with Palisade and the other way round, so
/// the value is transcribed from <c>hardentoolsKeyPath</c> and never "corrected".
/// </summary>
public sealed record RegistryOptions(string SavedStateKeyPath)
{
    public const string DefaultSavedStateKeyPath = @"SOFTWARE\Security Without Borders\";

    public static RegistryOptions Default { get; } = new(DefaultSavedStateKeyPath);
}

/// <summary>
/// The filesystem locations the engine may write to. An abstraction so the engine's tests
/// can be given a scratch directory without touching the user's real profile.
/// </summary>
public interface IAppPaths
{
    string LogDirectory { get; }
}

public sealed class AppPaths : IAppPaths
{
    public AppPaths(string logDirectory) => LogDirectory = logDirectory;

    public string LogDirectory { get; }
}
