// Palisade Tuning — UI-independent port of RyTuneX tuning logic.
// Copyright (C) 2017-2023 Security Without Borders
// Portions Copyright (C) RyTuneX contributors, GPLv3
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

using Microsoft.Win32;

namespace Palisade.Tuning.Policy;

/// <summary>
/// A known Group Policy entry with its registry location. Policy-backed
/// paths only, under HKLM\Software\Policies and HKCU\Software\Policies —
/// the same contract as upstream. Init-property shape so the transplanted
/// object-initializer catalog compiles unchanged.
/// </summary>
public sealed record PolicyEntry
{
    public required string Id { get; init; }

    public required string Name { get; init; }

    public required string Description { get; init; }

    public required string Category { get; init; }

    public required RegistryHive Hive { get; init; }

    public required string RegistryPath { get; init; }

    public required string ValueName { get; init; }

    public required RegistryValueKind ValueKind { get; init; }

    public int MinWindowsBuild { get; init; }

    public int MaxWindowsBuild { get; init; }
}

/// <summary>
/// The current state of a detected policy: "configured" means its registry
/// value exists — exactly upstream's definition.
/// </summary>
public sealed record PolicyState
{
    public required PolicyEntry Policy { get; init; }

    public required bool IsConfigured { get; init; }

    public object? CurrentValue { get; init; }

    public RegistryValueKind? ActualValueKind { get; init; }
}
