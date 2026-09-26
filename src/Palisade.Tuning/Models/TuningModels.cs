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

namespace Palisade.Tuning.Models;

/// <summary>Categories used to group tuning entries, mirroring RyTuneX pages.</summary>
public static class TuningCategories
{
    public const string Optimize = "Optimize";
    public const string Policy = "Policy";
    public const string Startup = "Startup";
    public const string Privacy = "Privacy";
    public const string Security = "Security";
    public const string Network = "Network";
    public const string Debloat = "Debloat";
    public const string Repair = "Repair";
    public const string System = "System";
}

/// <summary>
/// A single user-facing tuning toggle: the unit of enumeration for MVVM binding
/// and the unit of apply/restore. The command lists are transcribed verbatim from
/// the RyTuneX source (OptimizeSystemHelper.cs); fidelity over cleanup.
/// </summary>
/// <param name="Id">Stable unique identifier (used for persistence and tests).</param>
/// <param name="Title">Human-readable short label.</param>
/// <param name="Description">What the toggle changes, in the user's own machine terms.</param>
/// <param name="Category">One of <see cref="TuningCategories"/>.</param>
/// <param name="RequiresElevation">True when the operation needs an elevated process.</param>
/// <param name="ApplyCommands">Commands that turn the optimization on, run through cmd.</param>
/// <param name="RevertCommands">Commands that return the setting to the RyTuneX-default state.</param>
public sealed record TuningOption(
    string Id,
    string Title,
    string Description,
    string Category,
    bool RequiresElevation,
    IReadOnlyList<string> ApplyCommands,
    IReadOnlyList<string> RevertCommands);
