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

namespace Palisade.Core.Engine;

/// <summary>What the engine did with one measure in one operation.</summary>
public enum ApplyOutcome
{
    /// <summary>The measure was hardened (or its non-registry state changed) by this operation.</summary>
    Applied,

    /// <summary>The measure was already in its hardened state; nothing was written.</summary>
    AlreadyApplied,

    /// <summary>The measure was put back to its recorded original by this operation.</summary>
    Restored,

    /// <summary>Nothing was restored: the engine holds no recorded original for the measure.</summary>
    NotRestored,

    /// <summary>The measure cannot apply on this machine; the report's detail names the reason.</summary>
    Unavailable,

    /// <summary>The operation failed for this measure; the detail carries the error.</summary>
    Failed,
}

/// <summary>One measure's outcome in one operation.</summary>
public sealed record MeasureResult(MeasureId Id, ApplyOutcome Outcome, string? Detail);

/// <summary>
/// The result of an apply, restore or reapply operation. Warnings carry every malformed
/// saved-state entry the operation met — never a silent drop — and
/// <see cref="RequiresRestart"/> says whether Windows should be restarted for the changes to
/// take effect, which upstream states unconditionally after every harden and restore
/// (<c>gui.go:414</c>, <c>gui.go:421</c>).
/// </summary>
public sealed record ApplyReport(
    IReadOnlyList<MeasureResult> Results,
    IReadOnlyList<string> Warnings,
    bool RequiresRestart);
