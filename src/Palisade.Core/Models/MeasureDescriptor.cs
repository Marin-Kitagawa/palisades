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

/// <summary>
/// A measure identifier. It wraps a string rather than an enum so that the
/// <c>SavedStateNonReg_</c> feature names Palisade persists stay byte-identical to the
/// Go tool's, which are lowercase where upstream is lowercase.
/// </summary>
public readonly record struct MeasureId(string Value)
{
    public override string ToString() => Value;

    public static implicit operator string(MeasureId id) => id.Value;
}

public sealed record AvailabilityRule(string Kind, IReadOnlyDictionary<string, string> Arguments, string Reason);

public sealed record MeasureConstraint(MeasureId Target, string Reason);

/// <summary>
/// One registry value a measure writes. <see cref="Kind"/> is exactly one of
/// <c>"Dword"</c>, <c>"String"</c> or <c>"MultiString"</c> and drives the read and the
/// write, so a measure that writes both a REG_SZ and a REG_DWORD at one path needs no
/// bespoke encoding. <see cref="HardenedValue"/> is the string form of the hardened
/// value; for <c>"Dword"</c> it is decimal digits, and it may be empty
/// (<c>SecureURL\Value</c> hardens to <c>""</c>). <see cref="Path"/> may contain
/// <c>%s</c>, the placeholder for the product version.
/// </summary>
/// <param name="AppFilter">
/// Comma-separated allowlist of apps this target applies to, or <c>null</c> for no
/// narrowing. <c>office.go</c> scopes <c>AllowDDE</c> to Word and
/// <c>WorkbookLinkWarnings</c> to Excel; every other target applies to every discovered
/// product.
/// </param>
/// <param name="VersionFilter">
/// Comma-separated allowlist of versions this target applies to, or <c>null</c> for no
/// narrowing. <c>AllowDDE</c> and both <c>DontUpdateLinks</c> sub-values are scoped to
/// Office 14-16 and skip 12.0 upstream.
/// </param>
public sealed record MeasureTarget(
    RegistryRoot Root,
    string Path,
    string ValueName,
    string Kind,
    string HardenedValue,
    string? AppFilter = null,
    string? VersionFilter = null);

/// <summary>
/// A measure as data. <see cref="Mechanism"/> is the classification the engine dispatches
/// on; <see cref="Targets"/> is the registry payload, one entry per value written, each
/// carrying its own path template and optional narrowing. <see cref="Settings"/> holds
/// only the product universe to expand: <c>"OfficeVersions"</c>, <c>"AdobeVersions"</c>
/// and <c>"Apps"</c>.
/// </summary>
public sealed record MeasureDescriptor(
    MeasureId Id,
    string Name,
    string LongName,
    string Consequence,
    Mechanism Mechanism,
    bool RequiresElevation,
    bool HardenByDefault,
    MeasureGroup Group,
    IReadOnlyDictionary<string, string> Settings,
    IReadOnlyList<MeasureTarget> Targets,
    IReadOnlyList<MeasureConstraint> ConstrainedBy,
    IReadOnlyList<AvailabilityRule> Availability);
