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

namespace Palisade.Core.Mechanisms;

/// <summary>
/// One concrete registry value, after any version expansion. Distinct from
/// <see cref="MeasureTarget"/>, which is a <em>declared</em> target in the catalog and may
/// carry a <c>%s</c> path template and narrowing filters; a resolved target is what a
/// handler actually reads and writes.
/// </summary>
/// <param name="Root">The root key the value lives under.</param>
/// <param name="KeyPath">The key path below the root, fully expanded.</param>
/// <param name="ValueName">
/// The registry value name. Ignored when <paramref name="MultiValueName"/> is set.
/// </param>
/// <param name="MultiValueName">
/// Names where a handler fans out over several values under one key — the Autorun and Uac
/// lists and the DisallowRun subkey. This is <strong>not</strong> <c>REG_MULTI_SZ</c>: the
/// values written there are ordinary <c>REG_SZ</c>/<c>REG_DWORD</c> values.
/// </param>
/// <param name="Kind">Exactly <c>"Dword"</c>, <c>"String"</c> or <c>"MultiString"</c>.</param>
/// <param name="HardenedValue">The value to harden to, in string form.</param>
public sealed record ResolvedTarget(
    RegistryRoot Root,
    string KeyPath,
    string ValueName,
    string? MultiValueName,
    string Kind,
    string HardenedValue);

/// <summary>
/// One mechanism handler. Handlers are stateless: the hive, the saved-state store and the
/// resolved targets all arrive as parameters, so the same handler serves the in-memory hive
/// in tests and the real registry in production.
/// </summary>
public interface IMechanismHandler
{
    Mechanism Mechanism { get; }

    /// <summary>
    /// Expands the descriptor's declared targets into concrete values. Non-versioned
    /// measures map each <see cref="MeasureTarget"/> straight through; versioned measures
    /// fan one declared target out into one resolved target per discovered product.
    /// </summary>
    IReadOnlyList<ResolvedTarget> ResolveTargets(MeasureDescriptor descriptor, IVersionResolver versions);

    /// <summary>Derives the four-state measure state from the current registry contents.</summary>
    MeasureState Detect(MeasureDescriptor descriptor, IReadOnlyList<ResolvedTarget> targets, IRegistryKeyFactory registry);

    /// <summary>
    /// Records every target's current value in the saved-state store and then hardens it.
    /// A pre-existing value is recorded, never discarded.
    /// </summary>
    void Apply(MeasureDescriptor descriptor, IReadOnlyList<ResolvedTarget> targets, IRegistryKeyFactory registry, SavedStateStore store);

    /// <summary>
    /// Puts every target back to its recorded original. A restore never creates a key: it
    /// probes read-only first and stops without writing when the key is absent, which is
    /// Go's <c>OpenKey</c>-on-restore behaviour. A target with no saved entry is left alone.
    /// </summary>
    void Restore(MeasureDescriptor descriptor, IReadOnlyList<ResolvedTarget> targets, IRegistryKeyFactory registry, SavedStateStore store);
}

/// <summary>
/// Version discovery, so the versioned-path expansion is testable and swappable. The
/// production implementation enumerates what is installed; the tests substitute fixed lists.
/// </summary>
public interface IVersionResolver
{
    IReadOnlyList<string> ResolveOfficeVersions();

    IReadOnlyList<string> ResolveAdobeVersions();
}
