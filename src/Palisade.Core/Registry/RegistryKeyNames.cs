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
/// The shape of a saved-state value name read from the Go tool's key, so a caller knows
/// which registry operation restores it.
/// </summary>
public enum SavedStateKind
{
    /// <summary>A DWORD that existed before hardening. Written as <c>SavedStateNew_</c>.</summary>
    Dword,

    /// <summary>A string that existed before hardening. Written as <c>SavedStateNewSZ_</c>.</summary>
    String,

    /// <summary>
    /// The value did not exist before hardening, so restore deletes it. Written as
    /// <c>SavedStateNotExisting_</c> holding a DWORD zero.
    /// </summary>
    NotExisting,

    /// <summary>
    /// The read-only <c>SavedState_</c> form. Go never writes it any more, but it is still
    /// read, and it is read as an integer (<c>registry_utils.go:469</c>, <c>:503</c>).
    /// </summary>
    LegacyDword,

    /// <summary>
    /// Unreachable, and deliberately kept. Go reads the bare <c>SavedState_</c> form only as
    /// an integer, so no legacy string entry can exist. The member is kept so that a future
    /// legacy-string format does not silently fall into <see cref="LegacyDword"/>, and so a
    /// <c>switch</c> over <see cref="SavedStateKind"/> has to handle it explicitly instead of
    /// relying on its default arm. <see cref="RegistryKeyNames.TryParse"/> never returns it.
    /// </summary>
    LegacyString,
}

/// <summary>
/// One saved-state value name, resolved. <paramref name="Warning"/> is the field to check
/// first: when it is set the entry is <em>not</em> restorable, and every other field is
/// either meaningless or empty by design.
/// </summary>
/// <param name="Kind">Which registry operation restores the entry.</param>
/// <param name="Root">
/// The root key. Meaningless when the root token did not resolve, which is one of the reasons
/// <paramref name="Warning"/> can be set; it is resolved for a name that failed for some other
/// reason, but such an entry is still not restorable because its key path and value name are
/// empty.
/// </param>
/// <param name="KeyPath">
/// The key path below the root. Always empty when <paramref name="Warning"/> is set, so a
/// caller that ignores the warning cannot write to a plausible-looking wrong key.
/// </param>
/// <param name="ValueName">The value name. Always empty when <paramref name="Warning"/> is set.</param>
/// <param name="Warning">
/// A sentence to surface to the user, or <see langword="null"/> when the entry resolved.
/// </param>
public readonly record struct SavedStateEntry(
    SavedStateKind Kind,
    RegistryRoot Root,
    string KeyPath,
    string ValueName,
    string? Warning);

/// <summary>
/// Formats and parses the saved-state value names under
/// <c>HKCU\SOFTWARE\Security Without Borders\</c>. These names are the wire format between
/// the Go tool and Palisade: a machine hardened by one must restore with the other, so the
/// composition here is transcribed from <c>registry_utils.go</c> and never "corrected".
/// </summary>
public static class RegistryKeyNames
{
    /// <summary>Prefix for a DWORD that existed before hardening. <c>registry_utils.go:378</c>.</summary>
    public const string NewDwordPrefix = "SavedStateNew_";

    /// <summary>Prefix for a string that existed before hardening. <c>registry_utils.go:432</c>.</summary>
    public const string NewStringPrefix = "SavedStateNewSZ_";

    /// <summary>
    /// Prefix for a value that did not exist before hardening, so restore deletes it.
    /// <c>registry_utils.go:388</c> and <c>:442</c>.
    /// </summary>
    public const string NotExistingPrefix = "SavedStateNotExisting_";

    /// <summary>Prefix for a non-registry feature's state. <c>registry_utils.go:640</c>.</summary>
    public const string NonRegPrefix = "SavedStateNonReg_";

    /// <summary>
    /// Prefix for the read-only legacy form. Go writes none of these any more; it is parsed
    /// because an older release may have left them behind. <c>registry_utils.go:503</c>.
    /// </summary>
    public const string LegacyPrefix = "SavedState_";

    /// <summary>
    /// The separator between the key path and the value name in the three current
    /// <c>SavedStateNew…</c> forms. <c>registry_utils.go:378</c>.
    /// </summary>
    public const string Separator = "____";

    /// <summary>The separator in the read-only <c>SavedState_</c> form. <c>registry_utils.go:469</c>.</summary>
    public const string LegacySeparator = "_";

    private const char PathSeparatorChar = '\\';

    /// <summary>
    /// The name a DWORD's original state is stored under, byte-identical to
    /// <c>"SavedStateNew_" + root + "\" + keyPath + "____" + valueName</c>
    /// (<c>registry_utils.go:378</c>).
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="root"/> is not one of the six. Go logs and writes nothing in that case
    /// (<c>registry_utils.go:246</c>), so no byte on disk differs either way.
    /// </exception>
    public static string Format(RegistryRoot root, string keyPath, string valueName) =>
        Compose(NewDwordPrefix, root, keyPath, valueName);

    /// <summary>
    /// The name recording that a value did not exist, byte-identical to
    /// <c>"SavedStateNotExisting_" + root + "\" + keyPath + "____" + valueName</c>
    /// (<c>registry_utils.go:388</c> and <c>:442</c>).
    /// </summary>
    /// <inheritdoc cref="Format(RegistryRoot, string, string)" path="/exception"/>
    public static string FormatNotExisting(RegistryRoot root, string keyPath, string valueName) =>
        Compose(NotExistingPrefix, root, keyPath, valueName);

    /// <summary>
    /// The name a non-registry feature's state is stored under, byte-identical to
    /// <c>"SavedStateNonReg_" + feature</c> (<c>registry_utils.go:640</c>). The id is written
    /// verbatim, so <c>new MeasureId("recall")</c> is what reaches disk: lowercase, as the Go
    /// tool persists it (<c>recall_feature.go:50</c>).
    /// </summary>
    public static string FormatNonReg(MeasureId feature) => NonRegPrefix + feature.Value;

    /// <summary>
    /// Resolves a saved-state value name into the root, key path and value name to restore.
    /// The root token is the text up to the <em>first</em> <c>\</c>, and the value name is
    /// everything after the <em>last</em> separator, matching Go's <c>strings.LastIndex</c>
    /// (<c>registry_utils.go:509</c> for the legacy form, <c>:536</c>, <c>:562</c> and
    /// <c>:601</c> for the four-underscore forms). Both a key path and a value name may legally
    /// contain the separator, so only the last occurrence round-trips. This is the contract
    /// rather than a fix for a live bug: no key path in the Go tree contains an underscore and
    /// no value name contains four in a row, so first-match and last-match happen to agree on
    /// every name Go can write today. It stops being academic the moment an underscore-bearing
    /// name reaches the format.
    /// </summary>
    /// <returns>
    /// <see langword="false"/> only when <paramref name="valueName"/> carries none of the four
    /// registry prefixes, so it is not a saved-state name at all and nothing is reported.
    /// <see langword="true"/> when the name is one of ours, including when it cannot be
    /// resolved: <paramref name="warning"/> is then a sentence to surface and
    /// <paramref name="targetValueName"/> and <paramref name="keyPath"/> are empty.
    /// </returns>
    /// <param name="valueName">The value name read from the saved-state key.</param>
    /// <param name="kind">Which registry operation restores the entry.</param>
    /// <param name="root">
    /// The root. <strong>Meaningless when the root token did not resolve</strong>, which is one
    /// of the ways <paramref name="warning"/> can be set. Either way a caller must check
    /// <paramref name="warning"/> before using the entry.
    /// </param>
    /// <param name="keyPath">The key path below the root, empty when the entry is unresolved.</param>
    /// <param name="targetValueName">The value name to write, empty when the entry is unresolved.</param>
    /// <param name="warning">
    /// A sentence to surface, or <see langword="null"/> when the entry resolved. Never throws
    /// and never guesses: an entry it cannot resolve is reported rather than restored.
    /// </param>
    public static bool TryParse(
        string valueName,
        out SavedStateKind kind,
        out RegistryRoot root,
        out string keyPath,
        out string targetValueName,
        out string? warning)
    {
        if (TryGetPrefix(valueName, out var prefix, out var separator, out kind))
        {
            var entry = Parse(valueName, prefix, separator, kind);
            root = entry.Root;
            keyPath = entry.KeyPath;
            targetValueName = entry.ValueName;
            warning = entry.Warning;
            return true;
        }

        kind = default;
        root = default;
        keyPath = string.Empty;
        targetValueName = string.Empty;
        warning = null;
        return false;
    }

    /// <summary>
    /// Resolves the feature id in a <c>SavedStateNonReg_</c> name. Two rejection reasons only:
    /// a prefix that is not <see cref="NonRegPrefix"/>, and an empty feature name after it.
    /// There is deliberately no check against a closed set of known features: a future Go
    /// release writing <c>SavedStateNonReg_&lt;newfeature&gt;</c> must still restore, and
    /// <see cref="FormatNonReg"/> accepts any id, so a whitelist would also make the pair
    /// asymmetric. Case fidelity is the writer's and the caller's business, not the parser's.
    /// </summary>
    public static bool TryParseNonReg(string valueName, out MeasureId feature)
    {
        if (string.IsNullOrEmpty(valueName)
            || !valueName.StartsWith(NonRegPrefix, StringComparison.Ordinal))
        {
            feature = default;
            return false;
        }

        var featureName = valueName[NonRegPrefix.Length..];
        if (featureName.Length == 0)
        {
            feature = default;
            return false;
        }

        feature = new MeasureId(featureName);
        return true;
    }

    private static string Compose(string prefix, RegistryRoot root, string keyPath, string valueName) =>
        prefix + RootKeyNames.ToToken(root) + PathSeparatorChar + keyPath + Separator + valueName;

    private static bool TryGetPrefix(
        string valueName, out string prefix, out string separator, out SavedStateKind kind)
    {
        // Longest prefix first. The four are mutually exclusive (they differ at index 10 or
        // 11), so this order is insurance rather than necessity. Checked by a test, because a
        // future prefix could make it matter.
        if (TryMatch(valueName, NewStringPrefix, SavedStateKind.String, Separator, out prefix, out separator, out kind))
            return true;
        if (TryMatch(valueName, NewDwordPrefix, SavedStateKind.Dword, Separator, out prefix, out separator, out kind))
            return true;
        if (TryMatch(valueName, NotExistingPrefix, SavedStateKind.NotExisting, Separator, out prefix, out separator, out kind))
            return true;
        if (TryMatch(valueName, LegacyPrefix, SavedStateKind.LegacyDword, LegacySeparator, out prefix, out separator, out kind))
            return true;

        prefix = string.Empty;
        separator = string.Empty;
        kind = default;
        return false;
    }

    private static bool TryMatch(
        string valueName, string candidatePrefix, SavedStateKind candidateKind, string candidateSeparator,
        out string prefix, out string separator, out SavedStateKind kind)
    {
        if (valueName is not null && valueName.StartsWith(candidatePrefix, StringComparison.Ordinal))
        {
            prefix = candidatePrefix;
            separator = candidateSeparator;
            kind = candidateKind;
            return true;
        }

        prefix = string.Empty;
        separator = string.Empty;
        kind = default;
        return false;
    }

    private static SavedStateEntry Parse(
        string valueName, string prefix, string separator, SavedStateKind kind)
    {
        var remainder = valueName[prefix.Length..];

        // The root token is the text up to the first `\`, as Go's strings.Split(regKey, "\\")[0]
        // is (registry_utils.go:506, :533, :560, :598). A root token never contains a
        // backslash, so this, and only this, is a first-match search.
        var rootTokenEnd = remainder.IndexOf(PathSeparatorChar);
        if (rootTokenEnd < 0)
            return Unresolvable(kind, default, valueName, "there is no key path after the root token");

        var rootToken = remainder[..rootTokenEnd];
        if (!RootKeyNames.TryParse(rootToken, out var root))
            return Unresolvable(kind, default, valueName, $"'{rootToken}' is not a registry root token");

        var keyAndValue = remainder[(rootTokenEnd + 1)..];

        // Go takes the LAST occurrence: regKey[strings.LastIndex(regKey, "____")+4:]
        // (registry_utils.go:536, :562, :601) and regKey[strings.LastIndex(regKey, "_")+1:]
        // (:509). A first-match split would hand back a plausible-looking but wrong key path
        // and value name with no error at all, and restore would write to the wrong key.
        var separatorIndex = keyAndValue.LastIndexOf(separator, StringComparison.Ordinal);
        if (separatorIndex < 0)
            return Unresolvable(kind, root, valueName, "there is no separator before the value name");

        return new SavedStateEntry(
            kind,
            root,
            keyAndValue[..separatorIndex],
            keyAndValue[(separatorIndex + separator.Length)..],
            Warning: null);
    }

    /// <summary>
    /// An entry we recognised but cannot restore. Go's equivalent inputs are unreachable from
    /// its four write sites and it mishandles them: with no separator its
    /// regKey[LastIndex(...)+4:] degrades to regKey[3:], so
    /// <c>SavedStateNew_CURRENT_USER\Software</c> would restore the value name "tware" under
    /// "Software", and a name that is nothing but a root token panics on the empty slice. The
    /// legacy branch mis-splits just as badly, returning the remainder as both halves. We
    /// report instead, and leave the key path and value name empty so that a caller which
    /// somehow ignores the warning has nothing plausible to write to.
    /// </summary>
    private static SavedStateEntry Unresolvable(
        SavedStateKind kind, RegistryRoot root, string valueName, string reason) =>
        new(kind, root, string.Empty, string.Empty,
            $"Saved-state value '{valueName}' cannot be restored: {reason}. It will be reported and left alone.");
}
