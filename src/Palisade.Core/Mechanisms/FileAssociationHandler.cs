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
/// The per-extension restriction table, transcribed verbatim from
/// <c>explorer.go:65-77</c>: the extension and the ProgID upstream reassociates on restore.
/// This is the longest piece of hand-authored data in the project, kept flat in one class so
/// a diff against the Go file is a one-glance check.
/// </summary>
public static class FileAssociationTable
{
    public static IReadOnlyList<(string Extension, string ProgId)> Restrictions { get; } =
    [
        (".hta", "htafile"),
        (".js", "JSFile"),
        (".JSE", "JSEFile"),
        (".WSH", "WSHFile"),
        (".WSF", "WSFFile"),
        (".scf", "SHCmdFile"),
        (".scr", "scrfile"),
        (".vbs", "VBSFile"),
        (".VBE", "VBEFile"),
        (".pif", "piffile"),
        (".mht", "mhtmlfile"),
    ];
}

/// <summary>
/// The <c>FileAssociation</c> mechanism: breaks the shell association of each scripted
/// extension. Upstream does this with <c>assoc .ext=</c> (which deletes the extension key's
/// default value in the merged <c>HKEY_CLASSES_ROOT</c> view) and, per extension, deletes
/// every value under the user's <c>FileExts\{ext}\OpenWithProgids</c> bag
/// (<c>explorer.go:89-154</c>).
/// </summary>
/// <remarks>
/// Palisade's registry-only shape, recorded as a deliberate divergence: hardening writes an
/// <strong>empty string</strong> into the default value of
/// <c>HKCU\SOFTWARE\Classes\{ext}</c> — which overrides the machine association with an
/// association to nothing — instead of deleting the value. Deleted and never-existed are
/// indistinguishable afterwards, which is exactly the defect that made upstream's
/// <c>IsHardened</c> unable to report correctly (spec defect #1); with the empty-string
/// marker, <c>Taut</c> (restricted), <c>Slack</c> (associated, or never associated and never
/// touched) and <c>Stressed</c> (changed since) are three different registry states. Restore
/// reinstates the recorded original or deletes the value again when there was none. The
/// user-level <c>OpenWithProgids</c> values are recorded and deleted as upstream does; the
/// engine's orphan pass reinstates them from the saved state, since they have no target of
/// their own.
/// </remarks>
public sealed class FileAssociationHandler : RegistryValueHandlerBase
{
    private const string ClassesBase = @"SOFTWARE\Classes";
    private const string FileExtsBase = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts";

    public override Mechanism Mechanism => Mechanism.FileAssociation;

    /// <summary>One resolved target per extension: the default (empty-named) value of the per-user class key.</summary>
    public override IReadOnlyList<ResolvedTarget> ResolveTargets(MeasureDescriptor descriptor, IVersionResolver versions) =>
        FileAssociationTable.Restrictions
            .Select(restriction => new ResolvedTarget(
                RegistryRoot.CurrentUser,
                ClassesBase + restriction.Extension,
                ValueName: string.Empty,
                MultiValueName: null,
                Kind: "String",
                HardenedValue: string.Empty))
            .ToList();

    public override void Apply(MeasureDescriptor descriptor, IReadOnlyList<ResolvedTarget> targets, IRegistryKeyFactory registry, SavedStateStore store)
    {
        // The system-wide restriction: record the current default value (or that there was
        // none) and then write the empty-string marker over it.
        base.Apply(descriptor, targets, registry, store);

        // The user defaults: record every OpenWithProgids value and then delete it, as
        // upstream step 2 does. Only values that could be recorded are deleted, so nothing
        // is removed that could not be put back.
        foreach (var (extension, _) in FileAssociationTable.Restrictions)
        {
            var userKeyPath = FileExtsBase + @"\" + extension + @"\OpenWithProgids";
            using var probe = registry.OpenKey(RegistryRoot.CurrentUser, userKeyPath, writable: false);
            if (probe is null)
            {
                continue; // Quite common per extension; upstream just remembers and moves on.
            }

            using var userKey = registry.OpenKey(RegistryRoot.CurrentUser, userKeyPath, writable: true)!;
            foreach (var name in userKey.GetValueNames())
            {
                if (!userKey.TryGetString(name, out var value))
                {
                    continue; // Not a REG_SZ: cannot be recorded, so it is not deleted either.
                }

                store.SaveString(RegistryRoot.CurrentUser, userKeyPath, name, value);
                userKey.DeleteValue(name);
            }
        }
    }
}
