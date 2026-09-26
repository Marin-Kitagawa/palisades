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
/// Reads and writes the saved state under <c>HKCU\SOFTWARE\Security Without Borders\</c>.
/// The value names are composed by <see cref="RegistryKeyNames"/> and are byte-compatible
/// with the Go tool: a machine hardened by either can be restored by the other.
/// Only the four current prefixes are ever written; the legacy <c>SavedState_</c> form is
/// read-only (<c>registry_utils.go</c> has not written it for years, but an older release
/// may have left entries behind and they must still restore).
/// </summary>
/// <param name="registry">The hive to work against. The tests give an in-memory one.</param>
/// <param name="options">Where the saved state lives; <see cref="RegistryOptions.Default"/> upstream.</param>
public sealed class SavedStateStore(IRegistryKeyFactory registry, RegistryOptions options)
{
    /// <summary>Saves that a DWORD existed with this value before hardening (<c>registry_utils.go:378</c>).</summary>
    public void SaveDword(RegistryRoot root, string keyPath, string valueName, uint originalValue)
    {
        using var key = OpenWritable();
        key.SetDword(RegistryKeyNames.Format(root, keyPath, valueName), originalValue);
    }

    /// <summary>Saves that a string existed with this value before hardening (<c>registry_utils.go:432</c>).</summary>
    public void SaveString(RegistryRoot root, string keyPath, string valueName, string originalValue)
    {
        using var key = OpenWritable();
        key.SetString(RegistryKeyNames.FormatString(root, keyPath, valueName), originalValue);
    }

    /// <summary>
    /// Saves that a value did not exist before hardening, so restore deletes it. Go writes
    /// this as a <c>REG_DWORD</c> holding zero (<c>registry_utils.go:388</c>, <c>:442</c>),
    /// and so does this store, because the Go tool reads every
    /// <c>SavedStateNotExisting_</c> name with <c>GetIntegerValue</c>.
    /// </summary>
    public void SaveNotExisting(RegistryRoot root, string keyPath, string valueName)
    {
        using var key = OpenWritable();
        key.SetDword(RegistryKeyNames.FormatNotExisting(root, keyPath, valueName), 0);
    }

    /// <summary>
    /// Saves a non-registry feature's state under <c>SavedStateNonReg_</c>
    /// (<c>registry_utils.go:640</c>). The id is written verbatim: lowercase
    /// <c>recall</c> because that is what the Go tool persists (<c>recall_feature.go:50</c>).
    /// </summary>
    public void SaveNonReg(MeasureId feature, string state)
    {
        using var key = OpenWritable();
        key.SetString(RegistryKeyNames.FormatNonReg(feature), state);
    }

    /// <summary>
    /// Reads every registry saved-state entry under the saved-state key. Names that carry
    /// none of our prefixes are not ours and are skipped entirely. Names that are ours but
    /// cannot be resolved are returned with <see cref="SavedStateEntry.Warning"/> set —
    /// never dropped silently, and never guessed at. <c>SavedStateNonReg_</c> names are not
    /// returned here; <see cref="TryGetNonReg"/> reads them.
    /// </summary>
    public IReadOnlyList<SavedStateEntry> ReadAll()
    {
        using var key = registry.OpenKey(RegistryRoot.CurrentUser, options.SavedStateKeyPath, writable: false);
        if (key is null)
        {
            return [];
        }

        var entries = new List<SavedStateEntry>();
        foreach (var name in key.GetValueNames())
        {
            if (RegistryKeyNames.TryParse(name, out var kind, out var root, out var keyPath, out var valueName, out var warning))
            {
                entries.Add(new SavedStateEntry(kind, root, keyPath, valueName, warning));
            }
        }

        return entries;
    }

    /// <summary>Reads a non-registry feature's recorded state, if one was saved.</summary>
    public bool TryGetNonReg(MeasureId feature, out string state)
    {
        state = string.Empty;
        using var key = registry.OpenKey(RegistryRoot.CurrentUser, options.SavedStateKeyPath, writable: false);
        if (key is null)
        {
            return false;
        }

        if (!key.TryGetString(RegistryKeyNames.FormatNonReg(feature), out var saved))
        {
            return false;
        }

        state = saved;
        return true;
    }

    /// <summary>Deletes a non-registry feature's recorded state. Absent is a no-op.</summary>
    public void DeleteNonReg(MeasureId feature)
    {
        using var key = OpenWritable();
        key.DeleteValue(RegistryKeyNames.FormatNonReg(feature));
    }

    /// <summary>
    /// Deletes the whole saved-state key, matching <c>utils.go:159</c> via
    /// <c>markStatus(false)</c>, which removes the key outright on restore rather than
    /// emptying it. Already-absent is a no-op, not an error.
    /// </summary>
    public void Clear() => registry.DeleteKey(RegistryRoot.CurrentUser, options.SavedStateKeyPath);

    /// <summary>
    /// A writable open of the saved-state key never returns <c>null</c>: the factory creates
    /// the key on demand when <c>writable</c> is set, which is exactly Go's
    /// <c>CreateKey(CURRENT_USER, hardentoolsKeyPath, ALL_ACCESS)</c> at every save site.
    /// </summary>
    private IRegistryKey OpenWritable() =>
        registry.OpenKey(RegistryRoot.CurrentUser, options.SavedStateKeyPath, writable: true)
        ?? throw new InvalidOperationException(
            $"The saved-state key '{options.SavedStateKeyPath}' could not be opened for writing.");
}
