// Palisade Tuning - UI-independent port of RyTuneX tuning logic.
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
using Palisade.Tuning.Models;

namespace Palisade.Tuning.Runtime;

/// <summary>
/// Records which tuning options were applied on this account, under
/// HKCU\SOFTWARE\Palisade\Tuning, so a later run can tell "applied" from
/// "reverted" and restore what it recorded - the same marker scheme RyTuneX
/// uses under its own key.
/// </summary>
public static class TuningStateStore
{
    public const string StateKeyPath = @"SOFTWARE\Palisade\Tuning";

    public static bool IsApplied(string optionId)
    {
        using var key = Registry.CurrentUser.OpenSubKey(StateKeyPath);
        return key?.GetValue(optionId) is int value && value == 1;
    }

    public static void MarkApplied(string optionId)
    {
        using var key = Registry.CurrentUser.CreateSubKey(StateKeyPath);
        key.SetValue(optionId, 1, RegistryValueKind.DWord);
    }

    public static void MarkReverted(string optionId)
    {
        using var key = Registry.CurrentUser.CreateSubKey(StateKeyPath);
        key.SetValue(optionId, 0, RegistryValueKind.DWord);
    }

    public static IReadOnlyList<string> AppliedIds()
    {
        using var key = Registry.CurrentUser.OpenSubKey(StateKeyPath);
        if (key?.GetValueNames() is not { Length: > 0 } names)
        {
            return [];
        }
        return names.Where(n => key.GetValue(n) is int v && v == 1).ToList();
    }
}
