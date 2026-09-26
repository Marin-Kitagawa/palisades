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

namespace Palisade.Core.Tests;

public class TestRegistryTests
{
    [Fact]
    public void OpenKey_returns_null_for_an_absent_key()
    {
        IRegistry registry = new InMemoryRegistry();
        Assert.Null(registry.OpenKey(RegistryRoot.CurrentUser, @"Software\Nope", writable: false));
    }

    [Fact]
    public void Dword_round_trips()
    {
        var registry = new InMemoryRegistry();
        using var key = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!;
        key.SetDword("V", 42);
        Assert.True(key.TryGetDword("V", out var value));
        Assert.Equal(42u, value);
    }

    [Fact]
    public void DeleteValue_removes_the_value()
    {
        var registry = new InMemoryRegistry();
        using var key = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!;
        key.SetString("V", "x");
        key.DeleteValue("V");
        Assert.False(key.TryGetString("V", out _));
    }

    [Fact]
    public void GetValueNames_excludes_deleted_values()
    {
        var registry = new InMemoryRegistry();
        using var key = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!;
        key.SetString("Keep", "x");
        key.SetString("Drop", "y");
        key.DeleteValue("Drop");
        Assert.Equal(new[] { "Keep" }, key.GetValueNames());
    }

    [Fact]
    public void String_round_trips()
    {
        var registry = new InMemoryRegistry();
        using var key = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!;
        key.SetString("V", "hello");
        Assert.True(key.TryGetString("V", out var value));
        Assert.Equal("hello", value);
    }

    [Fact]
    public void An_empty_string_value_round_trips()
    {
        // `SecureURL\Value` hardens to "" (libreoffice.go:48). A fake that treated an empty
        // string as "absent" would make that target unrestorable.
        var registry = new InMemoryRegistry();
        using var key = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!;
        key.SetString("V", string.Empty);
        Assert.True(key.TryGetString("V", out var value));
        Assert.Equal(string.Empty, value);
        Assert.Equal(RegistryValueKind.String, key.GetValueKind("V"));
    }

    [Fact]
    public void MultiString_round_trips()
    {
        // The fake models REG_MULTI_SZ because the abstraction declares the kind, not because
        // any measure uses it: no Go call site writes a multi-string, and DisallowRun in
        // particular is numbered REG_SZ values in a subkey, not one list.
        var registry = new InMemoryRegistry();
        using var key = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!;
        key.SetMultiString("List", new[] { "one", "two" });
        Assert.True(key.TryGetMultiString("List", out var value));
        Assert.Equal(new[] { "one", "two" }, value);
    }

    [Fact]
    public void The_default_value_uses_the_empty_name()
    {
        // A Windows key can carry a default value, whose name is the empty string, so the
        // empty name has to round-trip rather than read as an absent value.
        var registry = new InMemoryRegistry();
        using var key = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!;
        key.SetString(string.Empty, "default");
        Assert.True(key.TryGetString(string.Empty, out var value));
        Assert.Equal("default", value);
        Assert.Equal(new[] { string.Empty }, key.GetValueNames());
    }

    [Fact]
    public void TryGet_returns_false_for_an_absent_value()
    {
        var registry = new InMemoryRegistry();
        using var key = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!;
        Assert.False(key.TryGetDword("Missing", out var dword));
        Assert.Equal(0u, dword);
        // The out parameters are non-nullable, so a failed read yields the empty value
        // rather than a null a caller could trip over by ignoring the bool.
        Assert.False(key.TryGetString("Missing", out var text));
        Assert.Equal(string.Empty, text);
        Assert.False(key.TryGetMultiString("Missing", out var list));
        Assert.Empty(list);
    }

    [Fact]
    public void GetValueKind_is_none_for_an_absent_value()
    {
        var registry = new InMemoryRegistry();
        using var key = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!;
        Assert.Equal(RegistryValueKind.None, key.GetValueKind("Missing"));
        key.SetDword("D", 1);
        key.SetString("S", "x");
        key.SetMultiString("M", new[] { "y" });
        Assert.Equal(RegistryValueKind.Dword, key.GetValueKind("D"));
        Assert.Equal(RegistryValueKind.String, key.GetValueKind("S"));
        Assert.Equal(RegistryValueKind.MultiString, key.GetValueKind("M"));
    }

    [Fact]
    public void TryGetDword_returns_false_for_a_string_value()
    {
        // Coercing here would make a REG_SZ indistinguishable from a REG_DWORD, and the
        // four-state detector in Task 9 needs "not set" to differ from "set to something else".
        var registry = new InMemoryRegistry();
        using var key = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!;
        key.SetString("V", "42");
        Assert.False(key.TryGetDword("V", out var value));
        Assert.Equal(0u, value);
    }

    [Fact]
    public void TryGetString_returns_false_for_a_dword_value()
    {
        var registry = new InMemoryRegistry();
        using var key = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!;
        key.SetDword("V", 42);
        Assert.False(key.TryGetString("V", out var value));
        Assert.Equal(string.Empty, value);
    }

    [Fact]
    public void TryGetMultiString_returns_false_for_a_dword_value()
    {
        var registry = new InMemoryRegistry();
        using var key = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!;
        key.SetDword("V", 42);
        Assert.False(key.TryGetMultiString("V", out var value));
        Assert.Empty(value);
    }

    [Fact]
    public void A_writable_open_creates_the_key_on_demand()
    {
        var registry = new InMemoryRegistry();
        using (registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true))
        {
        }

        using var again = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: false);
        Assert.NotNull(again);
    }

    [Fact]
    public void A_read_only_open_does_not_create_the_key()
    {
        var registry = new InMemoryRegistry();
        Assert.Null(registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: false));

        // Still absent: a read-only open must not have created anything on the way past.
        Assert.Null(registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: false));
    }

    [Fact]
    public void A_created_key_starts_empty()
    {
        var registry = new InMemoryRegistry();
        using var key = registry.OpenKey(RegistryRoot.LocalMachine, @"System\Nope", writable: true)!;
        Assert.Empty(key.GetValueNames());
    }

    [Fact]
    public void A_key_written_through_one_handle_is_visible_through_another()
    {
        var registry = new InMemoryRegistry();
        using (var first = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!)
        {
            first.SetDword("V", 1);
        }

        using var second = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: false)!;
        Assert.True(second.TryGetDword("V", out var value));
        Assert.Equal(1u, value);
    }

    [Fact]
    public void The_same_subkey_under_two_roots_is_two_keys()
    {
        var registry = new InMemoryRegistry();
        using (var current = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!)
        {
            current.SetDword("V", 1);
        }

        using var machine = registry.OpenKey(RegistryRoot.LocalMachine, @"Software\A", writable: true)!;
        Assert.False(machine.TryGetDword("V", out _));
    }

    [Fact]
    public void Key_paths_are_case_insensitive()
    {
        // The catalog spells LSA `SYSTEM\CurrentControlSet\Control\Lsa` (lsa_protection.go:28)
        // and the plan's own Task 6 tests open the same key as `System\...`. A case-sensitive
        // hive would fail those for the wrong reason.
        var registry = new InMemoryRegistry();
        using (var written = registry.OpenKey(RegistryRoot.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\Lsa", writable: true)!)
        {
            written.SetDword("RunAsPPL", 1);
        }

        using var read = registry.OpenKey(RegistryRoot.LocalMachine,
            @"System\CurrentControlSet\Control\Lsa", writable: false)!;
        Assert.True(read.TryGetDword("RunAsPPL", out var value));
        Assert.Equal(1u, value);
    }

    [Fact]
    public void A_differently_cased_subkey_is_the_same_key_not_a_child()
    {
        var registry = new InMemoryRegistry();
        using var key = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\Microsoft\Windows", writable: true)!;
        using var recased = registry.OpenKey(RegistryRoot.CurrentUser, @"SOFTWARE\microsoft\WINDOWS", writable: false)!;
        key.SetString("V", "x");
        Assert.True(recased.TryGetString("V", out var value));
        Assert.Equal("x", value);
    }

    [Fact]
    public void Value_names_are_case_insensitive()
    {
        var registry = new InMemoryRegistry();
        using var key = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!;
        key.SetDword("RunAsPPL", 1);
        Assert.True(key.TryGetDword("runasppl", out var value));
        Assert.Equal(1u, value);
        key.SetDword("RUNASPPL", 2); // Overwrites, rather than adding a second value.
        Assert.Equal(new[] { "RunAsPPL" }, key.GetValueNames());
        Assert.True(key.TryGetDword("RunAsPPL", out var overwritten));
        Assert.Equal(2u, overwritten);
    }

    [Fact]
    public void Deleting_a_value_clears_its_name_whatever_the_casing()
    {
        var registry = new InMemoryRegistry();
        using var key = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!;
        key.SetString("Value", "x");
        key.DeleteValue("VALUE");
        Assert.False(key.TryGetString("Value", out _));
        Assert.Equal(RegistryValueKind.None, key.GetValueKind("Value"));
    }

    [Fact]
    public void GetValueNames_is_sorted_so_its_order_does_not_depend_on_insertion()
    {
        // Insertion order here is deliberately not alphabetical and mixes case, so a
        // dictionary-order implementation fails this rather than passing by luck.
        var registry = new InMemoryRegistry();
        using var key = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!;
        key.SetString("C", "1");
        key.SetString("a", "2");
        key.SetString("B", "3");

        Assert.Equal(new[] { "a", "B", "C" }, key.GetValueNames());

        // The order is a property of the key, not of one handle: a second handle onto the
        // same path agrees, and sees a value written through the first.
        using var second = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: false)!;
        second.SetString("D", "4");
        Assert.Equal(new[] { "a", "B", "C", "D" }, second.GetValueNames());
        Assert.Equal(new[] { "a", "B", "C", "D" }, key.GetValueNames());
    }

    [Fact]
    public void Deleting_an_absent_value_is_a_no_op()
    {
        // The Go tool logs a failed DeleteValue at trace level and continues
        // (registry_utils.go:577-580), so restore on a machine that already lost the value
        // must not blow up.
        var registry = new InMemoryRegistry();
        using var key = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!;
        key.DeleteValue("NeverThere");
        Assert.Empty(key.GetValueNames());
    }

    [Fact]
    public void DeleteKey_removes_the_key_and_everything_beneath_it()
    {
        // The fake removes a subtree, which is RegDeleteTree (DeleteSubKeyTree in .NET) rather
        // than RegDeleteKey -- the latter fails with ERROR_ACCESS_DENIED on a key with subkeys.
        // Both upstream call sites delete keys that have none (the DisallowRun subkey once its
        // last entry is gone at cmd.go:136, the whole saved-state key on restore at
        // utils.go:159), so Go never reaches the case. Task 11's real adapter must use
        // DeleteSubKeyTree so the fake and production agree.
        var registry = new InMemoryRegistry();
        Seed(registry, RegistryRoot.CurrentUser, @"Software\A", "V");
        Seed(registry, RegistryRoot.CurrentUser, @"Software\A\B", "W");
        Seed(registry, RegistryRoot.CurrentUser, @"Software\A\B\C", "X");

        Assert.True(registry.DeleteKey(RegistryRoot.CurrentUser, @"Software\A"));

        Assert.Null(registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: false));
        Assert.Null(registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A\B", writable: false));
        Assert.Null(registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A\B\C", writable: false));
    }

    [Fact]
    public void DeleteKey_leaves_keys_that_only_share_a_prefix()
    {
        // Software\A must not take Software\AB or Software\A2 with it, so the subtree test
        // has to match a separator and not merely the leading characters.
        var registry = new InMemoryRegistry();
        Seed(registry, RegistryRoot.CurrentUser, @"Software\A", "V");
        Seed(registry, RegistryRoot.CurrentUser, @"Software\AB", "W");
        Seed(registry, RegistryRoot.CurrentUser, @"Software\A2\B", "X");

        Assert.True(registry.DeleteKey(RegistryRoot.CurrentUser, @"Software\A"));

        Assert.Null(registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: false));
        Assert.NotNull(registry.OpenKey(RegistryRoot.CurrentUser, @"Software\AB", writable: false));
        Assert.NotNull(registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A2\B", writable: false));
    }

    [Fact]
    public void DeleteKey_matches_descendant_paths_case_insensitively()
    {
        // The path dictionary is OrdinalIgnoreCase, so a child stored as
        // `software\microsoft\...` is beneath a parent asked for as `SOFTWARE\MICROSOFT\...`.
        // An ordinal prefix test would miss it and leave the subtree behind.
        var registry = new InMemoryRegistry();
        Seed(registry, RegistryRoot.CurrentUser, @"SOFTWARE\MICROSOFT\Windows", "V");
        Seed(registry, RegistryRoot.CurrentUser, @"software\microsoft\windows\currentversion\explorer", "W");
        // Outside the subtree, and stored in a third casing, so a scan that over-matched
        // would take this one too.
        Seed(registry, RegistryRoot.CurrentUser, @"software\other\policies", "X");

        Assert.True(registry.DeleteKey(RegistryRoot.CurrentUser, @"SOFTWARE\MICROSOFT\WINDOWS"));

        Assert.Null(registry.OpenKey(RegistryRoot.CurrentUser, @"SOFTWARE\MICROSOFT\Windows", writable: false));
        Assert.Null(registry.OpenKey(
            RegistryRoot.CurrentUser, @"software\microsoft\windows\currentversion\explorer", writable: false));
        Assert.NotNull(registry.OpenKey(RegistryRoot.CurrentUser, @"software\other\policies", writable: false));
    }

    [Fact]
    public void DeleteKey_returns_false_when_the_key_was_already_absent()
    {
        // "Already absent" has to stay distinguishable from "deleted", the same discipline as
        // OpenKey returning null rather than throwing.
        var registry = new InMemoryRegistry();
        Assert.False(registry.DeleteKey(RegistryRoot.CurrentUser, @"Software\Nope"));

        Seed(registry, RegistryRoot.CurrentUser, @"Software\A", "V");
        Assert.True(registry.DeleteKey(RegistryRoot.CurrentUser, @"Software\A"));
        Assert.False(registry.DeleteKey(RegistryRoot.CurrentUser, @"Software\A"));
    }

    [Fact]
    public void DeleteKey_returns_true_when_only_a_descendant_existed()
    {
        // A key is a path string with no enforced parent, so a child can exist with no entry
        // for its parent. Removing it is still a removal, and reporting false would tell the
        // caller nothing was deleted when something was.
        var registry = new InMemoryRegistry();
        Seed(registry, RegistryRoot.CurrentUser, @"Software\A\B", "V");

        Assert.True(registry.DeleteKey(RegistryRoot.CurrentUser, @"Software\A"));
        Assert.Null(registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A\B", writable: false));
    }

    [Fact]
    public void DeleteKey_leaves_the_same_path_under_another_root_alone()
    {
        var registry = new InMemoryRegistry();
        Seed(registry, RegistryRoot.CurrentUser, @"Software\A", "V");
        Seed(registry, RegistryRoot.LocalMachine, @"Software\A", "W");

        Assert.True(registry.DeleteKey(RegistryRoot.CurrentUser, @"Software\A"));

        Assert.Null(registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: false));
        using var machine = registry.OpenKey(RegistryRoot.LocalMachine, @"Software\A", writable: false)!;
        Assert.True(machine.TryGetString("W", out var value));
        Assert.Equal("W", value);
    }

    [Fact]
    public void DeleteKey_handles_the_saved_state_paths_trailing_backslash()
    {
        // utils.go:159 deletes hardentoolsKeyPath, which ends in a backslash
        // (constants.go:20). Appending a separator unconditionally would look for a doubled
        // backslash and match no descendant.
        var registry = new InMemoryRegistry();
        Seed(registry, RegistryRoot.CurrentUser, RegistryOptions.DefaultSavedStateKeyPath, "V");
        Seed(registry, RegistryRoot.CurrentUser, RegistryOptions.DefaultSavedStateKeyPath + "Sub", "W");

        Assert.True(registry.DeleteKey(RegistryRoot.CurrentUser, RegistryOptions.DefaultSavedStateKeyPath));

        Assert.Null(registry.OpenKey(RegistryRoot.CurrentUser, RegistryOptions.DefaultSavedStateKeyPath, writable: false));
        Assert.Null(registry.OpenKey(
            RegistryRoot.CurrentUser, RegistryOptions.DefaultSavedStateKeyPath + "Sub", writable: false));
    }

    [Fact]
    public void DeleteKey_refuses_an_empty_subkey_instead_of_wiping_the_root()
    {
        // An empty subKey composes "CURRENT_USER\", which is a prefix of every key under the
        // root, so without a guard this deletes the entire root and reports success. Real
        // RegDeleteKey(HKCU, "") fails, so refusing is the faithful answer. RegistryOptions is a
        // record with a public positional parameter, so new RegistryOptions("") compiles and
        // nothing upstream stops it arriving here.
        var registry = new InMemoryRegistry();
        Seed(registry, RegistryRoot.CurrentUser, @"Software\A", "V");
        Seed(registry, RegistryRoot.CurrentUser, @"Software\A\B", "W");

        Assert.False(registry.DeleteKey(RegistryRoot.CurrentUser, string.Empty));

        Assert.NotNull(registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: false));
        Assert.NotNull(registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A\B", writable: false));
    }

    [Fact]
    public void DeleteKey_refuses_a_separator_only_subkey()
    {
        // "\" composes "CURRENT_USER\\", which today matches nothing by accident of the
        // doubled backslash. Seeding a key at that literal path makes the assertion bite: the
        // refusal has to be a deliberate guard, not the accident it currently is.
        var registry = new InMemoryRegistry();
        Seed(registry, RegistryRoot.CurrentUser, @"Software\A", "V");
        Seed(registry, RegistryRoot.CurrentUser, "\\", "W");

        Assert.False(registry.DeleteKey(RegistryRoot.CurrentUser, @"\"));

        Assert.NotNull(registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: false));
        Assert.NotNull(registry.OpenKey(RegistryRoot.CurrentUser, "\\", writable: false));
    }

    [Fact]
    public void Using_a_key_after_disposing_it_throws()
    {
        // A real RegistryKey throws ObjectDisposedException. Without this a handler could read
        // through a disposed handle all the way through the suite and then crash in production,
        // which is the class of bug the fake exists to catch.
        var registry = new InMemoryRegistry();
        var key = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!;
        key.SetDword("V", 1);
        key.Dispose();

        Assert.Throws<ObjectDisposedException>(() => key.GetValueKind("V"));
        Assert.Throws<ObjectDisposedException>(() => key.TryGetDword("V", out _));
        Assert.Throws<ObjectDisposedException>(() => key.TryGetString("V", out _));
        Assert.Throws<ObjectDisposedException>(() => key.TryGetMultiString("V", out _));
        Assert.Throws<ObjectDisposedException>(() => key.GetValueNames());
        Assert.Throws<ObjectDisposedException>(() => key.SetDword("V", 2));
        Assert.Throws<ObjectDisposedException>(() => key.SetString("V", "2"));
        Assert.Throws<ObjectDisposedException>(() => key.SetMultiString("V", ["2"]));
        Assert.Throws<ObjectDisposedException>(() => key.DeleteValue("V"));

        // Disposing again is not an error: Dispose is idempotent, as it is on the real handle.
        key.Dispose();
    }

    [Fact]
    public void A_deleted_subtree_can_be_created_again_and_starts_empty()
    {
        var registry = new InMemoryRegistry();
        Seed(registry, RegistryRoot.CurrentUser, @"Software\A", "V");
        Seed(registry, RegistryRoot.CurrentUser, @"Software\A\B", "W");
        registry.DeleteKey(RegistryRoot.CurrentUser, @"Software\A");

        using var recreated = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!;
        Assert.Empty(recreated.GetValueNames());
        Assert.False(recreated.TryGetString("V", out _));
    }

    private static void Seed(InMemoryRegistry registry, RegistryRoot root, string path, string valueName)
    {
        using var key = registry.OpenKey(root, path, writable: true)!;
        key.SetString(valueName, valueName);
    }

    [Fact]
    public void The_saved_state_key_path_is_the_go_tools_path()
    {
        // registry_utils.go uses hardentoolsKeyPath for its own state; this is a byte-compat
        // surface, so the constant is asserted rather than assumed.
        Assert.Equal(@"SOFTWARE\Security Without Borders\", RegistryOptions.DefaultSavedStateKeyPath);
        Assert.Equal(RegistryOptions.DefaultSavedStateKeyPath, RegistryOptions.Default.SavedStateKeyPath);
    }

    [Fact]
    public void AppPaths_exposes_the_directory_it_was_built_with()
    {
        IAppPaths paths = new AppPaths(@"C:\Palisade\logs");
        Assert.Equal(@"C:\Palisade\logs", paths.LogDirectory);
    }

    [Fact]
    public void The_hive_answers_to_the_key_factory_abstraction()
    {
        IRegistryKeyFactory factory = new InMemoryRegistry();
        using var key = factory.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!;
        key.SetDword("V", 1);
        Assert.Single(key.GetValueNames());
    }
}
