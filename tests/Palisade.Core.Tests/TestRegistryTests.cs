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
        var registry = new InMemoryRegistry();
        using var key = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!;
        key.SetMultiString("DisallowRun", new[] { "cmd.exe", "wscript.exe" });
        Assert.True(key.TryGetMultiString("DisallowRun", out var value));
        Assert.Equal(new[] { "cmd.exe", "wscript.exe" }, value);
    }

    [Fact]
    public void The_default_value_uses_the_empty_name()
    {
        // The DisallowRun list is the key's default value upstream, which is the empty name.
        var registry = new InMemoryRegistry();
        using var key = registry.OpenKey(RegistryRoot.CurrentUser, @"Software\A", writable: true)!;
        key.SetMultiString(string.Empty, new[] { "cmd.exe" });
        Assert.True(key.TryGetMultiString(string.Empty, out var value));
        Assert.Equal(new[] { "cmd.exe" }, value);
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
