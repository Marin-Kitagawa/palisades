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

namespace Palisade.Core.Tests.Registry;

public class RegistryKeyNamesTests
{
    [Fact]
    public void Formats_the_dword_name_with_four_underscores() =>
        Assert.Equal(
            @"SavedStateNew_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer____DisallowRun",
            RegistryKeyNames.Format(RegistryRoot.CurrentUser,
                @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "DisallowRun"));

    [Fact]
    public void Formats_the_not_existing_name_with_four_underscores() =>
        // Byte-identical to registry_utils.go:388 and :442.
        Assert.Equal(
            @"SavedStateNotExisting_LOCAL_MACHINE\Software\Foo____Bar",
            RegistryKeyNames.FormatNotExisting(RegistryRoot.LocalMachine, @"Software\Foo", "Bar"));

    [Fact]
    public void Round_trips_a_dword_name()
    {
        Assert.True(RegistryKeyNames.TryParse(
            @"SavedStateNew_LOCAL_MACHINE\Software\Foo\Bar____MyValue",
            out var kind, out var root, out var keyPath, out var valueName, out var warning));
        Assert.Equal(SavedStateKind.Dword, kind);
        Assert.Equal(RegistryRoot.LocalMachine, root);
        Assert.Equal(@"Software\Foo\Bar", keyPath);
        Assert.Equal("MyValue", valueName);
        Assert.Null(warning);
    }

    [Fact]
    public void Parses_a_string_name_as_the_string_kind()
    {
        // The Go SZ write site (registry_utils.go:432) has no Palisade formatter, so this is
        // the only side of the SZ form under test; the parse has to be right or an SZ entry
        // written by the Go tool would be restored with the wrong value name.
        Assert.True(RegistryKeyNames.TryParse(
            @"SavedStateNewSZ_CURRENT_USER\Software\Foo____Bar",
            out var kind, out var root, out var keyPath, out var valueName, out var warning));
        Assert.Equal(SavedStateKind.String, kind);
        Assert.Equal(RegistryRoot.CurrentUser, root);
        Assert.Equal(@"Software\Foo", keyPath);
        Assert.Equal("Bar", valueName);
        Assert.Null(warning);
    }

    [Fact]
    public void Parses_a_not_existing_name_as_the_not_existing_kind()
    {
        Assert.True(RegistryKeyNames.TryParse(
            @"SavedStateNotExisting_LOCAL_MACHINE\Software\Foo____Bar",
            out var kind, out var root, out var keyPath, out var valueName, out var warning));
        Assert.Equal(SavedStateKind.NotExisting, kind);
        Assert.Equal(RegistryRoot.LocalMachine, root);
        Assert.Equal(@"Software\Foo", keyPath);
        Assert.Equal("Bar", valueName);
        Assert.Null(warning);
    }

    [Fact]
    public void Parses_a_value_name_that_contains_a_backslash() // Review Focus #1
    {
        Assert.True(RegistryKeyNames.TryParse(
            @"SavedStateNew_CURRENT_USER\Software\Foo____Bar\Baz",
            out _, out _, out var keyPath, out var valueName, out _));
        Assert.Equal(@"Software\Foo", keyPath);
        Assert.Equal(@"Bar\Baz", valueName);
    }

    [Fact]
    public void Splits_on_the_last_separator_not_the_first() // Review Focus #1
    {
        // The separator appears in the key path *and* again before the value. Splitting at the
        // first `____` yields "Software\My" + "Key____V" and restores to the wrong key while
        // reporting no error at all. Go uses strings.LastIndex (registry_utils.go:536).
        Assert.True(RegistryKeyNames.TryParse(
            @"SavedStateNew_CURRENT_USER\Software\My____Key____V",
            out _, out _, out var keyPath, out var valueName, out _));
        Assert.Equal(@"Software\My____Key", keyPath);
        Assert.Equal("V", valueName);
    }

    [Fact]
    public void Round_trips_a_key_path_containing_the_separator()
    {
        const string keyPath = @"Software\My____Key";
        var formatted = RegistryKeyNames.Format(RegistryRoot.CurrentUser, keyPath, "V");
        Assert.True(RegistryKeyNames.TryParse(formatted, out _, out _, out var parsedPath, out var parsedValue, out _));
        Assert.Equal(keyPath, parsedPath);
        Assert.Equal("V", parsedValue);
    }

    [Fact]
    public void Parses_a_legacy_name_with_single_underscore() // Review Focus #2
    {
        Assert.True(RegistryKeyNames.TryParse(
            @"SavedState_CURRENT_USER\Software\Foo_Bar",
            out var kind, out var root, out var keyPath, out var valueName, out _));
        Assert.Equal(SavedStateKind.LegacyDword, kind);
        Assert.Equal(RegistryRoot.CurrentUser, root);
        Assert.Equal(@"Software\Foo", keyPath);
        Assert.Equal("Bar", valueName);
    }

    [Fact]
    public void Splits_a_legacy_name_on_the_last_underscore() // Review Focus #2
    {
        // Discriminating case. `Software\My_Foo_Bar` has a single underscore in the remainder,
        // so first-match and last-match agree and the test proves nothing. This one does not:
        // Go takes strings.LastIndex (registry_utils.go:509) and so must we.
        Assert.True(RegistryKeyNames.TryParse(
            @"SavedState_CURRENT_USER\Software\My_Foo_Bar_Baz",
            out _, out _, out var keyPath, out var valueName, out _));
        Assert.Equal(@"Software\My_Foo_Bar", keyPath);
        Assert.Equal("Baz", valueName);
    }

    [Fact]
    public void Legacy_names_with_a_key_path_containing_underscores_resolve_the_way_go_resolves_them()
    {
        // Go mis-splits this too, and that is the point: faithfulness, not correctness.
        Assert.True(RegistryKeyNames.TryParse(
            @"SavedState_CURRENT_USER\Software\My_Foo_Bar",
            out _, out _, out var keyPath, out var valueName, out _));
        Assert.Equal(@"Software\My_Foo", keyPath);
        Assert.Equal("Bar", valueName);
    }

    [Fact]
    public void Reports_an_unresolvable_name_with_a_warning_instead_of_guessing()
    {
        Assert.True(RegistryKeyNames.TryParse(
            @"SavedStateNew_NOT_A_ROOT\Software\Foo____Bar",
            out _, out _, out _, out _, out var warning));
        Assert.NotNull(warning);
        Assert.Contains("NOT_A_ROOT", warning);
    }

    [Fact]
    public void Non_registry_names_round_trip()
    {
        // Lowercase `recall` because that is what the Go tool persists (recall_feature.go:50).
        var name = RegistryKeyNames.FormatNonReg(new MeasureId("recall"));
        Assert.Equal("SavedStateNonReg_recall", name);
        Assert.True(RegistryKeyNames.TryParseNonReg(name, out var feature));
        Assert.Equal("recall", feature.Value);
    }

    [Fact]
    public void Non_registry_names_match_the_go_tools_spelling_exactly()
    {
        // Guards the byte-compat surface. The parser deliberately does NOT validate the feature
        // id against a closed set — that would refuse a future Go feature's saved state at
        // restore. What matters is that a capitalised id round-trips to a *different* id, so
        // Task 5's exact-name lookup misses the Go tool's `SavedStateNonReg_recall` instead of
        // silently matching it.
        Assert.Equal("SavedStateNonReg_recall", RegistryKeyNames.FormatNonReg(new MeasureId("recall")));
        Assert.True(RegistryKeyNames.TryParseNonReg("SavedStateNonReg_Recall", out var capitalised));
        Assert.Equal("Recall", capitalised.Value);
        Assert.NotEqual(new MeasureId("recall"), capitalised);
    }

    [Fact]
    public void Non_registry_names_round_trip_for_an_arbitrary_feature()
    {
        // Asymmetric format/parse pairs are how a future Go feature becomes unrestorable.
        var name = RegistryKeyNames.FormatNonReg(new MeasureId("SomethingNew"));
        Assert.True(RegistryKeyNames.TryParseNonReg(name, out var feature));
        Assert.Equal("SomethingNew", feature.Value);
    }

    [Fact]
    public void Non_registry_parse_rejects_a_bad_prefix_or_an_empty_feature()
    {
        Assert.False(RegistryKeyNames.TryParseNonReg("SavedStateNew_recall", out _));
        Assert.False(RegistryKeyNames.TryParseNonReg("SavedStateNonReg_", out _));
        Assert.False(RegistryKeyNames.TryParseNonReg("", out _));
        Assert.False(RegistryKeyNames.TryParseNonReg(null!, out _));
    }

    [Fact]
    public void Rejects_a_name_that_carries_no_known_prefix()
    {
        Assert.False(RegistryKeyNames.TryParse("", out var kind, out var root, out var keyPath,
            out var valueName, out var warning));
        Assert.Equal(default, kind);
        Assert.Equal(default, root);
        Assert.Equal(string.Empty, keyPath);
        Assert.Equal(string.Empty, valueName);
        Assert.Null(warning);

        Assert.False(RegistryKeyNames.TryParse("SavedState", out _, out _, out _, out _, out _));
        Assert.False(RegistryKeyNames.TryParse("Something", out _, out _, out _, out _, out _));
        Assert.False(RegistryKeyNames.TryParse("SavedStateNew", out _, out _, out _, out _, out _));

        // No registry value name is null, but the parser is total rather than a crash waiting
        // for a caller to pass one.
        Assert.False(RegistryKeyNames.TryParse(null!, out _, out _, out var nullPath,
            out var nullValue, out var nullWarning));
        Assert.Equal(string.Empty, nullPath);
        Assert.Equal(string.Empty, nullValue);
        Assert.Null(nullWarning);
    }

    [Theory]
    [InlineData(@"SavedStateNew_CURRENT_USER\Software")]
    [InlineData(@"SavedStateNewSZ_CURRENT_USER\Software")]
    [InlineData(@"SavedStateNotExisting_CURRENT_USER\Software")]
    [InlineData(@"SavedState_CURRENT_USER\Software")]
    public void Warns_when_the_remainder_holds_no_separator(string name)
    {
        // Go's LastIndex returns -1, so regKey[LastIndex(...)+4:] becomes regKey[3:] and it
        // would restore the value name "tware" under "Software" (legacy: key == value ==
        // remainder). Unreachable from Go's four write sites, so warn rather than guess.
        Assert.True(RegistryKeyNames.TryParse(
            name, out _, out var root, out var keyPath, out var valueName, out var warning));
        Assert.Equal(RegistryRoot.CurrentUser, root);
        Assert.Equal(string.Empty, keyPath);
        Assert.Equal(string.Empty, valueName);
        Assert.NotNull(warning);
    }

    [Theory]
    [InlineData("SavedStateNew_")]
    [InlineData("SavedStateNewSZ_")]
    [InlineData("SavedStateNotExisting_")]
    [InlineData("SavedState_")]
    public void Warns_when_nothing_follows_the_prefix(string name)
    {
        Assert.True(RegistryKeyNames.TryParse(
            name, out _, out _, out var keyPath, out var valueName, out var warning));
        Assert.Equal(string.Empty, keyPath);
        Assert.Equal(string.Empty, valueName);
        Assert.NotNull(warning);
    }

    [Theory]
    [InlineData("SavedStateNew_CURRENT_USER")]
    [InlineData("SavedStateNewSZ_CURRENT_USER")]
    [InlineData("SavedStateNotExisting_CURRENT_USER")]
    [InlineData("SavedState_CURRENT_USER")]
    public void Warns_when_there_is_no_key_path_after_the_root_token(string name)
    {
        Assert.True(RegistryKeyNames.TryParse(
            name, out _, out _, out var keyPath, out var valueName, out var warning));
        Assert.Equal(string.Empty, keyPath);
        Assert.Equal(string.Empty, valueName);
        Assert.NotNull(warning);
    }

    [Fact]
    public void No_prefix_is_a_prefix_of_another_so_dispatch_order_is_defensive()
    {
        var prefixes = new[]
        {
            RegistryKeyNames.NewDwordPrefix,
            RegistryKeyNames.NewStringPrefix,
            RegistryKeyNames.NotExistingPrefix,
            RegistryKeyNames.LegacyPrefix,
        };

        foreach (var prefix in prefixes)
            Assert.All(prefixes, other => Assert.False(
                other != prefix && other.StartsWith(prefix, StringComparison.Ordinal)));
    }

    [Fact]
    public void The_saved_state_kinds_are_exactly_these_five_in_this_order()
    {
        // LegacyString is unreachable, and the member is kept on purpose so a future
        // legacy-string format does not fall into LegacyDword. Pinning the set and the order
        // keeps a `switch` that handles it explicitly compiling.
        Assert.Equal(
            new[] { "Dword", "String", "NotExisting", "LegacyDword", "LegacyString" },
            Enum.GetNames<SavedStateKind>());
    }

    [Fact]
    public void The_entry_carries_its_fields_by_name_and_flags_a_warning()
    {
        // Task 5 builds SavedStateEntry from these fields and reads Warning first, so the
        // shape is a contract in its own right.
        var resolved = new SavedStateEntry(
            SavedStateKind.Dword, RegistryRoot.LocalMachine, @"Software\Foo", "Bar", null);
        Assert.Equal(SavedStateKind.Dword, resolved.Kind);
        Assert.Equal(RegistryRoot.LocalMachine, resolved.Root);
        Assert.Equal(@"Software\Foo", resolved.KeyPath);
        Assert.Equal("Bar", resolved.ValueName);
        Assert.Null(resolved.Warning);

        var unresolvable = resolved with { Warning = "unresolvable" };
        Assert.Equal("unresolvable", unresolvable.Warning);
        Assert.Equal(@"Software\Foo", unresolvable.KeyPath);
    }
}
