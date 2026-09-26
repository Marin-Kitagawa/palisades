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

public class SavedStateStoreTests
{
    [Fact]
    public void Saves_and_reads_back_a_dword_entry()
    {
        var registry = new InMemoryRegistry();
        var store = new SavedStateStore(registry, RegistryOptions.Default);
        store.SaveDword(RegistryRoot.CurrentUser, @"Software\Foo", "Bar", 7);

        var entry = Assert.Single(store.ReadAll());
        Assert.Equal(SavedStateKind.Dword, entry.Kind);
        Assert.Equal(@"Software\Foo", entry.KeyPath);
        Assert.Equal("Bar", entry.ValueName);
    }

    [Fact]
    public void Writes_only_the_four_current_prefixes() // Global Constraints: never write legacy
    {
        var registry = new InMemoryRegistry();
        var store = new SavedStateStore(registry, RegistryOptions.Default);
        store.SaveDword(RegistryRoot.CurrentUser, @"Software\Foo", "Bar", 7);
        store.SaveString(RegistryRoot.CurrentUser, @"Software\Foo", "Baz", "x");
        store.SaveNotExisting(RegistryRoot.CurrentUser, @"Software\Foo", "Qux");
        store.SaveNonReg(new MeasureId("recall"), "disabled");

        using var key = registry.OpenKey(RegistryRoot.CurrentUser, RegistryOptions.DefaultSavedStateKeyPath, true)!;
        Assert.All(key.GetValueNames(), n => Assert.DoesNotContain(RegistryKeyNames.LegacyPrefix, n));
        Assert.Contains(key.GetValueNames(), n => n.StartsWith(RegistryKeyNames.NewDwordPrefix, StringComparison.Ordinal));
        Assert.Contains(key.GetValueNames(), n => n.StartsWith(RegistryKeyNames.NewStringPrefix, StringComparison.Ordinal));
        Assert.Contains(key.GetValueNames(), n => n.StartsWith(RegistryKeyNames.NotExistingPrefix, StringComparison.Ordinal));
        Assert.Contains(key.GetValueNames(), n => n.StartsWith(RegistryKeyNames.NonRegPrefix, StringComparison.Ordinal));
    }

    [Fact]
    public void Reads_a_legacy_entry_written_by_the_go_tool()
    {
        var registry = new InMemoryRegistry();
        using (var key = registry.OpenKey(RegistryRoot.CurrentUser, RegistryOptions.DefaultSavedStateKeyPath, true)!)
        {
            key.SetDword(@"SavedState_CURRENT_USER\Software\Foo_Bar", 3);
        }

        var store = new SavedStateStore(registry, RegistryOptions.Default);
        var entry = Assert.Single(store.ReadAll());
        Assert.Equal(SavedStateKind.LegacyDword, entry.Kind);
        Assert.Equal(@"Software\Foo", entry.KeyPath);
    }

    [Fact]
    public void Reports_a_malformed_entry_rather_than_dropping_it_silently()
    {
        var registry = new InMemoryRegistry();
        using (var key = registry.OpenKey(RegistryRoot.CurrentUser, RegistryOptions.DefaultSavedStateKeyPath, true)!)
        {
            key.SetDword(@"SavedStateNew_NOPE\Software\Foo____Bar", 1);
        }

        var store = new SavedStateStore(registry, RegistryOptions.Default);
        var entry = Assert.Single(store.ReadAll());
        Assert.NotNull(entry.Warning);
    }

    [Fact]
    public void Non_registry_state_round_trips_and_deletes()
    {
        var registry = new InMemoryRegistry();
        var store = new SavedStateStore(registry, RegistryOptions.Default);
        store.SaveNonReg(new MeasureId("recall"), "disabled");
        Assert.True(store.TryGetNonReg(new MeasureId("recall"), out var state));
        Assert.Equal("disabled", state);
        store.DeleteNonReg(new MeasureId("recall"));
        Assert.False(store.TryGetNonReg(new MeasureId("recall"), out _));
    }

    [Fact]
    public void Clear_removes_every_entry_and_tolerates_an_absent_key()
    {
        var registry = new InMemoryRegistry();
        var store = new SavedStateStore(registry, RegistryOptions.Default);
        store.Clear(); // already absent: a no-op, not an error.
        store.SaveDword(RegistryRoot.CurrentUser, @"Software\Foo", "Bar", 7);
        store.SaveNonReg(new MeasureId("recall"), "disabled");

        store.Clear();

        Assert.Empty(store.ReadAll());
        Assert.False(store.TryGetNonReg(new MeasureId("recall"), out _));
    }

    [Fact]
    public void ReadAll_returns_an_empty_list_when_the_saved_state_key_is_absent()
    {
        var registry = new InMemoryRegistry();
        var store = new SavedStateStore(registry, RegistryOptions.Default);
        Assert.Empty(store.ReadAll());
    }
}
