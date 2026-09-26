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

using Palisade.Core.Mechanisms;
using Palisade.Core.Models;
using Palisade.Core.Registry;

namespace Palisade.Core.Tests.Mechanisms;

public class RegistryMechanismTests
{
    [Fact]
    public void Dword_detects_slack_when_the_value_is_at_its_original() // Review Focus #3
    {
        var registry = new InMemoryRegistry();
        var descriptor = MeasureCatalog.Get(new MeasureId("Lsa"));
        using (var key = registry.OpenKey(RegistryRoot.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", true)!)
        {
            key.SetDword("RunAsPPL", 0);
        }

        var handler = new RegistryDwordHandler();
        var targets = handler.ResolveTargets(descriptor, new StubVersionResolver());
        Assert.Equal(MeasureState.Slack, handler.Detect(descriptor, targets, registry));
    }

    [Fact]
    public void Dword_detects_taut_after_apply()
    {
        var registry = new InMemoryRegistry();
        var store = new SavedStateStore(registry, RegistryOptions.Default);
        var descriptor = MeasureCatalog.Get(new MeasureId("Lsa"));
        var handler = new RegistryDwordHandler();
        var targets = handler.ResolveTargets(descriptor, new StubVersionResolver());

        handler.Apply(descriptor, targets, registry, store);
        Assert.Equal(MeasureState.Taut, handler.Detect(descriptor, targets, registry));

        handler.Restore(descriptor, targets, registry, store);
        Assert.Equal(MeasureState.Slack, handler.Detect(descriptor, targets, registry));
    }

    [Fact]
    public void Dword_detects_stressed_when_something_else_set_the_value_first() // Review Focus #3
    {
        var registry = new InMemoryRegistry();
        var store = new SavedStateStore(registry, RegistryOptions.Default);
        var descriptor = MeasureCatalog.Get(new MeasureId("Lsa"));
        using (var key = registry.OpenKey(RegistryRoot.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", true)!)
        {
            key.SetDword("RunAsPPL", 1); // Group Policy, not us.
        }

        var handler = new RegistryDwordHandler();
        var targets = handler.ResolveTargets(descriptor, new StubVersionResolver());
        Assert.Equal(MeasureState.Stressed, handler.Detect(descriptor, targets, registry));
    }

    [Fact]
    public void Applying_over_a_stressed_value_preserves_the_preexisting_value() // Review Focus #3
    {
        var registry = new InMemoryRegistry();
        var store = new SavedStateStore(registry, RegistryOptions.Default);
        var descriptor = MeasureCatalog.Get(new MeasureId("Lsa"));
        using (var key = registry.OpenKey(RegistryRoot.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", true)!)
        {
            key.SetDword("RunAsPPL", 1);
        }

        var handler = new RegistryDwordHandler();
        var targets = handler.ResolveTargets(descriptor, new StubVersionResolver());
        handler.Apply(descriptor, targets, registry, store);

        handler.Restore(descriptor, targets, registry, store);
        using var check = registry.OpenKey(RegistryRoot.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", false)!;
        Assert.True(check.TryGetDword("RunAsPPL", out var restored));
        Assert.Equal(1u, restored); // The pre-existing 1, not 0.
    }

    [Fact]
    public void NotExisting_restore_deletes_a_value_created_after_hardening() // Review Focus #4
    {
        var registry = new InMemoryRegistry();
        var store = new SavedStateStore(registry, RegistryOptions.Default);
        var descriptor = MeasureCatalog.Get(new MeasureId("Lsa"));
        var handler = new RegistryDwordHandler();
        var targets = handler.ResolveTargets(descriptor, new StubVersionResolver());

        store.SaveNotExisting(RegistryRoot.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL");
        using (var key = registry.OpenKey(RegistryRoot.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", true)!)
        {
            key.SetDword("RunAsPPL", 5); // Created after we recorded "did not exist".
        }

        handler.Restore(descriptor, targets, registry, store);
        using var check = registry.OpenKey(RegistryRoot.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", false)!;
        Assert.False(check.TryGetDword("RunAsPPL", out _));
    }

    [Fact]
    public void String_measure_detects_applies_and_restores_both_kinds_it_writes()
    {
        // LibreOffice measures are RegistryString, but each writes an REG_SZ "Value" and an
        // REG_DWORD "Final" at one path. One dropped kind would read as a complete port.
        var registry = new InMemoryRegistry();
        var store = new SavedStateStore(registry, RegistryOptions.Default);
        var descriptor = MeasureCatalog.Get(new MeasureId("LibreOfficeCtrlClickHyperlinks"));
        var handler = new RegistryStringHandler();
        var targets = handler.ResolveTargets(descriptor, new StubVersionResolver());
        Assert.Equal(2, targets.Count);

        Assert.Equal(MeasureState.Slack, handler.Detect(descriptor, targets, registry));
        handler.Apply(descriptor, targets, registry, store);
        Assert.Equal(MeasureState.Taut, handler.Detect(descriptor, targets, registry));

        using (var key = registry.OpenKey(RegistryRoot.LocalMachine, descriptor.Targets[0].Path, false)!)
        {
            Assert.True(key.TryGetString("Value", out var value));
            Assert.Equal("true", value);
            Assert.True(key.TryGetDword("Final", out var final));
            Assert.Equal(1u, final);
        }

        handler.Restore(descriptor, targets, registry, store);
        Assert.Equal(MeasureState.Slack, handler.Detect(descriptor, targets, registry));
    }

    [Fact]
    public void DisallowRun_restore_removes_only_our_entry() // Review Focus #5
    {
        var registry = new InMemoryRegistry();
        var store = new SavedStateStore(registry, RegistryOptions.Default);
        var descriptor = MeasureCatalog.Get(new MeasureId("Cmd"));
        var handler = new DisallowRunHandler();
        var targets = handler.ResolveTargets(descriptor, new StubVersionResolver());

        // A foreign program already owns index 1. Ours must land at index 2, and restore
        // must put the foreign entry back at index 1 — that is what compaction means.
        using (var key = registry.OpenKey(RegistryRoot.CurrentUser,
            @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun", true)!)
        {
            key.SetString("1", "wscript.exe");
        }

        handler.Apply(descriptor, targets, registry, store);
        handler.Restore(descriptor, targets, registry, store);

        using var check = registry.OpenKey(RegistryRoot.CurrentUser,
            @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun", false)!;
        Assert.Equal(new[] { "1" }, check.GetValueNames()); // the gap closed
        Assert.True(check.TryGetString("1", out var remaining));
        Assert.Equal("wscript.exe", remaining);
        Assert.DoesNotContain("cmd.exe", check.GetValueNames());
    }

    [Fact]
    public void DisallowRun_restore_deletes_the_subkey_when_nothing_is_left() // cmd.go:136
    {
        var registry = new InMemoryRegistry();
        var store = new SavedStateStore(registry, RegistryOptions.Default);
        var descriptor = MeasureCatalog.Get(new MeasureId("Cmd"));
        var handler = new DisallowRunHandler();
        var targets = handler.ResolveTargets(descriptor, new StubVersionResolver());

        handler.Apply(descriptor, targets, registry, store);
        handler.Restore(descriptor, targets, registry, store);

        // An empty DisallowRun subkey denies nothing, but upstream removes it, and leaving
        // residue the Go tool would not leave is a divergence in its own right.
        Assert.Null(registry.OpenKey(RegistryRoot.CurrentUser,
            @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun", false));
    }

    [Fact]
    public void DisallowRun_apply_appends_after_a_foreign_entry_instead_of_overwriting_it()
    {
        var registry = new InMemoryRegistry();
        var store = new SavedStateStore(registry, RegistryOptions.Default);
        var descriptor = MeasureCatalog.Get(new MeasureId("PowerShell"));
        var handler = new DisallowRunHandler();
        var targets = handler.ResolveTargets(descriptor, new StubVersionResolver());

        using (var key = registry.OpenKey(RegistryRoot.CurrentUser,
            @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun", true)!)
        {
            key.SetString("1", "wscript.exe");
            key.SetString("3", "notepad.exe"); // A gap at 2 and a foreign entry past it.
        }

        handler.Apply(descriptor, targets, registry, store);

        using var check = registry.OpenKey(RegistryRoot.CurrentUser,
            @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun", false)!;
        Assert.True(check.TryGetString("2", out var first));
        Assert.Equal("powershell_ise.exe", first);
        Assert.True(check.TryGetString("4", out var second));
        Assert.Equal("powershell.exe", second);
        Assert.True(check.TryGetString("3", out var untouched));
        Assert.Equal("notepad.exe", untouched);
    }

    [Fact]
    public void Restore_does_not_resurrect_a_deleted_key() // Global Constraint 6
    {
        var registry = new InMemoryRegistry();
        var store = new SavedStateStore(registry, RegistryOptions.Default);
        var descriptor = MeasureCatalog.Get(new MeasureId("OfficeDde"));
        var handler = new RegistryDwordHandler();
        var targets = handler.ResolveTargets(descriptor, new StubVersionResolver());

        handler.Apply(descriptor, targets, registry, store);
        // Simulate the user or a cleanup tool removing the key after hardening.
        foreach (var target in targets)
        {
            registry.DeleteKey(target.Root, target.KeyPath);
        }

        handler.Restore(descriptor, targets, registry, store);

        // Go's restore opens the key and skips on failure; it never re-creates it.
        Assert.All(targets, t => Assert.Null(registry.OpenKey(t.Root, t.KeyPath, false)));
    }

    [Fact]
    public void FileAssociation_detects_hardened_after_apply() // spec defect #1
    {
        var registry = new InMemoryRegistry();
        var store = new SavedStateStore(registry, RegistryOptions.Default);
        var descriptor = MeasureCatalog.Get(new MeasureId("FileAssociations"));
        var handler = new FileAssociationHandler();
        var targets = handler.ResolveTargets(descriptor, new StubVersionResolver());
        Assert.Equal(FileAssociationTable.Restrictions.Count, targets.Count);

        Assert.Equal(MeasureState.Slack, handler.Detect(descriptor, targets, registry));
        handler.Apply(descriptor, targets, registry, store);
        Assert.Equal(MeasureState.Taut, handler.Detect(descriptor, targets, registry));
        handler.Restore(descriptor, targets, registry, store);
        Assert.Equal(MeasureState.Slack, handler.Detect(descriptor, targets, registry));
    }
}
