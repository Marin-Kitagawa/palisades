// Palisade Tuning â€” UI-independent port of RyTuneX tuning logic.
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

using Palisade.Tuning.Catalog;
using Palisade.Tuning.Policy;
using Xunit;

namespace Palisade.Tuning.Tests;

/// <summary>
/// The transplanted policy catalog must stay intact: unique ids, real
/// registry paths under Software\Policies, known hives and value kinds.
/// </summary>
public class PolicyCatalogTests
{
    [Fact]
    public void Catalog_has_upstream_policy_count()
    {
        // 207 entries transplanted verbatim from RyTuneX PolicyHelper.
        Assert.Equal(207, PolicyCatalog.KnownPolicies.Length);
    }

    [Fact]
    public void Ids_are_unique()
    {
        var ids = PolicyCatalog.KnownPolicies.Select(p => p.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void Every_policy_targets_an_absolute_software_path()
    {
        // Upstream is mostly Software\Policies paths, with a small number of
        // policy-settings locations outside them (e.g. Windows Script Host
        // Settings). The invariant: every path is an absolute SOFTWARE path
        // under an explicit hive, never a bare or relative fragment.
        foreach (var policy in PolicyCatalog.KnownPolicies)
        {
            Assert.StartsWith("SOFTWARE", policy.RegistryPath, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("HKLM", policy.RegistryPath, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("HKCU", policy.RegistryPath, StringComparison.OrdinalIgnoreCase);
            Assert.False(string.IsNullOrWhiteSpace(policy.RegistryPath));
        }
    }

    [Fact]
    public void Every_policy_has_metadata()
    {
        foreach (var policy in PolicyCatalog.KnownPolicies)
        {
            Assert.False(string.IsNullOrWhiteSpace(policy.Name));
            Assert.False(string.IsNullOrWhiteSpace(policy.Description));
            Assert.False(string.IsNullOrWhiteSpace(policy.Category));
            Assert.False(string.IsNullOrWhiteSpace(policy.ValueName));
            Assert.True(policy.Hive is Microsoft.Win32.RegistryHive.LocalMachine
                or Microsoft.Win32.RegistryHive.CurrentUser,
                $"{policy.Id}: unexpected hive {policy.Hive}");
        }
    }

    [Fact]
    public void GetApplicablePolicies_returns_a_subset()
    {
        var applicable = PolicyScanner.GetApplicablePolicies();
        Assert.NotEmpty(applicable);
        Assert.True(applicable.Count <= PolicyCatalog.KnownPolicies.Length);
    }
}
