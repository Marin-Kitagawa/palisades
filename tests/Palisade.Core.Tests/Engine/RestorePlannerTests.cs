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

using Palisade.Core.Engine;
using Palisade.Core.Models;

namespace Palisade.Core.Tests.Engine;

public class RestorePlannerTests
{
    [Fact]
    public void Restore_order_is_stable_across_100_runs() // spec defect #4
    {
        var orders = Enumerable.Range(0, 100)
            .Select(_ => string.Join(",", RestorePlanner.Order(MeasureCatalog.All).Select(i => i.Value)))
            .Distinct()
            .ToList();
        Assert.Single(orders);
    }

    [Fact]
    public void Restore_order_respects_every_declared_constraint() // spec defect #4
    {
        var order = RestorePlanner.Order(MeasureCatalog.All).Select(i => i.Value).ToList();
        foreach (var descriptor in MeasureCatalog.All)
        {
            foreach (var constraint in descriptor.ConstrainedBy)
            {
                Assert.True(
                    order.IndexOf(constraint.Target.Value) < order.IndexOf(descriptor.Id.Value),
                    $"{constraint.Target} is constrained by {descriptor.Id}, so it must be restored first");
            }
        }
    }

    [Fact]
    public void Restore_order_is_a_permutation_of_the_catalog()
    {
        var order = RestorePlanner.Order(MeasureCatalog.All).Select(i => i.Value).OrderBy(v => v, StringComparer.Ordinal).ToList();
        var expected = MeasureCatalog.All.Select(m => m.Id.Value).OrderBy(v => v, StringComparer.Ordinal).ToList();
        Assert.Equal(expected, order);
    }

    [Fact]
    public void Constraints_pointing_outside_the_set_do_not_block_it()
    {
        // Ordering {Cmd} alone must not wait for PowerShell, which is not in the set.
        var order = RestorePlanner.Order([MeasureCatalog.Get(new MeasureId("Cmd"))]).ToList();
        Assert.Equal(new[] { "Cmd" }, order.Select(id => id.Value));
    }

    [Fact]
    public void Constrained_pairs_restore_in_declared_order_inside_a_subset()
    {
        var subset = MeasureCatalog.All
            .Where(m => m.Id.Value is "Cmd" or "PowerShell" or "WindowsAsrRules" or "DefenderPua")
            .ToList();
        var order = RestorePlanner.Order(subset).Select(id => id.Value).ToList();

        Assert.True(order.IndexOf("PowerShell") < order.IndexOf("Cmd"));
        Assert.True(order.IndexOf("DefenderPua") < order.IndexOf("WindowsAsrRules"));
    }
}
