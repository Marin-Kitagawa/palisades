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

namespace Palisade.Core.Engine;

/// <summary>
/// Computes the restore order from the constraint graph. Static, stateless, and not
/// injected anywhere: the apply engine calls <see cref="Order"/> directly, and consumers
/// that need one measure's constraints read <see cref="MeasureDescriptor.ConstrainedBy"/>
/// themselves.
/// </summary>
/// <remarks>
/// A measure that is constrained by another restores <em>after</em> the measure constraining
/// it: undoing the dependent first is what leaves the shared registry value in a valid
/// state. The order is a topological sort (Kahn's algorithm over the edges implied by
/// <see cref="MeasureConstraint"/>) with ties broken on the ordinal comparison of
/// <see cref="MeasureId.Value"/> through a <c>SortedSet</c>, so the order is structural
/// rather than an accident of insertion order and is identical on every run. A cycle —
/// which the catalog does not contain — would leave the remaining measures appended in
/// ordinal order rather than deadlock the tool.
/// </remarks>
public static class RestorePlanner
{
    public static IReadOnlyList<MeasureId> Order(IEnumerable<MeasureDescriptor> descriptors)
    {
        var list = descriptors.ToList();
        var ids = list.Select(descriptor => descriptor.Id.Value).ToHashSet(StringComparer.Ordinal);

        var inDegree = list.ToDictionary(descriptor => descriptor.Id.Value, _ => 0, StringComparer.Ordinal);
        var dependents = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var descriptor in list)
        {
            foreach (var constraint in descriptor.ConstrainedBy)
            {
                // A constraint pointing outside the set orders nothing.
                if (!ids.Contains(constraint.Target.Value) || constraint.Target.Value == descriptor.Id.Value)
                {
                    continue;
                }

                if (!dependents.TryGetValue(constraint.Target.Value, out var edges))
                {
                    edges = [];
                    dependents[constraint.Target.Value] = edges;
                }

                edges.Add(descriptor.Id.Value);
                inDegree[descriptor.Id.Value]++;
            }
        }

        var ready = new SortedSet<string>(
            inDegree.Where(entry => entry.Value == 0).Select(entry => entry.Key),
            StringComparer.Ordinal);

        var order = new List<MeasureId>();
        while (ready.Count > 0)
        {
            var id = ready.Min!;
            ready.Remove(id);
            order.Add(new MeasureId(id));
            if (!dependents.TryGetValue(id, out var edges))
            {
                continue;
            }

            foreach (var dependent in edges)
            {
                if (--inDegree[dependent] == 0)
                {
                    ready.Add(dependent);
                }
            }
        }

        // Cycle fallback: no cycles exist in the catalog; if one ever arrives, stay
        // deterministic instead of deadlocking.
        var ordered = order.Select(id => id.Value).ToHashSet(StringComparer.Ordinal);
        foreach (var id in inDegree.Keys.OrderBy(id => id, StringComparer.Ordinal))
        {
            if (!ordered.Contains(id))
            {
                order.Add(new MeasureId(id));
            }
        }

        return order;
    }
}
