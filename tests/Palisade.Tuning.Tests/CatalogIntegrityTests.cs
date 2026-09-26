// Palisade Tuning — UI-independent port of RyTuneX tuning logic.
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

using Palisade.Tuning;
using Xunit;

namespace Palisade.Tuning.Tests;

/// <summary>
/// Catalog integrity: every toggle must carry a stable id, a title, a
/// description, a known category, and at least one command in each direction.
/// </summary>
public class CatalogIntegrityTests
{
    public static TheoryData<string> AllOptionIds()
    {
        var data = new TheoryData<string>();
        foreach (var option in TuningCatalog.All)
        {
            data.Add(option.Id);
        }
        return data;
    }

    [Fact]
    public void Ids_are_unique()
    {
        var ids = TuningCatalog.All.Select(o => o.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct(StringComparer.Ordinal).Count());
    }

    [Theory]
    [MemberData(nameof(AllOptionIds))]
    public void Every_option_has_title_description_and_commands(string id)
    {
        var option = TuningCatalog.Get(id);
        Assert.False(string.IsNullOrWhiteSpace(option.Title));
        Assert.False(string.IsNullOrWhiteSpace(option.Description));
        Assert.NotEmpty(option.ApplyCommands);
        Assert.NotEmpty(option.RevertCommands);
        Assert.All(option.ApplyCommands, c => Assert.False(string.IsNullOrWhiteSpace(c)));
        Assert.All(option.RevertCommands, c => Assert.False(string.IsNullOrWhiteSpace(c)));
        Assert.Contains(option.Category,
            (System.Collections.Generic.IEnumerable<string>)["AI", "Explorer", "Performance", "Gaming", "System", "Security", "Telemetry", "Services", "Network", "Personalization"]);
    }

    [Fact]
    public void Get_throws_for_unknown_id()
    {
        Assert.Throws<KeyNotFoundException>(() => TuningCatalog.Get("no-such-option-xyz"));
    }
}
