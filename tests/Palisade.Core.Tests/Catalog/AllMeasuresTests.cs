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
using Palisade.Core.Tests.Engine;

namespace Palisade.Core.Tests.Catalog;

public class AllMeasuresTests
{
    public static TheoryData<string> AllMeasureIds()
    {
        var data = new TheoryData<string>();
        foreach (var m in MeasureCatalog.All)
        {
            data.Add(m.Id.Value);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(AllMeasureIds))]
    public void Every_measure_detects_to_a_known_state_without_elevation(string id)
    {
        var engine = EngineFactory.BuildEngine(isElevated: false);
        var result = Assert.Single(engine.Detect(), r => r.Id.Value == id);
        Assert.True(Enum.IsDefined(result.State));
        if (result.State == MeasureState.Unavailable)
        {
            Assert.False(string.IsNullOrWhiteSpace(result.Unavailable!.Reason));
        }
    }

    [Theory]
    [MemberData(nameof(AllMeasureIds))]
    public void Every_measure_detects_to_a_known_state_with_elevation(string id)
    {
        var engine = EngineFactory.BuildEngine(isElevated: true);
        var result = Assert.Single(engine.Detect(), r => r.Id.Value == id);
        Assert.True(Enum.IsDefined(result.State));
    }

    [Theory]
    [MemberData(nameof(AllMeasureIds))]
    public void Every_measures_detect_survives_an_apply_and_restore_cycle(string id)
    {
        var engine = EngineFactory.BuildEngine(isElevated: true);
        engine.Apply(new[] { new MeasureId(id) });
        engine.RestoreAll();
        var result = Assert.Single(engine.Detect(), r => r.Id.Value == id);
        Assert.True(result.State is MeasureState.Slack or MeasureState.Unavailable,
            $"{id} was {result.State} after restore");
    }
}
