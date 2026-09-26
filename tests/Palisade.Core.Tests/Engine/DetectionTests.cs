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

public class DetectionTests
{
    [Fact]
    public void Without_elevation_exactly_the_14_privileged_measures_are_unavailable()
    {
        var detector = EngineFactory.BuildDetector(isElevated: false);
        var results = detector.DetectAll();
        Assert.Equal(14, results.Count(r => r.State == MeasureState.Unavailable));
        Assert.All(
            results.Where(r => r.State == MeasureState.Unavailable),
            r => Assert.False(string.IsNullOrWhiteSpace(r.Unavailable!.Reason)));
    }

    [Fact]
    public void Elevation_reason_names_the_measure() // spec defect #11
    {
        var detector = EngineFactory.BuildDetector(isElevated: false);
        var cmd = detector.Detect(MeasureCatalog.Get(new MeasureId("Cmd")));
        Assert.Equal(MeasureState.Unavailable, cmd.State);
        Assert.Contains("cmd", cmd.Unavailable!.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Elevation_declined_reports_every_other_measure_normally()
    {
        // Declining elevation must not blank the machine: the 12 unprivileged measures are
        // still detected, which is what lets the UI show them at all.
        var detector = EngineFactory.BuildDetector(isElevated: false);
        var results = detector.DetectAll();
        Assert.Equal(12, results.Count(r => r.State != MeasureState.Unavailable));
    }

    [Fact]
    public void Detection_is_stable_across_runs()
    {
        var detector = EngineFactory.BuildDetector(isElevated: true);
        var first = string.Join(";", detector.DetectAll().Select(r => $"{r.Id}:{r.State}"));
        var second = string.Join(";", detector.DetectAll().Select(r => $"{r.Id}:{r.State}"));
        Assert.Equal(first, second);
    }

    [Fact]
    public void Every_detection_result_carries_the_measures_declared_constraints()
    {
        var detector = EngineFactory.BuildDetector(isElevated: true);
        foreach (var descriptor in MeasureCatalog.All)
        {
            var result = detector.Detect(descriptor);
            Assert.Equal(
                descriptor.ConstrainedBy.Select(c => c.Target.Value).OrderBy(v => v, StringComparer.Ordinal),
                result.ConstrainedBy.Select(id => id.Value).OrderBy(v => v, StringComparer.Ordinal));
        }
    }
}
