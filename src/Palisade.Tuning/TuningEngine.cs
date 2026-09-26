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
using Palisade.Tuning.Models;
using Palisade.Tuning.Runtime;

namespace Palisade.Tuning;

/// <summary>
/// All tuning options, aggregated across module catalogs.
/// </summary>
public static class TuningCatalog
{
    public static IReadOnlyList<TuningOption> All { get; } =
    [
        .. OptimizeCatalog.All,
        .. ServicesCatalog.All,
    ];

    public static TuningOption Get(string id) =>
        All.FirstOrDefault(o => o.Id == id)
        ?? throw new KeyNotFoundException($"No tuning option with id '{id}'.");
}

/// <summary>
/// Applies and reverts tuning options by running their command lists through
/// cmd, recording what was applied so it can be reverted exactly â€” the same
/// reversibility contract the hardening measures follow.
/// </summary>
public static class TuningEngine
{
    public sealed record TuningResult(string Id, string Direction, bool Ok, int FailedCommands, string Output);

    public static async Task<TuningResult> ApplyAsync(string optionId, CancellationToken token = default)
    {
        var option = TuningCatalog.Get(optionId);
        var results = await CommandRunner.RunAllAsync(option.ApplyCommands, token).ConfigureAwait(false);
        var failed = results.Count(r => r.ExitCode != 0);
        TuningStateStore.MarkApplied(optionId);
        return new TuningResult(
            optionId, "apply", failed == 0, failed,
            string.Join("\n", results.Where(r => r.Output.Length > 0).Select(r => r.Output)));
    }

    public static async Task<TuningResult> RevertAsync(string optionId, CancellationToken token = default)
    {
        var option = TuningCatalog.Get(optionId);
        var results = await CommandRunner.RunAllAsync(option.RevertCommands, token).ConfigureAwait(false);
        var failed = results.Count(r => r.ExitCode != 0);
        TuningStateStore.MarkReverted(optionId);
        return new TuningResult(
            optionId, "revert", failed == 0, failed,
            string.Join("\n", results.Where(r => r.Output.Length > 0).Select(r => r.Output)));
    }

    public static bool IsApplied(string optionId) => TuningStateStore.IsApplied(optionId);
}
