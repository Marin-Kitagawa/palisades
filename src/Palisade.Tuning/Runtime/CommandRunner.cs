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

using System.Diagnostics;

namespace Palisade.Tuning.Runtime;

/// <summary>
/// Runs one tuning command through cmd, exactly as RyTuneX's
/// OptimizationOptions.StartInCmd does. Failures are reported, not thrown:
/// a reg add on a key that does not exist on this build is a normal outcome.
/// </summary>
public static class CommandRunner
{
    public sealed record CommandResult(string Command, int ExitCode, string Output);

    public static async Task<CommandResult> RunAsync(string command, CancellationToken token = default)
    {
        var psi = new ProcessStartInfo("cmd.exe", $"/c {command}")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"cmd.exe could not be started for: {command}");
        var output = await process.StandardOutput.ReadToEndAsync(token).ConfigureAwait(false);
        var error = await process.StandardError.ReadToEndAsync(token).ConfigureAwait(false);
        await process.WaitForExitAsync(token).ConfigureAwait(false);

        return new CommandResult(command, process.ExitCode, (output + "\n" + error).Trim());
    }

    public static async Task<IReadOnlyList<CommandResult>> RunAllAsync(
        IEnumerable<string> commands, CancellationToken token = default)
    {
        var results = new List<CommandResult>();
        foreach (var command in commands)
        {
            token.ThrowIfCancellationRequested();
            results.Add(await RunAsync(command, token).ConfigureAwait(false));
        }
        return results;
    }
}
