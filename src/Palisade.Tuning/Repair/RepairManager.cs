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

namespace Palisade.Tuning.Repair;

/// <summary>
/// System repair workflow: DISM component-store check/repair, SFC verify/scan
/// and CHKDSK, with upstream's output-based health heuristics. Runs the same
/// tools with the same arguments as RyTuneX's RepairPage workflow; output is
/// captured through standard pipes instead of a pseudo-console (documented
/// divergence — line content is the same, ordering is not interleaved live).
/// All operations require elevation.
/// </summary>
public static class RepairManager
{
    public static readonly string[] Components = ["DISM", "SFC", "CHKDSK"];

    public static string FriendlyName(string component) => component switch
    {
        "DISM" => "Windows image",
        "SFC" => "System files",
        "CHKDSK" => "System drive",
        _ => component,
    };

    public sealed record ComponentResult(
        string Name,
        bool? Health,
        IReadOnlyList<string> OutputLines,
        bool Scheduled = false);

    /// <summary>
    /// Checks system health: DISM /ScanHealth, SFC /verifyonly, CHKDSK scan.
    /// Returns per-component health: true = healthy, false = needs attention,
    /// null = undetermined.
    /// </summary>
    public static async Task<IReadOnlyList<ComponentResult>> CheckAsync(CancellationToken token = default)
    {
        var checkArgs = new Dictionary<string, string>
        {
            ["DISM"] = "/Online /Cleanup-Image /ScanHealth",
            ["SFC"] = "/verifyonly",
            ["CHKDSK"] = string.Empty,
        };

        var results = new List<ComponentResult>();
        foreach (var name in Components)
        {
            if (token.IsCancellationRequested)
            {
                break;
            }

            var lines = await RunToolAsync(name, checkArgs[name], stdin: null, token).ConfigureAwait(false);
            var health = DetermineHealth(name, lines);
            results.Add(new ComponentResult(name, health, lines));
        }
        return results;
    }

    /// <summary>
    /// Repairs flagged components: DISM /RestoreHealth, SFC /scannow, and a
    /// scheduled `chkdsk X: /f` at next reboot (upstream schedules rather than
    /// forcing a dismount while Windows runs).
    /// </summary>
    public static async Task<IReadOnlyList<ComponentResult>> RepairAsync(
        IEnumerable<string> components, CancellationToken token = default)
    {
        var repairArgs = new Dictionary<string, string>
        {
            ["DISM"] = "/Online /Cleanup-Image /RestoreHealth",
            ["SFC"] = "/scannow",
            ["CHKDSK"] = "/f",
        };

        var results = new List<ComponentResult>();
        foreach (var name in components)
        {
            if (token.IsCancellationRequested)
            {
                break;
            }

            if (name == "CHKDSK")
            {
                var driveRoot = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows))?.TrimEnd('\\') ?? "C:";
                var result = await Runtime.CommandRunner.RunAsync($"echo Y|chkdsk {driveRoot} /f", token).ConfigureAwait(false);
                results.Add(new ComponentResult(
                    name, null,
                    [result.Output, "(scheduled for the next restart)"],
                    Scheduled: true));
                continue;
            }

            var lines = await RunToolAsync(name, repairArgs[name], stdin: null, token).ConfigureAwait(false);
            var health = DetermineHealth(name, lines) ?? true;
            results.Add(new ComponentResult(name, health, lines));
        }
        return results;
    }

    /// <summary>
    /// Upstream's output-based health detection, verbatim heuristics.
    /// </summary>
    public static bool? DetermineHealth(string name, IReadOnlyList<string> outputLines)
    {
        if (outputLines.Count == 0)
        {
            return null;
        }

        var text = string.Join("\n", outputLines).ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        return name switch
        {
            "DISM" =>
                text.Contains("no component store corruption") || text.Contains("operation completed successfully")
                    ? true
                    : text.Contains("repairable") || text.Contains("corruption detected") || text.Contains("restore health")
                        ? false
                        : null,

            "SFC" =>
                text.Contains("did not find any integrity violations")
                    ? true
                    : text.Contains("found corrupt files")
                        ? false
                        : null,

            "CHKDSK" =>
                text.Contains("found no problems") || text.Contains("no further action is required")
                    ? true
                    : text.Contains("errors found") || text.Contains("found problems")
                        ? false
                        : null,

            _ => null,
        };
    }

    private static string GetSystemToolPath(string tool) =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), tool);

    private static async Task<IReadOnlyList<string>> RunToolAsync(
        string name, string args, string? stdin, CancellationToken token)
    {
        var toolExecutable = name switch
        {
            "DISM" => "dism.exe",
            "SFC" => "sfc.exe",
            "CHKDSK" => "chkdsk.exe",
            _ => name + ".exe",
        };

        var psi = new ProcessStartInfo
        {
            FileName = GetSystemToolPath(toolExecutable),
            Arguments = args,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = stdin != null,
            CreateNoWindow = true,
        };

        var lines = new List<string>();
        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"{toolExecutable} could not be started");

        var stdout = process.StandardOutput;
        var stderr = process.StandardError;
        if (stdin != null)
        {
            await process.StandardInput.WriteAsync(stdin).ConfigureAwait(false);
            process.StandardInput.Close();
        }

        var outTask = Task.Run(async () =>
        {
            string? line;
            while ((line = await stdout.ReadLineAsync(token).ConfigureAwait(false)) != null)
            {
                lock (lines)
                {
                    lines.Add(line);
                }
            }
        }, CancellationToken.None);

        var errTask = Task.Run(async () =>
        {
            string? line;
            while ((line = await stderr.ReadLineAsync(token).ConfigureAwait(false)) != null)
            {
                lock (lines)
                {
                    lines.Add(line);
                }
            }
        }, CancellationToken.None);

        try
        {
            await process.WaitForExitAsync(token).ConfigureAwait(false);
            await Task.WhenAll(outTask, errTask).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch
            {
            }
            throw;
        }

        // SFC emits UTF-16 output on some builds; a later refinement can decode
        // raw bytes when NUL padding is detected. Line content is best-effort.
        return lines;
    }
}
