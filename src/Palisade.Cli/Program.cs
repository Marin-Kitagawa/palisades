// Palisade
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

using Palisade.Core;
using Palisade.Core.Engine;
using Palisade.Core.Models;
using Palisade.Core.Registry;
using System.Diagnostics;

namespace Palisade.Cli;

/// <summary>
/// CLI parity with the upstream Go tool: -harden and -restore with default
/// settings, for machines where the GUI cannot start. Exits with 0 on a
/// clean report and 2 when any measure failed — the process never exits
/// silently mid-operation, which is defect #7 of the Go original.
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length != 1 || args[0] is not ("-harden" or "-restore" or "-detect" or "--help" or "-h"))
        {
            PrintUsage();
            return 1;
        }

        if (args[0] is "--help" or "-h")
        {
            PrintUsage();
            return 0;
        }

        Console.WriteLine("Palisade — reversible hardening (not an antivirus)");
        Console.WriteLine();

        var logDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Palisade", "logs");
        Directory.CreateDirectory(logDirectory);

        var registry = new RegistryAccess();
        var engine = new PalisadeEngine(registry, RegistryOptions.Default, new AppPaths(logDirectory), () => IsElevated());

        var report = args[0] switch
        {
            "-harden" => engine.ReapplyDefaults(),
            "-restore" => engine.RestoreAll(),
            "-detect" => DetectWithTiming(engine),
            _ => throw new UnreachableException(),
        };

        if (report is null)
        {
            return 0;
        }

        foreach (var result in report.Results)
        {
            Console.WriteLine($"{result.Id,-28} {result.Outcome,-16} {result.Detail}");
        }

        foreach (var warning in report.Warnings)
        {
            Console.WriteLine($"warning: {warning}");
        }

        Console.WriteLine();
        Console.WriteLine(report.RequiresRestart
            ? "A restart is required for the full effect of several measures."
            : "No restart required.");

        return report.Results.Any(r => r.Outcome == ApplyOutcome.Failed) ? 2 : 0;
    }

    private static ApplyReport? DetectWithTiming(PalisadeEngine engine)
    {
        foreach (var descriptor in MeasureCatalog.All)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            ApplyOutcome outcome;
            string detail = "";
            try
            {
                var result = engine.Detect().FirstOrDefault(r => r.Id == descriptor.Id);
                outcome = result?.State switch
                {
                    MeasureState.Taut => ApplyOutcome.AlreadyApplied,
                    MeasureState.Slack => ApplyOutcome.NotRestored,
                    MeasureState.Stressed => ApplyOutcome.Failed,
                    _ => ApplyOutcome.Unavailable,
                };
                detail = result?.Unavailable?.Reason ?? result?.State.ToString() ?? "missing";
            }
            catch (Exception ex)
            {
                outcome = ApplyOutcome.Failed;
                detail = ex.Message;
            }
            Console.WriteLine($"{descriptor.Id,-30} {sw.ElapsedMilliseconds,6} ms  {outcome,-14} {detail}");
        }
        return null;
    }

    private static bool IsElevated()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(identity)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static void PrintUsage()
    {
        Console.WriteLine("""
            Usage: Palisade.Cli <option>

              -harden    Restore every applied measure to its recorded original,
                         then apply the default hardening set. Exits 0 on success,
                         2 if any measure failed.
              -restore   Restore every measure recorded on this account to its
                         original state.
              -h         This text.

            Palisade is not an antivirus. It reduces the Windows attack surface;
            it does not identify, block, or remove malware.
            """);
    }
}
