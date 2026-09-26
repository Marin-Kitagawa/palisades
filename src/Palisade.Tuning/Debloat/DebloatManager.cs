// Palisade Tuning - UI-independent port of RyTuneX tuning logic.
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
using Microsoft.Win32;

namespace Palisade.Tuning.Debloat;

/// <summary>
/// Installed-app enumeration and removal (the Debloat surface), plus the
/// deep temp-files clean. WinRT PackageManager is not available to a plain
/// .NET library, so UWP enumeration and removal go through the same
/// PowerShell cmdlets upstream used as its own fallback path - a documented
/// divergence with the same end state.
/// </summary>
public static class DebloatManager
{
    public sealed record AppEntry(string Name, string PackageId, bool IsWin32, string? Publisher = null);

    private static async Task<string> RunPowerShellAsync(string script, CancellationToken token = default)
    {
        var psi = new ProcessStartInfo("powershell.exe")
        {
            Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{script}\"",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("powershell.exe could not be started");
        var output = await process.StandardOutput.ReadToEndAsync(token).ConfigureAwait(false);
        await process.WaitForExitAsync(token).ConfigureAwait(false);
        return output;
    }

    /// <summary>
    /// Win32 apps from the registry Uninstall keys, skipping SystemComponent
    /// entries - upstream's GetWin32Apps.
    /// </summary>
    public static async Task<IReadOnlyList<AppEntry>> GetWin32AppsAsync(CancellationToken token = default)
    {
        return await Task.Run(() =>
        {
            var apps = new List<AppEntry>();
            try
            {
                var roots = new List<RegistryKey>();
                if (Environment.Is64BitOperatingSystem)
                {
                    roots.Add(RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64));
                    roots.Add(RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64));
                    roots.Add(RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32));
                }
                else
                {
                    roots.Add(RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default));
                    roots.Add(RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default));
                }

                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var root in roots)
                {
                    using (root)
                    {
                        using var uninstallKey = root.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                        if (uninstallKey == null)
                        {
                            continue;
                        }
                        foreach (var subName in uninstallKey.GetSubKeyNames())
                        {
                            if (!seen.Add(subName))
                            {
                                continue;
                            }
                            using var subKey = uninstallKey.OpenSubKey(subName);
                            var displayName = subKey?.GetValue("DisplayName") as string;
                            var systemComponent = subKey?.GetValue("SystemComponent") as int?;
                            if (string.IsNullOrEmpty(displayName) || systemComponent == 1)
                            {
                                continue;
                            }
                            apps.Add(new AppEntry(displayName, subName, IsWin32: true));
                        }
                    }
                }
            }
            catch
            {
                // Best-effort enumeration.
            }

            return (IReadOnlyList<AppEntry>)apps.DistinctBy(a => a.Name, StringComparer.OrdinalIgnoreCase)
                .OrderBy(a => a.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }, token).ConfigureAwait(false);
    }

    /// <summary>
    /// UWP apps via Get-AppxPackage - the documented WinRT substitution.
    /// </summary>
    public static async Task<IReadOnlyList<AppEntry>> GetUwpAppsAsync(CancellationToken token = default)
    {
        var output = await RunPowerShellAsync(
            "Get-AppxPackage | Where-Object { -not $_.IsFramework -and $_.NonRemovable -eq $false } | Select-Object Name, PackageFullName, Publisher | ConvertTo-Json -Compress",
            token).ConfigureAwait(false);

        var apps = new List<AppEntry>();
        try
        {
            if (string.IsNullOrWhiteSpace(output))
            {
                return apps;
            }
            using var doc = System.Text.Json.JsonDocument.Parse(output);
            var root = doc.RootElement;
            List<System.Text.Json.JsonElement> elements = [];
            if (root.ValueKind == System.Text.Json.JsonValueKind.Array)
            {
                foreach (var el in root.EnumerateArray())
                {
                    elements.Add(el);
                }
            }
            else
            {
                elements.Add(root);
            }

            foreach (var el in elements)
            {
                var name = el.TryGetProperty("Name", out var n) ? n.GetString() : null;
                var fullName = el.TryGetProperty("PackageFullName", out var f) ? f.GetString() : null;
                var publisher = el.TryGetProperty("Publisher", out var p) ? p.GetString() : null;
                if (!string.IsNullOrEmpty(name))
                {
                    apps.Add(new AppEntry(name, fullName ?? name, IsWin32: false, publisher));
                }
            }
        }
        catch
        {
            // Malformed output returns an empty list.
        }

        return (IReadOnlyList<AppEntry>)apps.DistinctBy(a => a.Name, StringComparer.OrdinalIgnoreCase)
            .OrderBy(a => a.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Uninstalls an app. Edge is deliberately refused: upstream ships a
    /// bespoke RemoveEdge.ps1 asset that is not part of this port, and
    /// silently removing the system browser from a security tool would be
    /// the wrong surprise.
    /// </summary>
    public static async Task<bool> UninstallAsync(AppEntry app, CancellationToken token = default)
    {
        if (app.Name.Contains("edge", StringComparison.OrdinalIgnoreCase) ||
            app.PackageId.Contains("Microsoft.MicrosoftEdge", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (app.IsWin32)
        {
            var uninstallString = GetWin32UninstallString(app.Name);
            if (string.IsNullOrEmpty(uninstallString))
            {
                return false;
            }
            var result = await Runtime.CommandRunner.RunAsync(uninstallString, token).ConfigureAwait(false);
            return result.ExitCode == 0;
        }

        var search = app.PackageId.Contains('_') ? app.PackageId.Split('_')[0] : app.PackageId;
        var provisioned =
            $"Get-AppxProvisionedPackage -Online | Where-Object {{ $_.DisplayName -eq '{search}' -or $_.PackageName -like '*{search}*' }} | ForEach-Object {{ Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }}";
        await RunPowerShellAsync(provisioned, token).ConfigureAwait(false);

        var removeAppx =
            $"Get-AppxPackage -AllUsers | Where-Object {{ $_.Name -eq '{search}' -or $_.PackageFullName -eq '{app.PackageId}' }} | Remove-AppxPackage -AllUsers";
        await RunPowerShellAsync(removeAppx, token).ConfigureAwait(false);
        return true;
    }

    private static string? GetWin32UninstallString(string appName)
    {
        try
        {
            var roots = new List<RegistryKey>();
            if (Environment.Is64BitOperatingSystem)
            {
                roots.Add(RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64));
                roots.Add(RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64));
                roots.Add(RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32));
            }
            else
            {
                roots.Add(RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default));
                roots.Add(RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default));
            }

            foreach (var root in roots)
            {
                using (root)
                {
                    using var uninstallKey = root.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                    if (uninstallKey == null)
                    {
                        continue;
                    }
                    foreach (var subName in uninstallKey.GetSubKeyNames())
                    {
                        using var subKey = uninstallKey.OpenSubKey(subName);
                        var displayName = subKey?.GetValue("DisplayName") as string;
                        if (string.IsNullOrEmpty(displayName) ||
                            !displayName.Equals(appName, StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }
                        var quiet = subKey?.GetValue("QuietUninstallString") as string;
                        if (!string.IsNullOrEmpty(quiet))
                        {
                            return quiet;
                        }
                        var uninstall = subKey?.GetValue("UninstallString") as string;
                        if (!string.IsNullOrEmpty(uninstall))
                        {
                            return uninstall;
                        }
                    }
                }
            }
        }
        catch
        {
        }
        return null;
    }
}
