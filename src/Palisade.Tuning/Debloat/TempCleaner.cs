// Palisade Tuning ” UI-independent port of RyTuneX tuning logic.
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

namespace Palisade.Tuning.Debloat;

/// <summary>
/// Upstream's RemoveTempFiles deep clean: stops update/search/font services,
/// cleans explorer-dependent and deep-clean paths plus shader caches, flushes
/// DNS and winsock, restores services. Returns (ok, bytes cleared estimate).
/// This is source code holding upstream's command strings; nothing runs here.
/// </summary>
public static class TempCleaner
{
    public static async Task<(bool Ok, long BytesCleared)> RemoveTempFilesAsync(CancellationToken token = default)
    {
        long totalBytes = 0;
        try
        {
            string[] servicesToStop = ["wuauserv", "bits", "dosvc", "WSearch", "FontCache"];
            foreach (var service in servicesToStop)
            {
                await Runtime.CommandRunner.RunAsync($"net stop {service} /y", token).ConfigureAwait(false);
            }

            await Runtime.CommandRunner.RunAsync("taskkill /F /IM explorer.exe", token).ConfigureAwait(false);

            string[] explorerDependentPaths =
            [
                Environment.ExpandEnvironmentVariables("%localappdata%\\Temp"),
                Environment.ExpandEnvironmentVariables("%localappdata%\\Microsoft\\Windows\\INetCache"),
                Environment.ExpandEnvironmentVariables("%localappdata%\\Microsoft\\Windows\\WebCache"),
                Environment.ExpandEnvironmentVariables("%windir%\\Prefetch"),
                Environment.ExpandEnvironmentVariables("%localappdata%\\Microsoft\\Windows\\History"),
                Environment.ExpandEnvironmentVariables("%localappdata%\\ConnectedDevicesPlatform"),
            ];
            totalBytes += await DeleteDirectoriesAsync(explorerDependentPaths, token).ConfigureAwait(false);

            string[] explorerDependentCommands =
            [
                "del /F /Q %localappdata%\\IconCache.db",
                "del /F /S /Q %localappdata%\\Microsoft\\Windows\\Explorer\\iconcache*",
                "del /F /S /Q %localappdata%\\Microsoft\\Windows\\Explorer\\thumbcache*",
                "del /F /Q %appdata%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*",
                "del /F /Q %appdata%\\Microsoft\\Windows\\Recent\\CustomDestinations\\*",
            ];
            foreach (var cmd in explorerDependentCommands)
            {
                await Runtime.CommandRunner.RunAsync(cmd, token).ConfigureAwait(false);
            }

            await Runtime.CommandRunner.RunAsync("start %SystemRoot%\\explorer.exe", token).ConfigureAwait(false);

            string[] deepCleanPaths =
            [
                Environment.ExpandEnvironmentVariables("%windir%\\SoftwareDistribution\\Download"),
                Environment.ExpandEnvironmentVariables("%windir%\\SoftwareDistribution\\DataStore"),
                Environment.ExpandEnvironmentVariables("%windir%\\SoftwareDistribution\\DeliveryOptimization"),
                Environment.ExpandEnvironmentVariables("%programdata%\\USOPrivate\\UpdateStore"),
                Environment.ExpandEnvironmentVariables("%programdata%\\USOShared\\Logs"),
                Environment.ExpandEnvironmentVariables("%localappdata%\\NVIDIA\\GLCache"),
                Environment.ExpandEnvironmentVariables("%localappdata%\\NVIDIA\\DXCache"),
                Environment.ExpandEnvironmentVariables("%localappdata%\\AMD\\DxCache"),
                Environment.ExpandEnvironmentVariables("%localappdata%\\D3DSCache"),
                Environment.ExpandEnvironmentVariables("%localappdata%\\Steam\\htmlcache"),
                Environment.ExpandEnvironmentVariables("%localappdata%\\Microsoft\\EdgeWebView"),
                Environment.ExpandEnvironmentVariables("%windir%\\Temp"),
                Environment.ExpandEnvironmentVariables("%TEMP%"),
                Environment.ExpandEnvironmentVariables("%windir%\\WinSxS\\Temp\\PendingDeletes"),
                Environment.ExpandEnvironmentVariables("%windir%\\WinSxS\\Temp\\PendingRenames"),
                Environment.ExpandEnvironmentVariables("%programdata%\\Microsoft\\Windows\\WER\\ReportQueue"),
                Environment.ExpandEnvironmentVariables("%programdata%\\Microsoft\\Windows\\WER\\ReportArchive"),
                Environment.ExpandEnvironmentVariables("%programdata%\\Microsoft\\Windows\\WER\\Temp"),
                Environment.ExpandEnvironmentVariables("%localappdata%\\CrashDumps"),
                Environment.ExpandEnvironmentVariables("%windir%\\LiveKernelReports"),
                Environment.ExpandEnvironmentVariables("%localappdata%\\Packages\\Microsoft.WindowsStore_8wekyb3d8bbwe\\LocalCache"),
                Environment.ExpandEnvironmentVariables("%localappdata%\\Packages\\Microsoft.WindowsStore_8wekyb3d8bbwe\\TempState"),
                Environment.ExpandEnvironmentVariables("%localappdata%\\Packages\\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\\TempState"),
                Environment.ExpandEnvironmentVariables("%localappdata%\\Packages\\Microsoft.GamingApp_8wekyb3d8bbwe\\TempState"),
            ];
            totalBytes += await DeleteDirectoriesAsync(deepCleanPaths, token).ConfigureAwait(false);

            string[] deepCleanCommands =
            [
                "rd /S /Q %windir%\\SoftwareDistribution\\Download",
                "rd /S /Q %windir%\\SoftwareDistribution\\DataStore",
                "rd /S /Q %windir%\\SoftwareDistribution\\DeliveryOptimization",
                "rd /S /Q %programdata%\\USOPrivate\\UpdateStore",
                "rd /S /Q %programdata%\\USOShared\\Logs",
                "del /F /S /Q %windir%\\Logs\\CBS\\*",
                "del /F /S /Q %windir%\\Logs\\DISM\\*",
                "del /F /S /Q %windir%\\Panther\\*",
                "del /F /S /Q %appdata%\\TeamViewer\\*.log",
                "del /F /S /Q %appdata%\\AnyDesk\\*.trace",
                "rd /S /Q %programdata%\\Microsoft\\Diagnosis",
                "rd /S /Q %windir%\\LiveKernelReports",
                """PowerShell.exe -NoProfile -Command "& { Get-ChildItem -Path \"$env:LOCALAPPDATA\Google\Chrome\User Data\", \"$env:LOCALAPPDATA\Microsoft\Edge\User Data\", \"$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\" -Recurse -Include 'Cache','Code Cache','GPUCache','ShaderCache','Service Worker' | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }""" + "\"",
                """PowerShell.exe -NoProfile -Command "& { Get-ChildItem -Path \"$env:APPDATA\Mozilla\Firefox\Profiles\", \"$env:LOCALAPPDATA\Mozilla\Firefox\Profiles\" -Recurse -Include 'cache2' | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }""" + "\"",
                "ipconfig /flushdns",
                "netsh winsock reset",
                "del /F /Q %windir%\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache\\*",
                "rd /S /Q %programdata%\\Microsoft\\Search\\Data\\Applications\\Windows",
                """PowerShell.exe -NoProfile -Command "Clear-RecycleBin -Force""" + "\"",
            ];
            foreach (var cmd in deepCleanCommands)
            {
                await Runtime.CommandRunner.RunAsync(cmd, token).ConfigureAwait(false);
            }

            foreach (var service in servicesToStop)
            {
                await Runtime.CommandRunner.RunAsync($"net start {service}", token).ConfigureAwait(false);
            }

            return (true, totalBytes);
        }
        catch
        {
            // Ensure the shell is back even on failure, as upstream does.
            try
            {
                await Runtime.CommandRunner.RunAsync("start %SystemRoot%\\explorer.exe", token).ConfigureAwait(false);
            }
            catch
            {
            }
            return (false, totalBytes);
        }
    }

    private static long GetDirectorySize(string path)
    {
        try
        {
            if (!Directory.Exists(path))
            {
                return 0;
            }
            return Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories)
                .Sum(f =>
                {
                    try
                    {
                        return new FileInfo(f).Length;
                    }
                    catch
                    {
                        return 0L;
                    }
                });
        }
        catch
        {
            return 0;
        }
    }

    private static async Task<long> DeleteDirectoriesAsync(IEnumerable<string> paths, CancellationToken token)
    {
        long total = 0;
        await Task.Run(() =>
        {
            foreach (var path in paths)
            {
                token.ThrowIfCancellationRequested();
                var size = GetDirectorySize(path);
                try
                {
                    if (Directory.Exists(path))
                    {
                        Directory.Delete(path, true);
                        total += size;
                    }
                }
                catch
                {
                    // Locked or protected paths are skipped.
                }
            }
        }, token).ConfigureAwait(false);
        return total;
    }
}
