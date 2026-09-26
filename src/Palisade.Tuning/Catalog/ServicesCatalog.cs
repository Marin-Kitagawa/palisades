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

using System.Runtime.InteropServices;
using Palisade.Tuning.Models;

namespace Palisade.Tuning.Catalog;

/// <summary>
/// Service-backed optimize toggles and the telemetry set, transcribed from
/// RyTuneX OptimizeSystemHelper.cs. Service start/stop uses sc with the same
/// start values upstream writes (4 = disabled, 2 = automatic, 3 = manual).
/// </summary>
public static class ServicesCatalog
{
    private const string TelemetryHostsPs =
        "$hosts=@('vortex-win.data.microsoft.com','settings-win.data.microsoft.com'," +
        "'telemetry.microsoft.com','watson.telemetry.microsoft.com','oca.telemetry.microsoft.com'," +
        "'sqm.telemetry.microsoft.com','sqm.ppe.telemetry.microsoft.com','watson.ppe.telemetry.microsoft.com'," +
        "'df.telemetry.microsoft.com','diagnostics.support.microsoft.com','oca.microsoft.com'," +
        "'oca.telemetry.microsoft.com.nsatc.net','redir.metaservices.microsoft.com','choice.microsoft.com'," +
        "'choice.microsoft.com.nsatc.net','ceuswatcab01.blob.core.windows.net')";

    public static IReadOnlyList<TuningOption> All { get; } =
    [
        Opt("telemetry-services",
            "Disable telemetry services and tasks",
            "Stops and disables DiagTrack and the other diagnostic services, CEIP tasks and " +
            "compatibility appraisers, applies the AllowTelemetry=0 policy set, and blocks the " +
            "Unified Telemetry Client outbound. Diagnostic data stops leaving the machine.",
            "Telemetry", true,
            BuildTelemetryApply(),
            BuildTelemetryRevert()),

        Opt("svchost-splitting",
            "Disable Service Host splitting",
            "Sets the SvcHost split threshold above this machine's RAM, so services share " +
            "processes again and background memory use drops.",
            "Performance", true,
            [$"reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\" /v SvcHostSplitThresholdInKB /t REG_DWORD /d {RamInKb()} /f"],
            [
                """reg delete "HKLM\SYSTEM\CurrentControlSet\Control" /v SvcHostSplitThresholdInKB /f""",
            ]),

        Opt("ntfs-optimization",
            "Optimize NTFS parameters",
            "Disables last-access timestamps and 8.3 short names, and halves the MFT zone " +
            "reservation. Speeds up file operations on large volumes.",
            "Performance", true,
            [
                "fsutil behavior set disablelastaccess 1",
                "fsutil behavior set disable8dot3 1",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v NtfsMftZoneReservation /t REG_DWORD /d 2 /f""",
            ],
            [
                "fsutil behavior set disablelastaccess 0",
                "fsutil behavior set disable8dot3 0",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v NtfsMftZoneReservation /t REG_DWORD /d 1 /f""",
            ]),

        ServiceOpt("print-spooler", "Disable Print Spooler",
            "Stops and disables the print spooler. Printing stops working; the spooler " +
            "becomes unreachable for network printers.",
            Service("Spooler")),
        ServiceOpt("sysmain", "Disable SysMain (Superfetch)",
            "Stops and disables SysMain and the prefetcher. First application launches get " +
            "slower; background prefetch activity stops.",
            Service("SysMain"),
            extraApply:
            [
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnableSuperfetch /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v SfTracingState /t REG_DWORD /d 1 /f""",
            ],
            extraRevert:
            [
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnableSuperfetch /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 1 /f""",
                """reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v SfTracingState /f""",
            ]),
        ServiceOpt("windows-search", "Disable Windows Search indexing",
            "Stops and disables the WSearch indexer. Start menu and Explorer search fall " +
            "back to live scans and get slower.",
            Service("WSearch")),
        ServiceOpt("media-player-sharing", "Disable WMP Network Sharing",
            "Stops and disables Windows Media Player network sharing; this machine stops " +
            "casting its media library over the network.",
            Service("WMPNetworkSvc")),
        Opt("homegroup",
            "Disable HomeGroup",
            "Stops and disables the HomeGroup listener and provider services.",
            "Network", true,
            [
                "sc stop HomeGroupListener",
                "sc stop HomeGroupProvider",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HomeGroup" /v DisableHomeGroup /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupListener" /v Start /t REG_DWORD /d 4 /f""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupProvider" /v Start /t REG_DWORD /d 4 /f""",
            ],
            [
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupListener" /v Start /t REG_DWORD /d 2 /f""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupProvider" /v Start /t REG_DWORD /d 2 /f""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\HomeGroup" /v DisableHomeGroup /f""",
                "sc start HomeGroupListener",
                "sc start HomeGroupProvider",
            ]),

        Opt("compatibility-assistant",
            "Disable Program Compatibility Assistant",
            "Stops PcaSvc and disables the AppCompat engine, steps recorder and inventory " +
            "policies. Windows stops asking about program compatibility.",
            "Telemetry", true,
            [
                "sc stop PcaSvc",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc" /v Start /t REG_DWORD /d 4 /f""",
                """reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v DisableEngine /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v SbEnable /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScheduledDiagnostics" /v EnabledExecution /t REG_DWORD /d 0 /f""",
            ],
            [
                "sc config PcaSvc start= auto",
                "sc start PcaSvc",
                """reg delete "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v DisableEngine /f""",
                """reg delete "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v AITEnable /f""",
                """reg delete "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /f""",
                """reg delete "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /f""",
                """reg delete "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /f""",
                """reg delete "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v SbEnable /f""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScheduledDiagnostics" /v EnabledExecution /f""",
            ]),

        Opt("system-restore",
            "Disable System Restore",
            "Deletes existing restore points on C: and disables System Restore via policy. " +
            "You lose the ability to roll the system back with System Restore.",
            "System", true,
            [
                "vssadmin delete shadows /for=c: /all /quiet",
                "sc stop VSS",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v DisableSR /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v DisableConfig /t REG_DWORD /d 1 /f""",
            ],
            [
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v DisableSR /f""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v DisableConfig /f""",
                "sc start VSS",
            ]),
    ];

    private static string[] Service(string name) =>
    [
        $"sc stop {name}",
        $"sc config {name} start= disabled",
    ];

    private static TuningOption ServiceOpt(
        string id, string title, string description, string[] serviceCommands,
        string[]? extraApply = null, string[]? extraRevert = null)
    {
        var apply = serviceCommands.ToList();
        var name = ExtractName(serviceCommands);
        var revert = new List<string>
        {
            $"sc config {name} start= auto",
            $"sc start {name}",
        };
        if (extraApply is not null)
        {
            apply.AddRange(extraApply);
        }
        if (extraRevert is not null)
        {
            revert.AddRange(extraRevert);
        }
        return new TuningOption(id, title, description, "Services", true, apply, revert);
    }

    private static string ExtractName(string[] serviceCommands)
    {
        // "sc stop SysMain" / "sc config SysMain start= disabled" â€” take the last token of the first command.
        var parts = serviceCommands[0].Split(' ');
        return parts[^1];
    }

    private static string[] BuildTelemetryApply()
    {
        var services = new[]
        {
            "DiagTrack", "diagnosticshub.standardcollector.service", "dmwappushservice",
            "DcpSvc", "WdiServiceHost", "WdiSystemHost", "TrkWks", "MapsBroker", "whesvc",
            "WebThreatDefenseSvc", "webthreatdefusersvc", "AppInventory", "InventorySvc",
        };
        var commands = new List<string>();
        foreach (var svc in services)
        {
            commands.Add($"sc stop {svc}");
            commands.Add($"sc config {svc} start= disabled");
        }

        string[] appCompatKeys = { "DisableEngine", "SbEnable", "AITEnable", "DisableInventory", "DisablePCA", "DisableUAR" };
        int[] appCompatValues = { 1, 0, 0, 1, 1, 1 };
        for (var i = 0; i < appCompatKeys.Length; i++)
        {
            commands.Add($"reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat\" /v {appCompatKeys[i]} /t REG_DWORD /d {appCompatValues[i]} /f");
        }

        commands.AddRange(
        [
            """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f""",
            """reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f""",
            """reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowTelemetry" /v value /t REG_DWORD /d 0 /f""",
            """reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v CEIPEnable /t REG_DWORD /d 0 /f""",
            """reg add "HKCU\Software\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f""",
            """reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v value /t REG_DWORD /d 0 /f""",
            """reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v value /t REG_DWORD /d 0 /f""",
            """reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f""",
            """reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f""",
            """reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v Start /t REG_DWORD /d 0 /f""",
            """reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v AllowExperimentation /t REG_DWORD /d 0 /f""",
            """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f""",
            """reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f""",
            """reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\SetupPlatformTel" /v Start /t REG_DWORD /d 0 /f""",
            """reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v AllowCommercialDataPipeline /t REG_DWORD /d 0 /f""",
            """reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v AllowDeviceNameInTelemetry /t REG_DWORD /d 0 /f""",
            """reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DisableEnterpriseAuthProxy /t REG_DWORD /d 1 /f""",
            """reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v MicrosoftEdgeDataOptIn /t REG_DWORD /d 0 /f""",
            """reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DisableTelemetryOptInChangeNotification /t REG_DWORD /d 1 /f""",
            """reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DisableTelemetryOptInSettingsUx /t REG_DWORD /d 1 /f""",
            """reg add "HKLM\Software\Policies\Microsoft\Windows\PreviewBuilds" /v EnableConfigFlighting /t REG_DWORD /d 0 /f""",
            """reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v LimitDiagnosticLogCollection /t REG_DWORD /d 1 /f""",
            """reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v LimitDumpCollection /t REG_DWORD /d 1 /f""",
            """reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v LimitEnhancedDiagnosticDataWindowsAnalytics /t REG_DWORD /d 0 /f""",
            """reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v AllowBuildPreview /t REG_DWORD /d 0 /f""",
            """reg add "HKLM\SOFTWARE\Policies\Microsoft\AppV\CEIP" /v CEIPEnable /t REG_DWORD /d 0 /f""",
            """reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\SQM" /v DisableCustomerImprovementProgram /t REG_DWORD /d 1 /f""",
            """reg add "HKLM\Software\Policies\Microsoft\Messenger\Client" /v CEIP /t REG_DWORD /d 2 /f""",
            """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v RSoPLogging /t REG_DWORD /d 0 /f""",
            """powershell -NoProfile -Command "if (-not (Get-NetFirewallRule -DisplayName 'Block-Unified-Telemetry-Client' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName 'Block-Unified-Telemetry-Client' -Direction Outbound -Action Block -Program '%SystemRoot%\system32\svchost.exe' -Service 'DiagTrack' -Profile Any }""" + "\"",
        ]);

        string[] tasks =
        [
            @"Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
            @"Microsoft\Windows\Application Experience\ProgramDataUpdater",
            @"Microsoft\Windows\Autochk\Proxy",
            @"Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
            @"Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
            @"Microsoft\Windows\Customer Experience Improvement Program\BthSQM",
            @"Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
            @"Microsoft\Windows\Feedback\Siuf\DmClient",
            @"Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
        ];
        foreach (var task in tasks)
        {
            commands.Add($"schtasks /Change /TN \"{task}\" /Disable");
        }

        commands.Add(
            "powershell -NoProfile -Command \"" + TelemetryHostsPs + "; " +
            "$f='$env:SystemRoot\\System32\\drivers\\etc\\hosts'.Replace('$env:SystemRoot',$env:SystemRoot); " +
            "$lines=[System.IO.File]::ReadAllLines($f); foreach($h in $hosts){$e='0.0.0.0 '+$h; if($lines -notcontains $e){Add-Content -Path $f -Value $e}}\"");

        return [.. commands];
    }

    private static string[] BuildTelemetryRevert()
    {
        var services = new[]
        {
            "DiagTrack", "diagnosticshub.standardcollector.service", "dmwappushservice",
            "DcpSvc", "WdiServiceHost", "WdiSystemHost", "TrkWks", "MapsBroker", "whesvc",
            "WebThreatDefenseSvc", "webthreatdefusersvc", "AppInventory", "InventorySvc",
        };
        var commands = new List<string>();
        foreach (var svc in services)
        {
            commands.Add($"sc config {svc} start= auto");
            commands.Add($"sc start {svc}");
        }

        commands.AddRange(
        [
            """reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /f""",
            """reg delete "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowTelemetry" /v value /f""",
            """reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v CEIPEnable /t REG_DWORD /d 1 /f""",
            """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 1 /f""",
            """reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\Diagtrack-Listener" /v Start /t REG_DWORD /d 1 /f""",
            """reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\SetupPlatformTel" /v Start /t REG_DWORD /d 1 /f""",
            """reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v Start /t REG_DWORD /d 1 /f""",
            """reg delete "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v AllowCommercialDataPipeline /f""",
            """reg delete "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v AllowDeviceNameInTelemetry /f""",
            """reg delete "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DisableEnterpriseAuthProxy /f""",
            """reg delete "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v MicrosoftEdgeDataOptIn /f""",
            """reg delete "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DisableTelemetryOptInChangeNotification /f""",
            """reg delete "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DisableTelemetryOptInSettingsUx /f""",
            """reg delete "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v LimitDiagnosticLogCollection /f""",
            """reg delete "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v LimitDumpCollection /f""",
            """reg delete "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v LimitEnhancedDiagnosticDataWindowsAnalytics /f""",
            """reg delete "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v AllowBuildPreview /f""",
            """reg delete "HKLM\SOFTWARE\Policies\Microsoft\AppV\CEIP" /v CEIPEnable /f""",
            """reg delete "HKLM\Software\Policies\Microsoft\Internet Explorer\SQM" /v DisableCustomerImprovementProgram /f""",
            """reg delete "HKLM\Software\Policies\Microsoft\Messenger\Client" /v CEIP /f""",
            """reg delete "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v Block-Unified-Telemetry-Client /f""",
            """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v RSoPLogging /f""",
        ]);

        string[] tasks =
        [
            @"Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
            @"Microsoft\Windows\Application Experience\ProgramDataUpdater",
            @"Microsoft\Windows\Autochk\Proxy",
            @"Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
            @"Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
            @"Microsoft\Windows\Customer Experience Improvement Program\BthSQM",
            @"Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
            @"Microsoft\Windows\Feedback\Siuf\DmClient",
            @"Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
        ];
        foreach (var task in tasks)
        {
            commands.Add($"schtasks /Change /TN \"{task}\" /Enable");
        }

        commands.Add(
            "powershell -NoProfile -Command \"" + TelemetryHostsPs + "; " +
            "$f='$env:SystemRoot\\System32\\drivers\\etc\\hosts'.Replace('$env:SystemRoot',$env:SystemRoot); " +
            "$lines=[System.IO.File]::ReadAllLines($f); " +
            "[System.IO.File]::WriteAllLines($f, ($lines | Where-Object { $ln=$_; -not ($hosts | Where-Object { $ln -eq ('0.0.0.0 '+$_) }) }))\"");

        return [.. commands];
    }

    private static long RamInKb()
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX buffer);

        var status = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
        GlobalMemoryStatusEx(ref status);
        var gb = (ulong)Math.Ceiling(status.ullTotalPhys / (1024d * 1024d * 1024d));
        var kb = gb * 1024UL * 1024UL;
        return kb > uint.MaxValue ? uint.MaxValue : (long)kb;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    private static TuningOption Opt(
        string id, string title, string description, string category, bool requiresElevation,
        string[] apply, string[] revert) =>
        new(id, title, description, category, requiresElevation, apply, revert);
}
