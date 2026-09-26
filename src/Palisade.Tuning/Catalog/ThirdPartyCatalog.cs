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

using Palisade.Tuning.Models;

namespace Palisade.Tuning.Catalog;

/// <summary>
/// Third-party and security-hardening toggles transcribed from RyTuneX
/// OptimizeSystemHelper.cs (part 5). SmartScreen and VBS weaken real
/// protections — their descriptions say so plainly.
/// </summary>
public static class ThirdPartyCatalog
{
    public static IReadOnlyList<TuningOption> All { get; } =
    [
        Opt("edge-discover-bar",
            "Disable Edge Discover bar / Hubs sidebar",
            "Blocks the Edge sidebar, Web widget and standalone hubs sidebar via policy.",
            "Third-party", true,
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V HubsSidebarEnabled /T REG_DWORD /D 0 /F""",
                """reg add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V HubsSidebarEnabled /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V WebWidgetAllowed /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V StandaloneHubsSidebarEnabled /T REG_DWORD /D 0 /F""",
            ],
            [
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V HubsSidebarEnabled /F""",
                """reg delete "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V HubsSidebarEnabled /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V WebWidgetAllowed /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V StandaloneHubsSidebarEnabled /F""",
            ]),

        Opt("edge-telemetry",
            "Disable Edge telemetry, startup boost and update tasks",
            "Stops Edge metrics, personalization reporting, feedback, startup boost, " +
            "background mode and the WebView2 pre-launch kill-switch, and disables the " +
            "Edge update services and tasks.",
            "Third-party", true,
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V PersonalizationReportingEnabled /T REG_DWORD /D 0 /F""",
                """reg add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V PersonalizationReportingEnabled /T REG_DWORD /D 0 /F""",
                """reg add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V UserFeedbackAllowed /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V UserFeedbackAllowed /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V MetricsReportingEnabled /T REG_DWORD /D 0 /F""",
                """reg add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V MetricsReportingEnabled /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BooksLibrary" /V EnableExtendedBooksTelemetry /T REG_DWORD /D 0 /F""",
                """reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BooksLibrary" /V EnableExtendedBooksTelemetry /T REG_DWORD /D 0 /F""",
                """reg add "HKCU\Software\Microsoft\Edge" /V SmartScreenEnabled /T REG_DWORD /D 0 /F""",
                """reg add "HKCU\Software\Microsoft\Edge" /V SmartScreenPuaEnabled /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V SpotlightExperiencesAndRecommendationsEnabled /T REG_DWORD /D 0 /F""",
                """reg add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V SpotlightExperiencesAndRecommendationsEnabled /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V StartupBoostEnabled /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V BackgroundModeEnabled /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge\WebView2" /V BrowserExecutableFolder /T REG_SZ /D "C:\Empty" /F""",
                "sc stop edgeupdate",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdate" /v Start /t REG_DWORD /d 4 /f""",
                "sc stop edgeupdatem",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v Start /t REG_DWORD /d 4 /f""",
                """schtasks /change /tn "Microsoft\Edge\MicrosoftEdgeWebView2UpdateTaskMachineCore" /disable""",
                """schtasks /change /tn "Microsoft\Edge\MicrosoftEdgeWebView2UpdateTaskMachineUA" /disable""",
                """schtasks /change /tn "\MicrosoftEdgeUpdateTaskMachineCore{DBF79331-3F46-4CDE-AEF0-5EE92CCCB0CF}" /disable""",
                """schtasks /change /tn "\MicrosoftEdgeUpdateTaskMachineUA{EB1A105C-3FF8-4145-81D0-3199F26551F7}" /disable""",
                """schtasks /change /tn "\Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup" /disable""",
                """schtasks /change /tn "\Microsoft\Windows\AppxDeploymentClient\UCPD velocity" /disable""",
            ],
            [
                """reg delete "HKCU\Software\Microsoft\Edge" /V SmartScreenEnabled /F""",
                """reg delete "HKCU\Software\Microsoft\Edge" /V SmartScreenPuaEnabled /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V MetricsReportingEnabled /F""",
                """reg delete "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V MetricsReportingEnabled /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BooksLibrary" /V EnableExtendedBooksTelemetry /F""",
                """reg delete "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\BooksLibrary" /V EnableExtendedBooksTelemetry /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V PersonalizationReportingEnabled /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V UserFeedbackAllowed /F""",
                """reg delete "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V PersonalizationReportingEnabled /F""",
                """reg delete "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V UserFeedbackAllowed /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V SpotlightExperiencesAndRecommendationsEnabled /F""",
                """reg delete "HKCU\SOFTWARE\Policies\Microsoft\Edge" /V SpotlightExperiencesAndRecommendationsEnabled /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V StartupBoostEnabled /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V BackgroundModeEnabled /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Edge\WebView2" /V BrowserExecutableFolder /F""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdate" /v Start /t REG_DWORD /d 3 /f""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v Start /t REG_DWORD /d 3 /f""",
                """schtasks /change /tn "Microsoft\Edge\MicrosoftEdgeWebView2UpdateTaskMachineCore" /enable""",
                """schtasks /change /tn "Microsoft\Edge\MicrosoftEdgeWebView2UpdateTaskMachineUA" /enable""",
                """schtasks /change /tn "\MicrosoftEdgeUpdateTaskMachineCore{DBF79331-3F46-4CDE-AEF0-5EE92CCCB0CF}" /enable""",
                """schtasks /change /tn "\MicrosoftEdgeUpdateTaskMachineUA{EB1A105C-3FF8-4145-81D0-3199F26551F7}" /enable""",
                """schtasks /change /tn "\Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup" /enable""",
                """schtasks /change /tn "\Microsoft\Windows\AppxDeploymentClient\UCPD velocity" /enable""",
            ]),

        Opt("copilot",
            "Remove Copilot",
            "Policy-blocks Windows Copilot, removes the taskbar button and shell extension, " +
            "stops the AI Fabric service and deprovisions the Copilot packages. NOTE: the " +
            "region policy JSON edit and Voice Access file deletion from upstream are not " +
            "carried out here (system-file modification kept out of this port).",
            "AI", true,
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /V TurnOffWindowsCopilot /T REG_DWORD /D 1 /F""",
                """reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /V TurnOffWindowsCopilot /T REG_DWORD /D 1 /F""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V ShowCopilotButton /T REG_DWORD /D 0 /F""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /V "{64134153-2E11-492F-8181-314091BA79A3}" /T REG_SZ /D "Copilot" /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages" /V Enabled /T REG_DWORD /D 1 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages\Microsoft.Copilot_8wekyb3d8bbwe" /V RemovedPackage /T REG_DWORD /D 1 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages\Microsoft.Windows.Ai.Fabric_8wekyb3d8bbwe" /V RemovedPackage /T REG_DWORD /D 1 /F""",
                """powershell -NoProfile -Command "$svc = Get-Service -Name 'WSAIFabricSvc' -ErrorAction SilentlyContinue; if ($svc) { Stop-Service -Name 'WSAIFabricSvc' -Force -ErrorAction SilentlyContinue }; Start-Process sc.exe -ArgumentList 'delete','WSAIFabricSvc' -NoNewWindow -Wait""" + "\"",
                """powershell -NoProfile -Command "$targets = @('Microsoft.Windows.Copilot','MicrosoftWindows.Client.Copilot','Microsoft.Windows.Ai.Copilot.Provider','Microsoft.Copilot'); foreach ($t in $targets) { Get-AppxPackage -AllUsers -Name '*$t*' | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue; Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like '*$t*' } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue }""" + "\"",
            ],
            [
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /V TurnOffWindowsCopilot /F""",
                """reg delete "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /V TurnOffWindowsCopilot /F""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /V "{64134153-2E11-492F-8181-314091BA79A3}" /F""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V ShowCopilotButton /T REG_DWORD /D 1 /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages\Microsoft.Copilot_8wekyb3d8bbwe" /V RemovedPackage /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages\Microsoft.Windows.Ai.Fabric_8wekyb3d8bbwe" /V RemovedPackage /F""",
                """powershell -NoProfile -Command "Get-AppxPackage -AllUsers *Copilot* | ForEach-Object { Add-AppxPackage -Register \\\"$($_.InstallLocation)\\appxmanifest.xml\\\" -DisableDevelopmentMode }""" + "\"",
            ]),

        Opt("vs-telemetry",
            "Disable Visual Studio telemetry",
            "Turns off VS telemetry, feedback dialog, email input, screenshot capture and " +
            "SQM opt-in across 14.0–16.0, and disables the collector service.",
            "Third-party", true,
            [
                """reg add "HKCU\Software\Microsoft\VisualStudio\Telemetry" /V TurnOffSwitch /T REG_DWORD /D 1 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /V DisableFeedbackDialog /T REG_DWORD /D 1 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /V DisableEmailInput /T REG_DWORD /D 1 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /V DisableScreenshotCapture /T REG_DWORD /D 1 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\SQM" /V OptIn /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Setup" /V ConcurrentDownloads /T REG_DWORD /D 2 /F""",
                """reg add "HKLM\SOFTWARE\Microsoft\VSCommon\14.0\SQM" /V OptIn /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SOFTWARE\Microsoft\VSCommon\15.0\SQM" /V OptIn /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SOFTWARE\Microsoft\VSCommon\16.0\SQM" /V OptIn /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\VSStandardCollectorService150" /v Start /t REG_DWORD /d 4 /f""",
            ],
            [
                """reg delete "HKCU\Software\Microsoft\VisualStudio\Telemetry" /V TurnOffSwitch /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /V DisableFeedbackDialog /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /V DisableEmailInput /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /V DisableScreenshotCapture /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\SQM" /V OptIn /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Setup" /V ConcurrentDownloads /F""",
                """reg delete "HKLM\SOFTWARE\Microsoft\VSCommon\14.0\SQM" /V OptIn /F""",
                """reg delete "HKLM\SOFTWARE\Microsoft\VSCommon\15.0\SQM" /V OptIn /F""",
                """reg delete "HKLM\SOFTWARE\Microsoft\VSCommon\16.0\SQM" /V OptIn /F""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\VSStandardCollectorService150" /v Start /t REG_DWORD /d 3 /f""",
            ]),

        Opt("nvidia-telemetry",
            "Disable NVIDIA telemetry",
            "Stops and disables the NVIDIA telemetry container service and its three " +
            "scheduled tasks. Applies only if NVIDIA software is installed.",
            "Third-party", true,
            [
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\NvTelemetryContainer" /v Start /t REG_DWORD /d 4 /f""",
                "schtasks.exe /change /tn NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /disable",
                "schtasks.exe /change /tn NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /disable",
                "schtasks.exe /change /tn NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /disable",
                "net.exe stop NvTelemetryContainer",
                "sc.exe stop NvTelemetryContainer",
            ],
            [
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\NvTelemetryContainer" /v Start /t REG_DWORD /d 2 /f""",
                "schtasks.exe /change /tn NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /enable",
                "schtasks.exe /change /tn NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /enable",
                "schtasks.exe /change /tn NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /enable",
                "net.exe start NvTelemetryContainer",
                "sc.exe start NvTelemetryContainer",
            ]),

        Opt("chrome-telemetry",
            "Disable Chrome metrics and cleanup reporting",
            "Applies Chrome enterprise policies that stop metrics, cleanup reporting and " +
            "user feedback. Applies only if Chrome is installed.",
            "Third-party", true,
            [
                """reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v MetricsReportingEnabled /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v ChromeCleanupReportingEnabled /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v ChromeCleanupEnabled /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v UserFeedbackAllowed /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v DeviceMetricsReportingEnabled /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg delete "HKLM\SOFTWARE\Policies\Google\Chrome" /v MetricsReportingEnabled /f""",
                """reg delete "HKLM\SOFTWARE\Policies\Google\Chrome" /v ChromeCleanupReportingEnabled /f""",
                """reg delete "HKLM\SOFTWARE\Policies\Google\Chrome" /v ChromeCleanupEnabled /f""",
                """reg delete "HKLM\SOFTWARE\Policies\Google\Chrome" /v UserFeedbackAllowed /f""",
                """reg delete "HKLM\SOFTWARE\Policies\Google\Chrome" /v DeviceMetricsReportingEnabled /f""",
            ]),

        Opt("firefox-telemetry",
            "Disable Firefox telemetry",
            "Applies Firefox enterprise policies that stop telemetry and the default " +
            "browser agent, and disables its scheduled tasks.",
            "Third-party", true,
            [
                """reg add "HKLM\SOFTWARE\Policies\Mozilla\Firefox" /v DisableTelemetry /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Mozilla\Firefox" /v DisableDefaultBrowserAgent /t REG_DWORD /d 1 /f""",
                "schtasks.exe /change /disable /tn \"\\Mozilla\\Firefox Default Browser Agent 308046B0AF4A39CB\"",
                "schtasks.exe /change /disable /tn \"\\Mozilla\\Firefox Default Browser Agent D2CEEC440E2074BD\"",
            ],
            [
                """reg delete "HKLM\SOFTWARE\Policies\Mozilla\Firefox" /v DisableTelemetry /f""",
                """reg delete "HKLM\SOFTWARE\Policies\Mozilla\Firefox" /v DisableDefaultBrowserAgent /f""",
                "schtasks.exe /change /enable /tn \"\\Mozilla\\Firefox Default Browser Agent 308046B0AF4A39CB\"",
                "schtasks.exe /change /enable /tn \"\\Mozilla\\Firefox Default Browser Agent D2CEEC440E2074BD\"",
            ]),

        Opt("smartscreen",
            "Disable SmartScreen",
            "SECURITY COST: disables Microsoft Defender SmartScreen for files, apps and " +
            "Edge phishing protection. Malicious downloads will no longer be warned about. " +
            "Only for controlled environments.",
            "Security", true,
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v SaveZoneInformation /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v ScanWithAntiVirus /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v ShellSmartScreenLevel /t REG_SZ /d Warn /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d Off /f""",
                """reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v PreventOverride /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v Enabled /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v SaveZoneInformation /t REG_DWORD /d 2 /f""",
                """reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v ScanWithAntiVirus /t REG_DWORD /d 2 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d On /f""",
                """reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v PreventOverride /f""",
            ]),

        Opt("vbs",
            "Disable Virtualization-Based Security",
            "SECURITY COST: disables VBS, HVCI/Memory Integrity, Credential Guard and " +
            "LSA Protection, and turns off the hypervisor. Real protection is lost — games " +
            "and benchmarks are the only typical reason.",
            "Security", true,
            [
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /V EnableVirtualizationBasedSecurity /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /V Enabled /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks" /V Enabled /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" /V Enabled /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /V RunAsPPL /T REG_DWORD /D 0 /F""",
                "bcdedit /set hypervisorlaunchtype off",
            ],
            [
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /V EnableVirtualizationBasedSecurity /T REG_DWORD /D 1 /F""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /V Enabled /T REG_DWORD /D 1 /F""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks" /V Enabled /T REG_DWORD /D 1 /F""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" /V Enabled /T REG_DWORD /D 1 /F""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /V RunAsPPL /T REG_DWORD /D 1 /F""",
                "bcdedit /set hypervisorlaunchtype on",
            ]),
    ];

    private static TuningOption Opt(
        string id, string title, string description, string category, bool requiresElevation,
        string[] apply, string[] revert) =>
        new(id, title, description, category, requiresElevation, apply, revert);
}
