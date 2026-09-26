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

using Palisade.Tuning.Models;

namespace Palisade.Tuning.Catalog;

/// <summary>
/// Optimize toggles transcribed verbatim from RyTuneX OptimizeSystemHelper.cs
/// (the Disable*/Enable* method pairs). Every command string is upstream's;
/// only the grouping into apply/revert lists is new. Categories follow the
/// RyTuneX Optimize page sections.
/// </summary>
public static class OptimizeCatalog
{
    public static IReadOnlyList<TuningOption> All { get; } =
    [
        Opt("recall",
            "Disable Windows Recall",
            "Blocks Recall snapshot capture and removes the AI fabric packages. Disabling " +
            "Recall removes an always-on screen snapshot history from this machine.",
            "AI", true,
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /V DisableAIDataAnalysis /T REG_DWORD /D 1 /F""",
                """reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsAI" /V DisableAIDataAnalysis /T REG_DWORD /D 1 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /V TurnOffSavingSnapshots /T REG_DWORD /D 1 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /V AllowRecallEnablement /T REG_DWORD /D 0 /F""",
                """powershell -NoProfile -Command "Stop-Service -Name 'WSAIFabricSvc' -ErrorAction SilentlyContinue; Set-Service -Name 'WSAIFabricSvc' -StartupType Disabled""" + "\"",
                """powershell -NoProfile -Command "$tasks = @('\Microsoft\Windows\WindowsAI\Recall\InitialConfiguration','\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration'); foreach($t in $tasks){ if(Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue){ Disable-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue }}""" + "\"",
                """dism /Online /Disable-Feature /FeatureName:Recall /Remove /NoRestart /Quiet""",
                """powershell "Get-AppxPackage -AllUsers *AiFabric* | Remove-AppxPackage -AllUsers""" + "\"",
                """powershell "Get-AppxPackage -AllUsers *WindowsIntelligence* | Remove-AppxPackage -AllUsers""" + "\"",
            ],
            [
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /V DisableAIDataAnalysis /F""",
                """reg delete "HKCU\Software\Policies\Microsoft\Windows\WindowsAI" /V DisableAIDataAnalysis /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /V TurnOffSavingSnapshots /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /V AllowRecallEnablement /F""",
                """powershell -NoProfile -Command "Set-Service -Name 'WSAIFabricSvc' -StartupType Manual""" + "\"",
                """powershell -NoProfile -Command "$tasks = @('\Microsoft\Windows\WindowsAI\Recall\InitialConfiguration','\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration'); foreach($t in $tasks){ if(Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue){ Enable-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue }}""" + "\"",
                """dism /Online /Enable-Feature /FeatureName:Recall /NoRestart""",
            ]),

        Opt("windows-ai",
            "Disable Windows AI features",
            "Turns off Copilot, gaming AI capture, Notepad/Paint AI, Edge AI features and " +
            "the Windows AI data collection policy across the system.",
            "AI", true,
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameBar" /V UseGamingCopilot /T REG_DWORD /D 0 /F""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /V AppCaptureEnabled /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\Glass" /V IsEyeContactEnabled /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\Glass" /V IsVoiceFocusEnabled /T REG_DWORD /D 0 /F""",
                """reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\AppLaunchAllowed" /V AgentAllowed /T REG_DWORD /D 0 /F""",
                """reg add "HKCU\Software\Microsoft\Notepad" /V ShowRewriteButton /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SOFTWARE\Policies\WindowsNotepad" /V DisableAIFeatures /T REG_DWORD /D 1 /F""",
                """reg add "HKCU\Software\Microsoft\OneDrive" /V EnablePeopleProcessing /T REG_DWORD /D 0 /F""",
                """reg add "HKCU\Software\Policies\Microsoft\Windows\Paint" /V AllowCocreator /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint" /V DisableImageCreator /T REG_DWORD /D 1 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Intelligence" /V AllowWindowsIntelligence /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V ComposeEnabled /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V HubsSidebarEnabled /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V GenAILocalFoundationalModelSettings /T REG_DWORD /D 1 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V EnableDynamicContentInSearchBox /T REG_DWORD /D 0 /F""",
                """reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /V DisableSearchBoxSuggestions /T REG_DWORD /D 1 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /V DisableAgentConnectors /T REG_DWORD /D 1 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /V DisableAIDataCollection /T REG_DWORD /D 1 /F""",
                """sc stop InputInsights""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\InputInsights" /v Start /t REG_DWORD /d 4 /f""",
                """schtasks /change /tn "\Microsoft\Windows\Input\InputInsights" /disable""",
                """schtasks /change /tn "\Microsoft\Windows\WindowsAI\AIHost" /disable""",
                """schtasks /change /tn "\Microsoft\Windows\WindowsAI\AIFeedback" /disable""",
            ],
            [
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\GameBar" /V UseGamingCopilot /F""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /V AppCaptureEnabled /T REG_DWORD /D 1 /F""",
                """reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\Glass" /V IsEyeContactEnabled /F""",
                """reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\Glass" /V IsVoiceFocusEnabled /F""",
                """reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\AppLaunchAllowed" /V AgentAllowed /T REG_DWORD /D 1 /F""",
                """reg delete "HKCU\Software\Microsoft\Notepad" /V ShowRewriteButton /F""",
                """reg delete "HKLM\SOFTWARE\Policies\WindowsNotepad" /V DisableAIFeatures /F""",
                """reg add "HKCU\Software\Microsoft\OneDrive" /V EnablePeopleProcessing /T REG_DWORD /D 1 /F""",
                """reg delete "HKCU\Software\Policies\Microsoft\Windows\Paint" /V AllowCocreator /F""",
                """reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint" /V DisableImageCreator /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Intelligence" /V AllowWindowsIntelligence /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V ComposeEnabled /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V HubsSidebarEnabled /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /V GenAILocalFoundationalModelSettings /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V EnableDynamicContentInSearchBox /F""",
                """reg delete "HKCU\Software\Policies\Microsoft\Windows\Explorer" /V DisableSearchBoxSuggestions /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /V DisableAgentConnectors /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /V DisableAIDataCollection /F""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\AiFabric" /v Start /t REG_DWORD /d 3 /f""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\InputInsights" /v Start /t REG_DWORD /d 3 /f""",
                """schtasks /change /tn "\Microsoft\Windows\Input\InputInsights" /enable""",
                """schtasks /change /tn "\Microsoft\Windows\WindowsAI\AIHost" /enable""",
                """schtasks /change /tn "\Microsoft\Windows\WindowsAI\AIFeedback" /enable""",
            ]),

        Opt("start-recommended",
            "Hide Start menu recommended section",
            "Removes the Recommended section and its suggestions from the Start menu.",
            "Explorer", true,
            [
                """reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start" /v HideRecommendedSection /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Education" /v IsEducationEnvironment /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v HideRecommendedSection /t REG_DWORD /d 1 /f""",
            ],
            [
                """reg delete "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start" /v HideRecommendedSection /f""",
                """reg delete "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Education" /v IsEducationEnvironment /f""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v HideRecommendedSection /f""",
            ]),

        Opt("background-apps",
            "Disable background apps",
            "Stops Store apps from running in the background, disables Office click-to-run " +
            "background logging and makes Microsoft accounts optional for Store apps.",
            "Explorer", true,
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v BackgroundAppGlobalToggle /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsRunInBackground /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Microsoft\ClickToRun\OverRide" /v DisableLogManagement /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" /v TimerInterval /t REG_SZ /d 900000 /f""",
                """reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v MSAOptional /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoPublishingWizard /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoWebServices /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoOnlinePrintsWizard /t REG_DWORD /d 1 /f""",
            ],
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 0 /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v BackgroundAppGlobalToggle /f""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsRunInBackground /f""",
                """reg delete "HKLM\SOFTWARE\Microsoft\ClickToRun\OverRide" /v DisableLogManagement /f""",
                """reg delete "HKLM\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" /v TimerInterval /f""",
                """reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v MSAOptional /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoPublishingWizard /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoWebServices /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoOnlinePrintsWizard /f""",
            ]),

        Opt("window-shake",
            "Disable window shake minimize",
            "Windows will no longer minimize every other window when you shake one ” " +
            "a gesture that can scatter your work.",
            "Explorer", false,
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DisallowShaking /t REG_DWORD /d 1 /f""",
            ],
            [
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DisallowShaking /f""",
            ]),

        Opt("classic-context-menu",
            "Enable classic context menu",
            "Restores the full Windows 10-style right-click menu in File Explorer instead " +
            "of the condensed Windows 11 menu.",
            "Explorer", false,
            [
                """reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f""",
            ],
            [
                """reg delete "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" /f""",
            ]),

        Opt("copy-move-menu",
            "Add Copy To / Move To context menu",
            "Adds Copy To and Move To entries to the right-click menu of every file.",
            "Explorer", true,
            [
                """reg add "HKLM\SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To" /ve /d "{C2FBB630-2971-11D1-A18C-00C04FD75D13}" /f""",
                """reg add "HKLM\SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\Move To" /ve /d "{C2FBB631-2971-11D1-A18C-00C04FD75D13}" /f""",
            ],
            [
                """reg delete "HKLM\SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To" /f""",
                """reg delete "HKLM\SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\Move To" /f""",
            ]),

        Opt("menu-show-delay",
            "Zero menu show delay",
            "Menus open instantly instead of after the default hover delay.",
            "Performance", false,
            [
                """reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 0 /f""",
            ],
            [
                """reg delete "HKCU\Control Panel\Desktop" /v MenuShowDelay /f""",
            ]),

        Opt("mouse-hover-time",
            "Zero mouse hover time",
            "Tooltips and hover popups appear instantly.",
            "Performance", false,
            [
                """reg add "HKCU\Control Panel\Mouse" /v MouseHoverTime /t REG_SZ /d 0 /f""",
            ],
            [
                """reg delete "HKCU\Control Panel\Mouse" /v MouseHoverTime /f""",
            ]),

        Opt("keyboard-latency",
            "Fastest keyboard response",
            "Sets the keyboard repeat delay to shortest and repeat rate to fastest, " +
            "for this account and the default profile.",
            "Performance", false,
            [
                """reg add "HKCU\Control Panel\Keyboard" /v KeyboardDelay /t REG_SZ /d 0 /f""",
                """reg add "HKCU\Control Panel\Keyboard" /v KeyboardSpeed /t REG_SZ /d 31 /f""",
                """reg add "HKEY_USERS\.DEFAULT\Control Panel\Keyboard" /v KeyboardDelay /t REG_SZ /d 0 /f""",
                """reg add "HKEY_USERS\.DEFAULT\Control Panel\Keyboard" /v KeyboardSpeed /t REG_SZ /d 31 /f""",
            ],
            [
                """reg add "HKCU\Control Panel\Keyboard" /v KeyboardDelay /t REG_SZ /d 1 /f""",
                """reg add "HKCU\Control Panel\Keyboard" /v KeyboardSpeed /t REG_SZ /d 31 /f""",
                """reg add "HKEY_USERS\.DEFAULT\Control Panel\Keyboard" /v KeyboardDelay /t REG_SZ /d 1 /f""",
                """reg add "HKEY_USERS\.DEFAULT\Control Panel\Keyboard" /v KeyboardSpeed /t REG_SZ /d 31 /f""",
            ]),

        Opt("mouse-acceleration",
            "Disable mouse acceleration",
            "Mouse movement maps 1:1 to the pointer ” preferred for precision work and games.",
            "Performance", false,
            [
                """reg add "HKCU\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d 0 /f""",
                """reg add "HKCU\Control Panel\Mouse" /v MouseThreshold1 /t REG_SZ /d 0 /f""",
                """reg add "HKCU\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d 0 /f""",
            ],
            [
                """reg add "HKCU\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d 1 /f""",
                """reg add "HKCU\Control Panel\Mouse" /v MouseThreshold1 /t REG_SZ /d 6 /f""",
                """reg add "HKCU\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d 10 /f""",
            ]),

        Opt("fullscreen-optimizations",
            "Disable fullscreen optimizations",
            "Windows stops optimizing exclusive fullscreen for games; some older games " +
            "run better, some newer games run worse.",
            "Gaming", false,
            [
                """reg add "HKCU\System\GameConfigStore" /v GameDVR_DXGIHonorFSEWindowsCompatible /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\System\GameConfigStore" /v GameDVR_FSEBehavior /t REG_DWORD /d 2 /f""",
                """reg add "HKCU\System\GameConfigStore" /v GameDVR_FSEBehaviorMode /t REG_DWORD /d 2 /f""",
                """reg add "HKCU\System\GameConfigStore" /v GameDVR_HonorUserFSEBehaviorMode /t REG_DWORD /d 1 /f""",
            ],
            [
                """reg add "HKCU\System\GameConfigStore" /v GameDVR_DXGIHonorFSEWindowsCompatible /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\System\GameConfigStore" /v GameDVR_FSEBehavior /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\System\GameConfigStore" /v GameDVR_FSEBehaviorMode /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\System\GameConfigStore" /v GameDVR_HonorUserFSEBehaviorMode /t REG_DWORD /d 0 /f""",
            ]),

        Opt("foreground-priority",
            "Prioritize foreground applications",
            "Gives the program you are actively using a larger CPU scheduling share " +
            "(Win32PrioritySeparation 42 instead of 2).",
            "Performance", true,
            [
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 42 /f""",
            ],
            [
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 2 /f""",
            ]),

        Opt("wpbt",
            "Disable WPBT execution",
            "Disables Windows Platform Binary Table execution ” firmware can no longer " +
            "inject code into Windows at boot.",
            "System", true,
            [
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v DisableWpbtExecution /t REG_DWORD /d 1 /f""",
            ],
            [
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v DisableWpbtExecution /t REG_DWORD /d 0 /f""",
            ]),

        Opt("legacy-boot-menu",
            "Enable legacy boot menu (F8)",
            "Restores the F8 advanced boot options menu at startup.",
            "System", true,
            [
                """bcdedit /set bootmenupolicy legacy""",
            ],
            [
                """bcdedit /set bootmenupolicy standard""",
            ]),

        Opt("remote-assistance",
            "Disable Remote Assistance",
            "Nobody can send a Remote Assistance invitation from this machine.",
            "Security", true,
            [
                """reg add "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg delete "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /f""",
            ]),

        Opt("remote-registry",
            "Disable Remote Registry service",
            "The remote registry service can no longer be started; another machine cannot " +
            "read this machine's registry over the network.",
            "Security", true,
            [
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry" /v Start /t REG_DWORD /d 4 /f""",
            ],
            [
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry" /v Start /t REG_DWORD /d 3 /f""",
            ]),

        Opt("crash-dump",
            "Small crash dumps",
            "Writes a small memory dump (minidump) on BSOD instead of the default.",
            "System", true,
            [
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 3 /f""",
            ],
            [
                """reg delete "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled /f""",
            ]),

        Opt("task-timeouts",
            "Faster shutdown task timeouts",
            "Hung apps are ended after 1 second and shutdown waits at most 2 seconds.",
            "Performance", false,
            [
                """reg add "HKCU\Control Panel\Desktop" /v AutoEndTasks /t REG_SZ /d 1 /f""",
                """reg add "HKCU\Control Panel\Desktop" /v HungAppTimeout /t REG_SZ /d 1000 /f""",
                """reg add "HKCU\Control Panel\Desktop" /v WaitToKillAppTimeout /t REG_SZ /d 2000 /f""",
                """reg add "HKCU\Control Panel\Desktop" /v LowLevelHooksTimeout /t REG_SZ /d 1000 /f""",
            ],
            [
                """reg delete "HKCU\Control Panel\Desktop" /v AutoEndTasks /f""",
                """reg delete "HKCU\Control Panel\Desktop" /v HungAppTimeout /f""",
                """reg delete "HKCU\Control Panel\Desktop" /v WaitToKillAppTimeout /f""",
                """reg delete "HKCU\Control Panel\Desktop" /v LowLevelHooksTimeout /f""",
            ]),

        Opt("service-timeouts",
            "Faster service shutdown timeout",
            "Services are killed after 2 seconds at shutdown instead of the default 5.",
            "Performance", true,
            [
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v WaitToKillServiceTimeout /t REG_SZ /d 2000 /f""",
            ],
            [
                """reg delete "HKLM\SYSTEM\CurrentControlSet\Control" /v WaitToKillServiceTimeout /f""",
            ]),

        Opt("low-disk-space-checks",
            "Disable low disk space checks",
            "Stops the low-disk-space warning balloon.",
            "Explorer", false,
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoLowDiskSpaceChecks /t REG_DWORD /d 00000001 /f""",
            ],
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoLowDiskSpaceChecks /t REG_DWORD /d 00000000 /f""",
            ]),

        Opt("link-resolve",
            "Disable link resolve helpers",
            "Stops Windows searching the network and internet to resolve broken shortcuts.",
            "Explorer", false,
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v LinkResolveIgnoreLinkInfo /t REG_DWORD /d 00000001 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoResolveSearch /t REG_DWORD /d 00000001 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoResolveTrack /t REG_DWORD /d 00000001 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoInternetOpenWith /t REG_DWORD /d 00000001 /f""",
            ],
            [
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v LinkResolveIgnoreLinkInfo /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoResolveSearch /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoResolveTrack /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoInternetOpenWith /f""",
            ]),

        Opt("transparency",
            "Disable transparency effects",
            "Windows and surfaces render solid instead of translucent ” lighter on GPU.",
            "Personalization", false,
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 1 /f""",
            ]),

        Opt("verbose-logon",
            "Verbose logon messages",
            "Shows detailed status messages while signing in.",
            "System", true,
            [
                """reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v VerboseStatus /t REG_DWORD /d 1 /f""",
            ],
            [
                """reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v VerboseStatus /t REG_DWORD /d 0 /f""",
            ]),
    ];

    private static TuningOption Opt(
        string id, string title, string description, string category, bool requiresElevation,
        string[] apply, string[] revert) =>
        new(id, title, description, category, requiresElevation, apply, revert);
}
