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
/// Explorer, taskbar and system-feature toggles transcribed from RyTuneX
/// OptimizeSystemHelper.cs (part 4).
/// </summary>
public static class ShellCatalog
{
    public static IReadOnlyList<TuningOption> All { get; } =
    [
        Opt("quick-access-history",
            "Disable Quick Access history and ads",
            "Frequent folders and recent files stop being tracked, sync-provider ads in " +
            "Explorer go away, Explorer opens at This PC, and Meet Now plus File History " +
            "policies are disabled.",
            "Explorer", false,
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v EnthusiastMode /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v ShowFrequent /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v ShowRecent /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAMeetNow /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAMeetNow /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\FileHistory" /v Disabled /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\File History" /v Disabled /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackProgs /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\TestHooks" /v DisablePreLaunch /t REG_DWORD /d 1 /f""",
            ],
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v EnthusiastMode /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v ShowFrequent /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v ShowRecent /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d 2 /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /f""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\FileHistory" /v Disabled /f""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\File History" /v Disabled /f""",
                """reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAMeetNow /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAMeetNow /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackProgs /f""",
                """reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\TestHooks" /v DisablePreLaunch /f""",
            ]),

        Opt("start-menu-ads",
            "Disable Start menu ads and suggestions",
            "Removes suggested apps, tips, and all subscribed-content promotion from the " +
            "Start menu, plus online search suggestions.",
            "Privacy", false,
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-88000326Enabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v ScoobeSystemSettingEnabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ContentDeliveryAllowed /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RemediationRequired /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEverEnabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-314559Enabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338387Enabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338393Enabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353694Enabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353696Enabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-310093Enabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContentEnabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SoftLandingEnabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v FeatureManagementEnabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v AllowOnlineTips /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f""",
            ],
            [
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-88000326Enabled /f""",
                """reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v ScoobeSystemSettingEnabled /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ContentDeliveryAllowed /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RemediationRequired /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEverEnabled /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-314559Enabled /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338387Enabled /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338393Enabled /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353694Enabled /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353696Enabled /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-310093Enabled /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContentEnabled /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SoftLandingEnabled /f""",
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v FeatureManagementEnabled /f""",
                """reg delete "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v DisableSearchBoxSuggestions /f""",
                """reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v AllowOnlineTips /f""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v DisableSearchBoxSuggestions /f""",
            ]),

        Opt("my-people",
            "Disable My People taskbar band",
            "Removes the People band from the taskbar.",
            "Explorer", false,
            [
                """reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v PeopleBand /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v PeopleBand /t REG_DWORD /d 1 /f""",
            ]),

        Opt("windows-ink",
            "Disable Windows Ink workspace",
            "Removes the Ink workspace and suggested ink apps; inking with touch off.",
            "Explorer", true,
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v AllowWindowsInkWorkspace /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v EnableInkingWithTouch /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v AllowWindowsInkWorkspace /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v EnableInkingWithTouch /t REG_DWORD /d 1 /f""",
            ]),

        Opt("spelling-typing",
            "Disable touch keyboard spelling features",
            "Turns off autocorrection, spellchecking, insights, double-tap space, " +
            "prediction space insertion and text prediction for the touch keyboard.",
            "Explorer", false,
            [
                """reg add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v EnableAutocorrection /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v EnableSpellchecking /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Input\Settings" /v InsightsEnabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v EnableDoubleTapSpace /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v EnablePredictionSpaceInsertion /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v EnableTextPrediction /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v EnableAutocorrection /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v EnableSpellchecking /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Microsoft\Input\Settings" /v InsightsEnabled /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v EnableDoubleTapSpace /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v EnablePredictionSpaceInsertion /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v EnableTextPrediction /t REG_DWORD /d 1 /f""",
            ]),

        Opt("sticky-keys",
            "Disable Sticky Keys and accessibility shortcuts",
            "Pressing Shift five times no longer pops the Sticky Keys prompt — a prompt " +
            "that can be abused for local privilege escalation on unlocked machines.",
            "Security", false,
            [
                """reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f""",
                """reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v Flags /t REG_SZ /d 122 /f""",
                """reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 58 /f""",
                """reg add "HKEY_USERS\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f""",
                """reg add "HKEY_USERS\.DEFAULT\Control Panel\Accessibility\Keyboard Response" /v Flags /t REG_SZ /d 122 /f""",
                """reg add "HKEY_USERS\.DEFAULT\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 58 /f""",
            ],
            [
                """reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 510 /f""",
                """reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v Flags /t REG_SZ /d 126 /f""",
                """reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 62 /f""",
                """reg add "HKEY_USERS\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 510 /f""",
                """reg add "HKEY_USERS\.DEFAULT\Control Panel\Accessibility\Keyboard Response" /v Flags /t REG_SZ /d 126 /f""",
                """reg add "HKEY_USERS\.DEFAULT\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 62 /f""",
            ]),

        Opt("cast-to-device",
            "Remove Cast to Device context menu",
            "Removes the Cast to Device entry from the right-click menu.",
            "Explorer", true,
            [
                """reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /V {7AD84985-87B4-4a16-BE58-8B72A5B390F7} /T REG_SZ /D "Play to Menu" /F""",
            ],
            [
                """reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /V {7AD84985-87B4-4a16-BE58-8B72A5B390F7} /F""",
            ]),

        Opt("snap-assist",
            "Disable Snap Assist flyouts",
            "Windows stop showing the snap layout suggestions when you snap or dock a window.",
            "Explorer", false,
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V EnableSnapAssistFlyout /T REG_DWORD /D 0 /F""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V EnableSnapBar /T REG_DWORD /D 0 /F""",
                """reg add "HKCU\Control Panel\Desktop" /V DockMoving /T REG_SZ /D 0 /F""",
            ],
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V EnableSnapAssistFlyout /T REG_DWORD /D 1 /F""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V EnableSnapBar /T REG_DWORD /D 1 /F""",
                """reg add "HKCU\Control Panel\Desktop" /V DockMoving /T REG_SZ /D 1 /F""",
            ]),

        Opt("widgets",
            "Disable Widgets taskbar button",
            "Removes the Widgets button and its feed from the taskbar.",
            "Explorer", false,
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V TaskbarDa /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /V EnableFeeds /T REG_DWORD /D 0 /F""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /V AllowNewsAndInterests /T REG_DWORD /D 0 /F""",
            ],
            [
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V TaskbarDa /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /V EnableFeeds /F""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /V AllowNewsAndInterests /F""",
            ]),

        Opt("chat",
            "Disable Chat taskbar button",
            "Removes the Teams Chat button from the taskbar.",
            "Explorer", false,
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V TaskbarMn /T REG_DWORD /D 0 /F""",
            ],
            [
                """reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V TaskbarMn /F""",
            ]),

        Opt("files-compact-mode",
            "Enable File Explorer compact mode",
            "Uses the denser Windows 10-style spacing in File Explorer.",
            "Explorer", false,
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V UseCompactMode /T REG_DWORD /D 1 /F""",
            ],
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V UseCompactMode /T REG_DWORD /D 0 /F""",
            ]),

        Opt("stickers",
            "Enable Windows stickers",
            "Re-enables the sticker feature on touch devices via the policy key.",
            "Personalization", true,
            [
                """reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Stickers" /V EnableStickers /T REG_DWORD /D 1 /F""",
            ],
            [
                """reg delete "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Stickers" /V EnableStickers /F""",
            ]),

        Opt("taskbar-left",
            "Align taskbar to the left",
            "Moves the Windows 11 taskbar icons to the left edge, Windows 10 style.",
            "Personalization", false,
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAl /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAl /t REG_DWORD /d 1 /f""",
            ]),

        Opt("end-task",
            "Enable End Task on the taskbar",
            "Right-clicking a taskbar app gets a direct End Task option (developer setting).",
            "Explorer", false,
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings" /v TaskbarEndTask /t REG_DWORD /d 1 /f""",
            ],
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings" /v TaskbarEndTask /t REG_DWORD /d 0 /f""",
            ]),

        Opt("legacy-volume-slider",
            "Enable legacy volume slider",
            "Restores the classic volume overlay instead of the Windows 11 one.",
            "Personalization", true,
            [
                """reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\MTCUVC" /v EnableMtcUvc /t REG_DWORD /d 1 /f""",
            ],
            [
                """reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\MTCUVC" /v EnableMtcUvc /t REG_DWORD /d 0 /f""",
            ]),

        Opt("fax-service",
            "Disable Fax service",
            "Stops and disables the Fax service. Faxing stops working.",
            "Services", true,
            [
                "sc stop Fax",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\Fax" /v Start /t REG_DWORD /d 4 /f""",
            ],
            [
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\Fax" /v Start /t REG_DWORD /d 3 /f""",
            ]),

        Opt("insider-service",
            "Disable Windows Insider service",
            "Stops and disables wisvc and blocks Insider preview builds and experimentation. " +
            "You will not receive Insider builds.",
            "System", true,
            [
                "sc stop wisvc",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\wisvc" /v Start /t REG_DWORD /d 4 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v AllowBuildPreview /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v EnableConfigFlighting /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v EnableExperimentation /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v HideInsiderPage /t REG_DWORD /d 1 /f""",
            ],
            [
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\wisvc" /v Start /t REG_DWORD /d 3 /f""",
                "sc start wisvc",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v AllowBuildPreview /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v EnableConfigFlighting /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v EnableExperimentation /t REG_DWORD /d 1 /f""",
                """reg delete "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v HideInsiderPage /f""",
            ]),

        Opt("cloud-clipboard",
            "Disable clipboard history and cloud clipboard",
            "Clipboard history stops and the clipboard no longer roams across devices.",
            "Privacy", true,
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v AllowClipboardHistory /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v AllowCrossDeviceClipboard /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Clipboard" /v EnableClipboardHistory /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\Software\Microsoft\Clipboard" /v EnableClipboardHistory /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v AllowClipboardHistory /f""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v AllowCrossDeviceClipboard /f""",
                """reg delete "HKCU\Software\Microsoft\Clipboard" /v EnableClipboardHistory /f""",
                """reg delete "HKLM\Software\Microsoft\Clipboard" /v EnableClipboardHistory /f""",
            ]),
    ];

    private static TuningOption Opt(
        string id, string title, string description, string category, bool requiresElevation,
        string[] apply, string[] revert) =>
        new(id, title, description, category, requiresElevation, apply, revert);
}
