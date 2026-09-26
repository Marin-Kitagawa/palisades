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
/// Privacy and telemetry toggles transcribed from RyTuneX
/// OptimizeSystemHelper.cs Disable*/Enable* pairs (part 2).
/// </summary>
public static class PrivacyCatalog
{
    public static IReadOnlyList<TuningOption> All { get; } =
    [
        Opt("error-reporting",
            "Disable Windows Error Reporting",
            "Stops WER services, applies the do-not-report policy set and blocks WER " +
            "outbound. Crash reports stop leaving the machine (dumps are still kept locally).",
            "Telemetry", true,
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v DoReport /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v AutoApproveOSDumps /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v LoggingDisabled /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v DontSendAdditionalData /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v DontShowUI /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v DefaultConsent /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v DefaultOverrideBehavior /t REG_DWORD /d 1 /f""",
                "sc stop WerSvc",
                "sc stop wercplsupport",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc" /v Start /t REG_DWORD /d 4 /f""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\wercplsupport" /v Start /t REG_DWORD /d 4 /f""",
                """powershell -NoProfile -Command "if (-not (Get-NetFirewallRule -DisplayName 'Block-Windows-Error-Reporting' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName 'Block-Windows-Error-Reporting' -Direction Outbound -Action Block -Program '%SystemRoot%\system32\svchost.exe' -Service 'WerSvc' -Profile Any }""" + "\"",
            ],
            [
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /f""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v DoReport /f""",
                """reg delete "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /f""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v AutoApproveOSDumps /f""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v LoggingDisabled /f""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v DontSendAdditionalData /f""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v DontShowUI /f""",
                """reg delete "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v DefaultConsent /f""",
                """reg delete "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v DefaultOverrideBehavior /f""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\wercplsupport" /v Start /t REG_DWORD /d 3 /f""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc" /v Start /t REG_DWORD /d 2 /f""",
                "sc start WerSvc",
                "sc start wercplsupport",
                """reg delete "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v Block-Windows-Error-Reporting /f""",
            ]),

        Opt("cortana",
            "Disable Cortana and web search",
            "Disables Cortana, Bing web search, search history and search location at the " +
            "policy level. Start menu search only looks at local files and apps.",
            "Telemetry", true,
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v IsDeviceSearchHistoryEnabled /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWeb /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWebOverMeteredConnections /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v HistoryViewEnabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v DeviceHistoryEnabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCloudSearch /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortanaAboveLock /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortanaInAAD /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortanaInAADPathOOBE /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchPrivacy /t REG_DWORD /d 3 /f""",
                """reg add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v VoiceActivationEnableAboveLockscreen /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWeb /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWebOverMeteredConnections /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v HistoryViewEnabled /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v DeviceHistoryEnabled /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v AllowSearchToUseLocation /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCloudSearch /t REG_DWORD /d 1 /f""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortanaAboveLock /f""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortanaInAAD /f""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortanaInAADPathOOBE /f""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowSearchToUseLocation /f""",
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchPrivacy /f""",
                """reg delete "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v VoiceActivationEnableAboveLockscreen /f""",
            ]),

        Opt("news-interests",
            "Disable News and Interests / Widgets feed",
            "Removes the news and weather feed from the taskbar.",
            "Privacy", true,
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v EnableFeeds /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v EnableFeeds /t REG_DWORD /d 1 /f""",
            ]),

        Opt("spotlight",
            "Disable Windows Spotlight",
            "Stops lock-screen and start-menu Spotlight content, third-party suggestions " +
            "and welcome experiences, for this account and the default profile.",
            "Privacy", false,
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenOverlayEnabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenEnabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v ConfigureWindowsSpotlight /t REG_DWORD /d 2 /f""",
                """reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\CloudContent" /v ConfigureWindowsSpotlight /t REG_DWORD /d 2 /f""",
                """reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableThirdPartySuggestions /t REG_DWORD /d 1 /f""",
                """reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\CloudContent" /v DisableThirdPartySuggestions /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightWindowsWelcomeExperience /t REG_DWORD /d 1 /f""",
                """reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightWindowsWelcomeExperience /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightOnActionCenter /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightOnSettings /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f""",
                """reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v IncludeEnterpriseSpotlight /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenOverlayEnabled /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenEnabled /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 0 /f""",
                """reg delete "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v ConfigureWindowsSpotlight /f""",
                """reg delete "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\CloudContent" /v ConfigureWindowsSpotlight /f""",
                """reg delete "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableThirdPartySuggestions /f""",
                """reg delete "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\CloudContent" /v DisableThirdPartySuggestions /f""",
                """reg delete "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightWindowsWelcomeExperience /f""",
                """reg delete "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightWindowsWelcomeExperience /f""",
                """reg delete "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightOnActionCenter /f""",
                """reg delete "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightOnSettings /f""",
                """reg delete "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /f""",
                """reg delete "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /f""",
                """reg delete "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v IncludeEnterpriseSpotlight /f""",
            ]),

        Opt("tailored-experiences",
            "Disable tailored experiences",
            "Stops Microsoft using diagnostic data to personalize tips, ads and " +
            "recommendations, for this account and the default profile.",
            "Privacy", false,
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f""",
                """reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 1 /f""",
                """reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 1 /f""",
            ]),

        Opt("cloud-content",
            "Disable cloud optimized content",
            "Blocks Windows from pulling cloud-delivered shell content.",
            "Privacy", true,
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableCloudOptimizedContent /t REG_DWORD /d 1 /f""",
            ],
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableCloudOptimizedContent /t REG_DWORD /d 0 /f""",
            ]),

        Opt("feedback-notifications",
            "Disable feedback notifications",
            "Windows stops asking for feedback.",
            "Privacy", true,
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f""",
            ],
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 0 /f""",
            ]),

        Opt("advertising-id",
            "Disable advertising ID",
            "Apps can no longer show you personalized ads via the Windows advertising ID.",
            "Privacy", true,
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f""",
            ],
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 0 /f""",
            ]),

        Opt("bluetooth-advertising",
            "Disable Bluetooth advertising",
            "Bluetooth devices stop receiving advertising from this machine.",
            "Privacy", true,
            [
                """reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /v AllowAdvertising /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /v AllowAdvertising /t REG_DWORD /d 1 /f""",
            ]),

        Opt("auto-restart-signon",
            "Disable automatic restart sign-on",
            "Windows no longer saves your sign-in to auto-complete lock screen updates — " +
            "slightly less convenient after updates, no stored credentials.",
            "Privacy", true,
            [
                """reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableAutomaticRestartSignOn /t REG_DWORD /d 1 /f""",
            ],
            [
                """reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableAutomaticRestartSignOn /t REG_DWORD /d 0 /f""",
            ]),

        Opt("handwriting-sharing",
            "Disable handwriting data sharing",
            "Blocks sharing inking data with Microsoft.",
            "Telemetry", true,
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPc" /v PreventHandwritingDataSharing /t REG_DWORD /d 1 /f""",
            ],
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPc" /v PreventHandwritingDataSharing /t REG_DWORD /d 0 /f""",
            ]),

        Opt("text-input-collection",
            "Disable linguistic data collection",
            "Stops collection of typed and handwritten text for language modeling.",
            "Telemetry", true,
            [
                """reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" /v AllowLinguisticDataCollection /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" /v AllowLinguisticDataCollection /t REG_DWORD /d 1 /f""",
            ]),

        Opt("input-personalization",
            "Disable input personalization",
            "Turns off cloud-based personalization of typing, inking and dictation.",
            "Telemetry", true,
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v AllowInputPersonalization /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v AllowInputPersonalization /t REG_DWORD /d 1 /f""",
            ]),

        Opt("safe-search",
            "Bing SafeSearch off",
            "Sets Bing SafeSearch to off in Windows search.",
            "Explorer", false,
            [
                """reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v SafeSearchMode /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v SafeSearchMode /t REG_DWORD /d 1 /f""",
            ]),

        Opt("activity-uploads",
            "Disable activity uploads",
            "Stops uploading your activity history to Microsoft's cloud (timeline sync).",
            "Telemetry", true,
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 1 /f""",
            ]),

        Opt("clipboard-sync",
            "Disable cross-device clipboard",
            "Clipboard history and cloud clipboard sync between devices stop.",
            "Privacy", true,
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v AllowCrossDeviceClipboard /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v AllowCrossDeviceClipboard /t REG_DWORD /d 1 /f""",
            ]),

        Opt("message-sync",
            "Disable message sync",
            "Stops syncing text messages between your phone and Windows.",
            "Privacy", true,
            [
                """reg add "HKLM\Software\Policies\Microsoft\Windows\Messaging" /v AllowMessageSync /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg add "HKLM\Software\Policies\Microsoft\Windows\Messaging" /v AllowMessageSync /t REG_DWORD /d 1 /f""",
            ]),

        Opt("settings-sync",
            "Disable settings sync",
            "Stops syncing credentials and application settings between devices.",
            "Privacy", true,
            [
                """reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableCredentialsSettingSync /t REG_DWORD /d 2 /f""",
                """reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableCredentialsSettingSyncUserOverride /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableApplicationSettingSync /t REG_DWORD /d 2 /f""",
                """reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableApplicationSettingSyncUserOverride /t REG_DWORD /d 1 /f""",
            ],
            [
                """reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableCredentialsSettingSync /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableCredentialsSettingSyncUserOverride /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableApplicationSettingSync /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableApplicationSettingSyncUserOverride /t REG_DWORD /d 0 /f""",
            ]),

        Opt("voice-activation",
            "Force-deny voice activation",
            "Apps are policy-blocked from activating with your voice.",
            "Privacy", true,
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoice /t REG_DWORD /d 2 /f""",
            ],
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoice /t REG_DWORD /d 1 /f""",
            ]),

        Opt("find-my-device",
            "Disable Find My Device",
            "Stops location sync for lost-device tracking.",
            "Privacy", true,
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice" /v AllowFindMyDevice /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Microsoft\Settings\FindMyDevice" /v LocationSyncEnabled /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice" /v AllowFindMyDevice /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Microsoft\Settings\FindMyDevice" /v LocationSyncEnabled /t REG_DWORD /d 1 /f""",
            ]),

        Opt("activity-feed",
            "Disable activity feed",
            "Turns off the Windows activity feed / timeline collection.",
            "Telemetry", true,
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 1 /f""",
            ]),

        Opt("cdp",
            "Disable Continuous Diagnostics tracking",
            "Turns off the Connected Devices Platform and activity coordination.",
            "Telemetry", true,
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableCdp /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableCdp /t REG_DWORD /d 1 /f""",
            ]),

        Opt("diagnostics-toast",
            "Lowest diagnostics consent",
            "Sets diagnostic data consent toast to the minimal level for this account and " +
            "the default profile.",
            "Telemetry", false,
            [
                """reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v ShowedToastAtLevel /t REG_DWORD /d 1 /f""",
                """reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v ShowedToastAtLevel /t REG_DWORD /d 1 /f""",
            ],
            [
                """reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v ShowedToastAtLevel /t REG_DWORD /d 0 /f""",
                """reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v ShowedToastAtLevel /t REG_DWORD /d 0 /f""",
            ]),

        Opt("online-speech",
            "Disable online speech recognition",
            "Dictation goes local only; voice data stops going to Microsoft cloud speech.",
            "Privacy", false,
            [
                """reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v HasAccepted /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v HasAccepted /t REG_DWORD /d 1 /f""",
            ]),

        Opt("location",
            "Disable location",
            "Blocks location for apps and disables the Windows location provider. Apps that " +
            "need your position (maps, weather) stop getting it.",
            "Privacy", true,
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v Value /t REG_SZ /d Deny /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v DisableLocation /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v DisableWindowsLocationProvider /t REG_DWORD /d 1 /f""",
            ],
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v Value /t REG_SZ /d Allow /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v DisableLocation /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v DisableWindowsLocationProvider /t REG_DWORD /d 0 /f""",
            ]),

        Opt("biometrics",
            "Disable biometrics (fingerprint/face sign-in)",
            "Blocks Windows Hello biometric sign-in by policy. You will sign in with a PIN " +
            "or password instead.",
            "Security", true,
            [
                """reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v Enabled /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg delete "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /f""",
            ]),
    ];

    private static TuningOption Opt(
        string id, string title, string description, string category, bool requiresElevation,
        string[] apply, string[] revert) =>
        new(id, title, description, category, requiresElevation, apply, revert);
}
