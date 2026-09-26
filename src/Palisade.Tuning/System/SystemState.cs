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

using Microsoft.Win32;

namespace Palisade.Tuning.System;

/// <summary>
/// Live applied-state detection for tuning toggles, transcribed from RyTuneX
/// SystemStateDetector. Each tag reads its real registry/service state; a
/// null means "cannot tell" — callers then fall back to the recorded state
/// marker, exactly upstream's behavior.
/// </summary>
public static class SystemState
{
    private static readonly RegistryView RegView =
        Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default;

    /// <summary>Detects the applied state for a tuning option id (null = unknown).</summary>
    public static bool? DetectForOption(string optionId) =>
        TagFor(optionId) is { } tag ? DetectState(tag) : null;

    /// <summary>The upstream detector tag for a tuning option id, if one exists.</summary>
    public static string? TagFor(string optionId) => optionId switch
    {
        "recall" => "WindowsRecall",
        "windows-ai" => "WindowsAI",
        "start-recommended" => "RecommendedSectionStartMenu",
        "background-apps" => "BackgroundApps",
        "window-shake" => "WindowShake",
        "classic-context-menu" => "ClassicContextMenu",
        "copy-move-menu" => "CopyMoveContextMenu",
        "menu-show-delay" => "MenuShowDelay",
        "mouse-hover-time" => "MouseHoverTime",
        "keyboard-latency" => "KeyboardLatency",
        "mouse-acceleration" => "MouseAcceleration",
        "fullscreen-optimizations" => "FullscreenOptimizations",
        "foreground-priority" => "PrioritizeForegroundApplications",
        "wpbt" => "WPBT",
        "legacy-boot-menu" => "LegacyBootMenu",
        "remote-assistance" => "RemoteAssistance",
        "remote-registry" => "RemoteRegistry",
        "crash-dump" => "CrashDump",
        "task-timeouts" => "TaskTimeouts",
        "service-timeouts" => "ServiceTimeouts",
        "low-disk-space-checks" => "LowDiskSpaceChecks",
        "link-resolve" => "LinkResolve",
        "transparency" => "WindowsTransparency",
        "verbose-logon" => "VerboseLogon",
        "telemetry-services" => "TelemetryServices",
        "svchost-splitting" => "ServiceHostSplitting",
        "ntfs-optimization" => "OptimizeNTFS",
        "print-spooler" => "PrintService",
        "sysmain" => "SysMain",
        "windows-search" => "Search",
        "media-player-sharing" => "MediaPlayerSharing",
        "homegroup" => "HomeGroup",
        "compatibility-assistant" => "CompatibilityAssistant",
        "system-restore" => "SystemRestore",
        "fax-service" => "FaxService",
        "insider-service" => "InsiderService",
        "cloud-clipboard" => "CloudClipboard",
        "error-reporting" => "ErrorReporting",
        "cortana" => "Cortana",
        "gaming-mode" => "GamingMode",
        "gamebar" => "GameBar",
        "usb-power-saving" => "UsbPowerSaving",
        "power-throttling" => "PowerThrottling",
        "gpu-driver-tweaks" => "GpuDriverTweaks",
        "hibernation" => "Hibernation",
        "news-interests" => "NewsAndInterests",
        "spotlight" => "SpotlightFeatures",
        "tailored-experiences" => "TailoredExperiences",
        "cloud-content" => "CloudOptimizedContent",
        "feedback-notifications" => "FeedbackNotifications",
        "advertising-id" => "AdvertisingID",
        "bluetooth-advertising" => "BluetoothAdvertising",
        "auto-restart-signon" => "AutomaticRestartSignOn",
        "handwriting-sharing" => "HandwritingDataSharing",
        "text-input-collection" => "TextInputDataCollection",
        "input-personalization" => "InputPersonalization",
        "safe-search" => "SafeSearchMode",
        "activity-uploads" => "ActivityUploads",
        "clipboard-sync" => "ClipboardSync",
        "message-sync" => "MessageSync",
        "settings-sync" => "SettingSync",
        "voice-activation" => "VoiceActivation",
        "find-my-device" => "FindMyDevice",
        "activity-feed" => "ActivityFeed",
        "cdp" => "Cdp",
        "diagnostics-toast" => "DiagnosticsToast",
        "online-speech" => "OnlineSpeechPrivacy",
        "location" => "LocationFeatures",
        "biometrics" => "Biometrics",
        "store-updates" => "StoreUpdates",
        "onedrive" => "OneDrive",
        "exclude-drivers" => "Drivers",
        "quick-access-history" => "QuickAccessHistory",
        "start-menu-ads" => "StartMenuAds",
        "my-people" => "MyPeople",
        "windows-ink" => "WindowsInk",
        "spelling-typing" => "SpellingAndTypingFeatures",
        "sticky-keys" => "StickyKeys",
        "cast-to-device" => "CastToDevice",
        "snap-assist" => "SnapAssist",
        "widgets" => "Widgets",
        "chat" => "Chat",
        "files-compact-mode" => "FilesCompactMode",
        "stickers" => "Stickers",
        "taskbar-left" => "TaskbarToLeft",
        "end-task" => "EndTask",
        "edge-discover-bar" => "EdgeDiscoverBar",
        "edge-telemetry" => "EdgeTelemetry",
        "copilot" => "CoPilotAI",
        "vs-telemetry" => "VisualStudioTelemetry",
        "nvidia-telemetry" => "NvidiaTelemetry",
        "chrome-telemetry" => "ChromeTelemetry",
        "firefox-telemetry" => "FirefoxTelemetry",
        "smartscreen" => "SmartScreen",
        "vbs" => "VBS",
        _ => null,
    };

    public static bool? DetectState(string tag)
    {
        return tag switch
        {
            "RecommendedSectionStartMenu" => All(
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\Explorer", "HideRecommendedSection", 1),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\PolicyManager\current\device\Start", "HideRecommendedSection", 1),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\PolicyManager\current\device\Education", "IsEducationEnvironment", 1)),

            "LegacyBootMenu" => null, // falls back to the recorded state marker

            "OptimizeNTFS" => DwordEquals(RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\FileSystem", "NtfsMftZoneReservation", 2),

            "PrioritizeForegroundApplications" => DwordEquals(RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\PriorityControl", "Win32PrioritySeparation", 42),

            "WPBT" => DwordEquals(RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\Session Manager", "DisableWpbtExecution", 1),

            "MenuShowDelay" => StringEquals(RegistryHive.CurrentUser, @"Control Panel\Desktop", "MenuShowDelay", "0"),

            "MouseHoverTime" => StringEquals(RegistryHive.CurrentUser, @"Control Panel\Mouse", "MouseHoverTime", "0"),

            "KeyboardLatency" => All(
                StringEquals(RegistryHive.CurrentUser, @"Control Panel\Keyboard", "KeyboardDelay", "0"),
                StringEquals(RegistryHive.CurrentUser, @"Control Panel\Keyboard", "KeyboardSpeed", "31")),

            "MouseAcceleration" => All(
                StringEquals(RegistryHive.CurrentUser, @"Control Panel\Mouse", "MouseSpeed", "0"),
                StringEquals(RegistryHive.CurrentUser, @"Control Panel\Mouse", "MouseThreshold1", "0"),
                StringEquals(RegistryHive.CurrentUser, @"Control Panel\Mouse", "MouseThreshold2", "0")),

            "BackgroundApps" => All(
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications", "GlobalUserDisabled", 1),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\AppPrivacy", "LetAppsRunInBackground", 0),
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Search", "BackgroundAppGlobalToggle", 0)),

            "AutoComplete" => Not(StringEquals(RegistryHive.CurrentUser,
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete", "AutoSuggest", "yes")),

            "CrashDump" => DwordEquals(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\CrashControl", "CrashDumpEnabled", 3),

            "RemoteAssistance" => DwordEquals(RegistryHive.LocalMachine, @"System\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp", 0),

            "WindowShake" => DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "DisallowShaking", 1),

            "CopyMoveContextMenu" => All(
                ValueExists(RegistryHive.LocalMachine, @"SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To"),
                ValueExists(RegistryHive.LocalMachine, @"SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\Move To")),

            "TaskTimeouts" => All(
                StringEquals(RegistryHive.CurrentUser, @"Control Panel\Desktop", "AutoEndTasks", "1"),
                StringEquals(RegistryHive.CurrentUser, @"Control Panel\Desktop", "HungAppTimeout", "1000"),
                StringEquals(RegistryHive.CurrentUser, @"Control Panel\Desktop", "WaitToKillAppTimeout", "2000"),
                StringEquals(RegistryHive.CurrentUser, @"Control Panel\Desktop", "LowLevelHooksTimeout", "1000")),

            "LowDiskSpaceChecks" => DwordEquals(RegistryHive.CurrentUser,
                @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoLowDiskSpaceChecks", 0),

            "LinkResolve" => All(
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "LinkResolveIgnoreLinkInfo", 1),
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoResolveSearch", 1),
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoResolveTrack", 1),
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoInternetOpenWith", 1)),

            "ServiceTimeouts" => StringEquals(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control", "WaitToKillServiceTimeout", "2000"),

            "RemoteRegistry" => ServiceDisabled("RemoteRegistry"),

            "SystemProfile" => All(
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile", "SystemResponsiveness", 10),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile", "NoLazyMode", 1),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile", "AlwaysOn", 1)),

            "TelemetryServices" => All(
                ServiceDisabled("DiagTrack"),
                ServiceDisabled("dmwappushservice"),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 0),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection", "AllowTelemetry", 0)),

            "HomeGroup" => All(
                ServiceDisabled("HomeGroupListener"),
                ServiceDisabled("HomeGroupProvider")),

            "PrintService" => ServiceDisabled("Spooler"),

            "SysMain" => All(
                ServiceDisabled("SysMain"),
                DwordEquals(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters", "EnableSuperfetch", 0),
                DwordEquals(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters", "EnablePrefetcher", 0)),

            "CompatibilityAssistant" => All(
                ServiceDisabled("PcaSvc"),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\AppCompat", "DisableUAR", 1),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\AppCompat", "AITEnable", 0)),

            "SystemRestore" => All(
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore", "DisableSR", 1),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore", "DisableConfig", 1)),

            "WindowsTransparency" => DwordEquals(RegistryHive.CurrentUser,
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "EnableTransparency", 0),

            "VerboseLogon" => DwordEquals(RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "VerboseStatus", 1),

            "ClassicContextMenu" => KeyExists(RegistryHive.CurrentUser,
                @"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"),

            "Search" => ServiceDisabled("WSearch"),

            "Biometrics" => DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Biometrics", "Enabled", 0),

            "ErrorReporting" => All(
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\Windows Error Reporting", "Disabled", 1),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\Windows Error Reporting", "DontShowUI", 1),
                ServiceDisabled("WerSvc")),

            "Cortana" => All(
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "AllowCortana", 0),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "DisableWebSearch", 1),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "ConnectedSearchUseWeb", 0),
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Search", "BingSearchEnabled", 0)),

            "GamingMode" => All(
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\GameBar", "AutoGameModeEnabled", 1),
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\GameBar", "AllowAutoGameMode", 1),
                DwordEquals(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "HwSchMode", 2)),

            "FullscreenOptimizations" => All(
                DwordEquals(RegistryHive.CurrentUser, @"System\GameConfigStore", "GameDVR_DXGIHonorFSEWindowsCompatible", 0),
                DwordEquals(RegistryHive.CurrentUser, @"System\GameConfigStore", "GameDVR_FSEBehavior", 0),
                DwordEquals(RegistryHive.CurrentUser, @"System\GameConfigStore", "GameDVR_FSEBehaviorMode", 0),
                DwordEquals(RegistryHive.CurrentUser, @"System\GameConfigStore", "GameDVR_HonorUserFSEBehaviorMode", 0)),

            "UsbPowerSaving" => null,

            "PowerThrottling" => All(
                DwordEquals(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Power\PowerThrottling", "PowerThrottlingOff", 1),
                DwordEquals(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\USB\AutomaticSurpriseRemoval", "AttemptRecoveryFromUsbPowerDrain", 0)),

            "GpuDriverTweaks" => null,

            "StoreUpdates" => All(
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SilentInstalledAppsEnabled", 0),
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "PreInstalledAppsEnabled", 0),
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "OemPreInstalledAppsEnabled", 0),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableWindowsConsumerFeatures", 1)),

            "OneDrive" => DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\OneDrive", "DisableFileSyncNGSC", 1),

            "NewsAndInterests" => All(
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Dsh", "AllowNewsAndInterests", 0),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\Windows Feeds", "EnableFeeds", 0)),

            "Hibernation" => DwordEquals(RegistryHive.LocalMachine, @"System\CurrentControlSet\Control\Power", "PlatformAoAcOverride", 0),

            "EndTask" => DwordEquals(RegistryHive.CurrentUser,
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings", "TaskbarEndTask", 1),

            "MediaPlayerSharing" => ServiceDisabled("WMPNetworkSvc"),

            "SpotlightFeatures" => DwordEquals(RegistryHive.CurrentUser,
                @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "DisableWindowsSpotlightFeatures", 1),

            "TailoredExperiences" => All(
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Privacy", "TailoredExperiencesWithDiagnosticDataEnabled", 0),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableTailoredExperiencesWithDiagnosticData", 1)),

            "CloudOptimizedContent" => DwordEquals(RegistryHive.LocalMachine,
                @"SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableCloudOptimizedContent", 1),

            "FeedbackNotifications" => DwordEquals(RegistryHive.LocalMachine,
                @"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "DoNotShowFeedbackNotifications", 1),

            "AdvertisingID" => All(
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 0),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo", "DisabledByGroupPolicy", 1)),

            "BluetoothAdvertising" => DwordEquals(RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth", "AllowAdvertising", 0),

            "AutomaticRestartSignOn" => DwordEquals(RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "DisableAutomaticRestartSignOn", 1),

            "HandwritingDataSharing" => DwordEquals(RegistryHive.LocalMachine,
                @"SOFTWARE\Policies\Microsoft\Windows\TabletPc", "PreventHandwritingDataSharing", 1),

            "TextInputDataCollection" => DwordEquals(RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput", "AllowLinguisticDataCollection", 0),

            "InputPersonalization" => DwordEquals(RegistryHive.LocalMachine,
                @"SOFTWARE\Policies\Microsoft\InputPersonalization", "AllowInputPersonalization", 0),

            "SafeSearchMode" => DwordEquals(RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings", "SafeSearchMode", 0),

            "ActivityUploads" => DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System", "UploadUserActivities", 0),

            "ClipboardSync" => DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System", "AllowCrossDeviceClipboard", 0),

            "MessageSync" => DwordEquals(RegistryHive.LocalMachine, @"Software\Policies\Microsoft\Windows\Messaging", "AllowMessageSync", 0),

            "SettingSync" => All(
                DwordEquals(RegistryHive.LocalMachine, @"Software\Policies\Microsoft\Windows\SettingSync", "DisableCredentialsSettingSync", 2),
                DwordEquals(RegistryHive.LocalMachine, @"Software\Policies\Microsoft\Windows\SettingSync", "DisableApplicationSettingSync", 2)),

            "VoiceActivation" => DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\AppPrivacy", "LetAppsActivateWithVoice", 2),

            "FindMyDevice" => All(
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\FindMyDevice", "AllowFindMyDevice", 0),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Settings\FindMyDevice", "LocationSyncEnabled", 0)),

            "ActivityFeed" => DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System", "EnableActivityFeed", 0),

            "Cdp" => DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System", "EnableCdp", 0),

            "DiagnosticsToast" => DwordEquals(RegistryHive.CurrentUser,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack", "ShowedToastAtLevel", 1),

            "OnlineSpeechPrivacy" => DwordEquals(RegistryHive.CurrentUser,
                @"Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy", "HasAccepted", 0),

            "LocationFeatures" => All(
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors", "DisableLocation", 1),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors", "DisableWindowsLocationProvider", 1)),

            "GameBar" => All(
                DwordEquals(RegistryHive.CurrentUser, @"System\GameConfigStore", "GameDVR_Enabled", 0),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\GameDVR", "AllowGameDVR", 0),
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\GameDVR", "AppCaptureEnabled", 0)),

            "QuickAccessHistory" => All(
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer", "ShowRecent", 0),
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer", "ShowFrequent", 0),
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "LaunchTo", 1)),

            "StartMenuAds" => All(
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SystemPaneSuggestionsEnabled", 0),
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "ContentDeliveryAllowed", 0)),

            "MyPeople" => DwordEquals(RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People", "PeopleBand", 0),

            "Drivers" => All(
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "ExcludeWUDriversInQualityUpdate", 1),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching", "SearchOrderConfig", 0)),

            "WindowsInk" => All(
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\WindowsInkWorkspace", "AllowWindowsInkWorkspace", 0),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\WindowsInkWorkspace", "AllowSuggestedAppsInWindowsInkWorkspace", 0)),

            "SpellingAndTypingFeatures" => All(
                DwordEquals(RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\TabletTip\1.7", "EnableAutocorrection", 0),
                DwordEquals(RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\TabletTip\1.7", "EnableSpellchecking", 0),
                DwordEquals(RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\TabletTip\1.7", "EnableTextPrediction", 0)),

            "FaxService" => ServiceDisabled("Fax"),

            "InsiderService" => All(
                ServiceDisabled("wisvc"),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds", "AllowBuildPreview", 0),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds", "EnableConfigFlighting", 0)),

            "SmartScreen" => All(
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen", 0),
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Policies\Attachments", "SaveZoneInformation", 1)),

            "CloudClipboard" => All(
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System", "AllowClipboardHistory", 0),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System", "AllowCrossDeviceClipboard", 0),
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Clipboard", "EnableClipboardHistory", 0)),

            "StickyKeys" => All(
                StringEquals(RegistryHive.CurrentUser, @"Control Panel\Accessibility\StickyKeys", "Flags", "506"),
                StringEquals(RegistryHive.CurrentUser, @"Control Panel\Accessibility\Keyboard Response", "Flags", "122"),
                StringEquals(RegistryHive.CurrentUser, @"Control Panel\Accessibility\ToggleKeys", "Flags", "58")),

            "CastToDevice" => ValueExists(RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked",
                "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}"),

            "VBS" => All(
                DwordEquals(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\DeviceGuard", "EnableVirtualizationBasedSecurity", 0),
                DwordEquals(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled", 0),
                DwordEquals(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard", "Enabled", 0)),

            "TaskbarToLeft" => DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "TaskbarAl", 0),

            "SnapAssist" => All(
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "EnableSnapAssistFlyout", 0),
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "EnableSnapBar", 0),
                StringEquals(RegistryHive.CurrentUser, @"Control Panel\Desktop", "DockMoving", "0")),

            "Widgets" => All(
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "TaskbarDa", 0),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\Windows Feeds", "EnableFeeds", 0)),

            "Chat" => DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "TaskbarMn", 0),

            "FilesCompactMode" => DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "UseCompactMode", 1),

            "Stickers" => Not(DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\PolicyManager\current\device\Stickers", "EnableStickers", 1)),

            "EdgeDiscoverBar" => All(
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Edge", "HubsSidebarEnabled", 0),
                DwordEquals(RegistryHive.CurrentUser, @"SOFTWARE\Policies\Microsoft\Edge", "HubsSidebarEnabled", 0),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Edge", "WebWidgetAllowed", 0)),

            "EdgeTelemetry" => All(
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Edge", "MetricsReportingEnabled", 0),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Edge", "StartupBoostEnabled", 0),
                ServiceDisabled("edgeupdate")),

            "CoPilotAI" => All(
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot", "TurnOffWindowsCopilot", 1),
                DwordEquals(RegistryHive.CurrentUser, @"Software\Policies\Microsoft\Windows\WindowsCopilot", "TurnOffWindowsCopilot", 1),
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ShowCopilotButton", 0)),

            "WindowsRecall" => All(
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", "DisableAIDataAnalysis", 1),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", "AllowRecallEnablement", 0),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", "TurnOffSavingSnapshots", 1)),

            "VisualStudioTelemetry" => All(
                DwordEquals(RegistryHive.CurrentUser, @"Software\Microsoft\VisualStudio\Telemetry", "TurnOffSwitch", 1),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\VisualStudio\Feedback", "DisableFeedbackDialog", 1),
                ServiceDisabled("VSStandardCollectorService150")),

            "NvidiaTelemetry" => ServiceDisabled("NvTelemetryContainer"),

            "ChromeTelemetry" => All(
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Google\Chrome", "MetricsReportingEnabled", 0),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Google\Chrome", "ChromeCleanupReportingEnabled", 0),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Google\Chrome", "UserFeedbackAllowed", 0)),

            "FirefoxTelemetry" => All(
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Mozilla\Firefox", "DisableTelemetry", 1),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Mozilla\Firefox", "DisableDefaultBrowserAgent", 1)),

            "WindowsAI" => All(
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", "DisableAgentConnectors", 1),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", "DisableAIDataAnalysis", 1),
                DwordEquals(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", "AllowRecallEnablement", 0)),

            _ => null,
        };
    }

    // Registry helpers — upstream's exact semantics: null means "cannot tell".

    private static bool? DwordEquals(RegistryHive hive, string keyPath, string valueName, int expected)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegView);
            using var key = baseKey.OpenSubKey(keyPath, writable: false);
            if (key == null)
            {
                return null;
            }
            var val = key.GetValue(valueName);
            return val is int intVal ? intVal == expected : null;
        }
        catch
        {
            return null;
        }
    }

    private static bool? StringEquals(RegistryHive hive, string keyPath, string valueName, string expected)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegView);
            using var key = baseKey.OpenSubKey(keyPath, writable: false);
            if (key == null)
            {
                return null;
            }
            var val = key.GetValue(valueName) as string;
            return val == null ? null : string.Equals(val, expected, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return null;
        }
    }

    private static bool? KeyExists(RegistryHive hive, string keyPath)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegView);
            using var key = baseKey.OpenSubKey(keyPath, writable: false);
            return key != null;
        }
        catch
        {
            return null;
        }
    }

    private static bool? ValueExists(RegistryHive hive, string keyPath, string? valueName = null)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegView);
            using var key = baseKey.OpenSubKey(keyPath, writable: false);
            if (key == null)
            {
                return null;
            }
            return valueName == null ? key.GetValueNames().Length > 0 : key.GetValue(valueName) != null;
        }
        catch
        {
            return null;
        }
    }

    private static bool? ServiceDisabled(string serviceName)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegView);
            using var key = baseKey.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}", writable: false);
            if (key == null)
            {
                return null;
            }
            return key.GetValue("Start") is int start ? start == 4 : null;
        }
        catch
        {
            return null;
        }
    }

    private static bool? Not(bool? value) => value.HasValue ? !value.Value : null;

    private static bool? All(params bool?[] checks)
    {
        if (checks.Any(c => c == false))
        {
            return false;
        }
        return checks.All(c => c == true) ? true : null;
    }
}
