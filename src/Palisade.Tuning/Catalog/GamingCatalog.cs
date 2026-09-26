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
/// Gaming and power toggles transcribed from RyTuneX OptimizeSystemHelper.cs
/// (part 3). The GPU driver tweaks and USB power-saving PowerShell are
/// upstream's scripts, passed as plain -Command strings.
/// </summary>
public static class GamingCatalog
{
    private const string UsbPowerDisableScript =
        "$devices = Get-CimInstance -Namespace root\\wmi -ClassName MSPower_DeviceEnable -ErrorAction SilentlyContinue | Where-Object { $_.InstanceName -match 'USB\\\\ROOT' }; foreach ($device in $devices) { if ($device.Enable -ne $false) { Set-CimInstance -CimInstance $device -Property @{ Enable = $false } | Out-Null } }";

    private const string UsbPowerEnableScript =
        "$devices = Get-CimInstance -Namespace root\\wmi -ClassName MSPower_DeviceEnable -ErrorAction SilentlyContinue | Where-Object { $_.InstanceName -match 'USB\\\\ROOT' }; foreach ($device in $devices) { if ($device.Enable -ne $true) { Set-CimInstance -CimInstance $device -Property @{ Enable = $true } | Out-Null } }";

    private const string GpuTweaksScript =
        "$displayClass = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}'; " +
        "$controllers = Get-CimInstance -ClassName Win32_VideoController -ErrorAction SilentlyContinue; " +
        "foreach ($gpu in $controllers) { " +
        "$deviceId = [string]$gpu.DeviceID; if ($deviceId -notmatch '^VideoController(\\d+)$') { continue }; " +
        "$index = [int]$Matches[1] - 1; $path = Join-Path $displayClass ('{0:D4}' -f $index); " +
        "if (-not (Test-Path $path)) { continue }; " +
        "$vendorText = \"$($gpu.Name) $($gpu.AdapterCompatibility)\"; " +
        "if ($vendorText -match 'AMD|Advanced Micro Devices|ATI') { " +
        "New-ItemProperty -Path $path -Name EnableULPS -Value 0 -PropertyType DWord -Force | Out-Null; " +
        "New-ItemProperty -Path $path -Name DisablePowerGating -Value 1 -PropertyType DWord -Force | Out-Null; " +
        "New-ItemProperty -Path $path -Name PP_GPUPowerDownEnabled -Value 0 -PropertyType DWord -Force | Out-Null; " +
        "New-ItemProperty -Path $path -Name DisableDynamicPstate -Value 1 -PropertyType DWord -Force | Out-Null; " +
        "New-ItemProperty -Path $path -Name DisableVCEPowerGating -Value 1 -PropertyType DWord -Force | Out-Null; " +
        "New-ItemProperty -Path $path -Name DisableVceClockGating -Value 1 -PropertyType DWord -Force | Out-Null; " +
        "New-ItemProperty -Path $path -Name EnableUvdClockGating -Value 0 -PropertyType DWord -Force | Out-Null; " +
        "New-ItemProperty -Path $path -Name EnableVceSwClockGating -Value 0 -PropertyType DWord -Force | Out-Null; " +
        "New-ItemProperty -Path $path -Name EnableAspmL0s -Value 0 -PropertyType DWord -Force | Out-Null; " +
        "New-ItemProperty -Path $path -Name EnableAspmL1 -Value 0 -PropertyType DWord -Force | Out-Null } " +
        "elseif ($vendorText -match 'NVIDIA') { " +
        "New-ItemProperty -Path $path -Name DisableDynamicPstate -Value 1 -PropertyType DWord -Force | Out-Null; " +
        "New-ItemProperty -Path $path -Name DisableASyncPstates -Value 1 -PropertyType DWord -Force | Out-Null } " +
        "elseif ($vendorText -match 'Intel') { " +
        "New-ItemProperty -Path $path -Name Display1_DisableAsyncFlips -Value 1 -PropertyType DWord -Force | Out-Null; " +
        "New-ItemProperty -Path $path -Name AdaptiveVsyncEnable -Value 0 -PropertyType DWord -Force | Out-Null } }";

    private const string GpuRevertScript =
        "$displayClass = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}'; " +
        "$values = @('EnableULPS','DisablePowerGating','PP_GPUPowerDownEnabled','DisableDynamicPstate','DisableVCEPowerGating','DisableVceClockGating','EnableUvdClockGating','EnableVceSwClockGating','EnableAspmL0s','EnableAspmL1','DisableASyncPstates','Display1_DisableAsyncFlips','AdaptiveVsyncEnable'); " +
        "Get-ChildItem -Path $displayClass -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\\d{4}$' } | ForEach-Object { foreach ($value in $values) { Remove-ItemProperty -Path $_.PSPath -Name $value -ErrorAction SilentlyContinue } }";

    public static IReadOnlyList<TuningOption> All { get; } =
    [
        Opt("gaming-mode",
            "Enable Game Mode",
            "Enables Windows Game Mode and hardware GPU scheduling for lower latency.",
            "Gaming", true,
            [
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v HwSchMode /t REG_DWORD /d 2 /f""",
                """reg add "HKCU\Software\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Microsoft\GameBar" /v AutoGameModeEnabled /t REG_DWORD /d 1 /f""",
            ],
            [
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v HwSchMode /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\GameBar" /v AutoGameModeEnabled /t REG_DWORD /d 0 /f""",
            ]),

        Opt("gamebar",
            "Disable Game Bar and Game DVR",
            "Stops the Xbox Game Bar overlay, background recording, the GameInput service " +
            "and AMD metrics capture. Background recording stops using your GPU and disk.",
            "Gaming", true,
            [
                """reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v OverlayTestMode /t REG_DWORD /d 5 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVr" /v AppCaptureEnabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVr" /v AudioCaptureEnabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVr" /v CursorCaptureEnabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\GameBar" /v UseNexusForGameBarEnabled /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\Software\Microsoft\GameBar" /v ShowStartupPanel /t REG_DWORD /d 0 /f""",
                """reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f""",
                """reg add "HKLM\Software\Policies\Microsoft\Windows\GameDVr" /v AllowGameDVR /t REG_DWORD /d 0 /f""",
                "sc stop GameInputSvc",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\GameInputSvc" /v Start /t REG_DWORD /d 4 /f""",
                """schtasks /change /tn "\Microsoft\Windows\GameInput\GameInput Service Start" /disable""",
                """schtasks /change /tn "\Microsoft\Windows\GameInput\GameInput Rediscovery" /disable""",
                """schtasks /change /tn "\Microsoft\Windows\GameDVR\StartDVR" /disable""",
                """reg add "HKCU\Software\AMD\Cn" /v EnableMetricsService /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVr" /v AppCaptureEnabled /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVr" /v AudioCaptureEnabled /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVr" /v CursorCaptureEnabled /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Microsoft\GameBar" /v UseNexusForGameBarEnabled /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\Software\Microsoft\GameBar" /v ShowStartupPanel /t REG_DWORD /d 1 /f""",
                """reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\Software\Policies\Microsoft\Windows\GameDVr" /v AllowGameDVR /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Services\GameInputSvc" /v Start /t REG_DWORD /d 3 /f""",
                """schtasks /change /tn "\Microsoft\Windows\GameInput\GameInput Service Start" /enable""",
                """schtasks /change /tn "\Microsoft\Windows\GameInput\GameInput Rediscovery" /enable""",
                """schtasks /change /tn "\Microsoft\Windows\GameDVR\StartDVR" /enable""",
                """reg delete "HKCU\Software\AMD\Cn" /v EnableMetricsService /f""",
                """reg delete "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v OverlayTestMode /f""",
            ]),

        Opt("usb-power-saving",
            "Disable USB selective suspend",
            "USB root hubs stop powering down — fixes disconnecting peripherals, at a " +
            "small battery cost on laptops.",
            "Power", true,
            [
                $"powershell -NoProfile -Command \"{UsbPowerDisableScript}\"",
                "powercfg /SETACVALUEINDEX SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0",
                "powercfg /SETDCVALUEINDEX SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0",
                "powercfg /S SCHEME_CURRENT",
            ],
            [
                $"powershell -NoProfile -Command \"{UsbPowerEnableScript}\"",
                "powercfg /SETACVALUEINDEX SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 1",
                "powercfg /SETDCVALUEINDEX SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 1",
                "powercfg /S SCHEME_CURRENT",
            ]),

        Opt("power-throttling",
            "Disable power throttling",
            "Stops Windows throttling background app CPU — better sustained performance, " +
            "worse battery life.",
            "Power", true,
            [
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v PowerThrottlingOff /t REG_DWORD /d 1 /f""",
                """reg add "HKLM\SYSTEM\CurrentControlSet\Control\USB\AutomaticSurpriseRemoval" /v AttemptRecoveryFromUsbPowerDrain /t REG_DWORD /d 0 /f""",
            ],
            [
                """reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v PowerThrottlingOff /f""",
                """reg delete "HKLM\SYSTEM\CurrentControlSet\Control\USB\AutomaticSurpriseRemoval" /v AttemptRecoveryFromUsbPowerDrain /f""",
            ]),

        Opt("gpu-driver-tweaks",
            "Apply GPU driver power tweaks",
            "Disables AMD ULPS / dynamic p-state / clock gating, NVIDIA dynamic p-states " +
            "and Intel async flips per detected GPU — lower latency, higher idle draw. " +
            "Registry values are deleted on revert.",
            "Gaming", true,
            [
                $"powershell -NoProfile -Command \"{GpuTweaksScript}\"",
            ],
            [
                $"powershell -NoProfile -Command \"{GpuRevertScript}\"",
            ]),

        Opt("hibernation",
            "Disable hibernation and Modern Standby",
            "Turns off hibernation (deletes hiberfil.sys, frees its disk space) and " +
            "Modern Standby S0 idle. SECURITY COST: no hibernation for BitLocker key hygiene.",
            "Power", true,
            [
                "powercfg -h off",
                """reg add "HKLM\System\CurrentControlSet\Control\Power" /v PlatformAoAcOverride /t REG_DWORD /d 0 /f""",
            ],
            [
                "powercfg -h on",
                """reg delete "HKLM\System\CurrentControlSet\Control\Power" /v PlatformAoAcOverride /f""",
            ]),
    ];

    private static TuningOption Opt(
        string id, string title, string description, string category, bool requiresElevation,
        string[] apply, string[] revert) =>
        new(id, title, description, category, requiresElevation, apply, revert);
}
