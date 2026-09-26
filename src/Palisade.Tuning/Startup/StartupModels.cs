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

namespace Palisade.Tuning.Startup;

public enum StartupLocationType
{
    HKCU_Run,
    HKCU_RunOnce,
    HKLM_Run,
    HKLM_RunOnce,
    UserStartupFolder,
    CommonStartupFolder,
    ScheduledTask
}

public enum StartupImpact
{
    Low,
    Medium,
    High,
    Broken
}

/// <summary>
/// One startup entry as enumerated from the registry, startup folders,
/// scheduled tasks and UWP startup tasks. A plain record — the UI layer
/// wraps it for binding.
/// </summary>
public sealed record StartupItem
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required string Command { get; init; }
    public required string ExecutablePath { get; init; }
    public string Publisher { get; init; } = "Unknown";
    public string Description { get; init; } = string.Empty;
    public required string Location { get; init; }
    public StartupLocationType LocationType { get; init; }
    public RegistryHive? Hive { get; init; }
    public RegistryView View { get; init; } = RegistryView.Default;
    public string? RegistryPath { get; init; }
    public string? ValueName { get; init; }
    public string? FilePath { get; init; }
    public string? TaskName { get; init; }
    public bool IsValid { get; init; } = true;
    public StartupImpact Impact { get; init; } = StartupImpact.Low;
    public long FileSizeBytes { get; init; }
    public bool IsEnabled { get; set; }

    public string LocationDisplay => LocationType switch
    {
        StartupLocationType.HKCU_Run => "Registry (HKCU)",
        StartupLocationType.HKCU_RunOnce => "Registry (HKCU RunOnce)",
        StartupLocationType.HKLM_Run => "Registry (HKLM)",
        StartupLocationType.HKLM_RunOnce => "Registry (HKLM RunOnce)",
        StartupLocationType.UserStartupFolder => "Startup Folder (User)",
        StartupLocationType.CommonStartupFolder => "Startup Folder (Common)",
        StartupLocationType.ScheduledTask => "Scheduled Task",
        _ => Location,
    };

    public bool IsUserScope => LocationType is StartupLocationType.HKCU_Run
        or StartupLocationType.HKCU_RunOnce
        or StartupLocationType.UserStartupFolder;
}
