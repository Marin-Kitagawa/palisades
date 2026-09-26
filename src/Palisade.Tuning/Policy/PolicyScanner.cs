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

using Palisade.Tuning.Catalog;
using Microsoft.Win32;

namespace Palisade.Tuning.Policy;

/// <summary>
/// Detects and reverts Local Group Policy changes (gpedit.msc), operating
/// only on the known policy-backed registry paths of the catalog. Behavior,
/// heuristics and return values follow RyTuneX's PolicyHelper.
/// </summary>
public static class PolicyScanner
{
    private static int GetWindowsBuildNumber()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            if (key?.GetValue("CurrentBuildNumber") is string buildStr && int.TryParse(buildStr, out var build))
            {
                return build;
            }
        }
        catch
        {
            // Ignore errors
        }
        return 0;
    }

    /// <summary>All known policies applicable to the current Windows version.</summary>
    public static IReadOnlyList<PolicyEntry> GetApplicablePolicies()
    {
        var currentBuild = GetWindowsBuildNumber();
        return PolicyCatalog.KnownPolicies
            .Where(p => (p.MinWindowsBuild == 0 || currentBuild >= p.MinWindowsBuild) &&
                        (p.MaxWindowsBuild == 0 || currentBuild <= p.MaxWindowsBuild))
            .ToList();
    }

    /// <summary>Detects the current state of all known policies.</summary>
    public static async Task<IReadOnlyList<PolicyState>> DetectPolicyStatesAsync(
        CancellationToken cancellationToken = default)
    {
        return await Task.Run(() =>
        {
            var results = new List<PolicyState>();
            foreach (var policy in GetApplicablePolicies())
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                results.Add(DetectPolicyState(policy));
            }
            return (IReadOnlyList<PolicyState>)results.AsReadOnly();
        }, cancellationToken).ConfigureAwait(false);
    }

    private static PolicyState DetectPolicyState(PolicyEntry policy)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(policy.Hive,
                Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default);
            using var subKey = baseKey.OpenSubKey(policy.RegistryPath, writable: false);

            if (subKey == null)
            {
                return new PolicyState { Policy = policy, IsConfigured = false, CurrentValue = null, ActualValueKind = null };
            }

            var value = subKey.GetValue(policy.ValueName);
            if (value == null)
            {
                return new PolicyState { Policy = policy, IsConfigured = false, CurrentValue = null, ActualValueKind = null };
            }

            var actualKind = subKey.GetValueKind(policy.ValueName);
            return new PolicyState { Policy = policy, IsConfigured = true, CurrentValue = value, ActualValueKind = actualKind };
        }
        catch
        {
            return new PolicyState { Policy = policy, IsConfigured = false, CurrentValue = null, ActualValueKind = null };
        }
    }

    /// <summary>
    /// Removes a policy override by deleting its registry value, returning the
    /// policy to "Not Configured" state. Empty parent keys under Policies are
    /// cleaned up, keys with other values are left alone.
    /// </summary>
    public static async Task<bool> RemovePolicyOverrideAsync(PolicyEntry policy)
    {
        return await Task.Run(() =>
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(policy.Hive,
                    Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default);
                using var subKey = baseKey.OpenSubKey(policy.RegistryPath, writable: true);

                if (subKey == null)
                {
                    return true;
                }

                if (subKey.GetValue(policy.ValueName) != null)
                {
                    subKey.DeleteValue(policy.ValueName, throwOnMissingValue: false);
                }

                CleanupEmptyPolicyKey(policy.Hive, policy.RegistryPath);
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
            catch
            {
                return false;
            }
        }).ConfigureAwait(false);
    }

    /// <summary>Removes multiple policy overrides, reporting per-policy success.</summary>
    public static async Task<(int succeeded, int failed)> RemovePolicyOverridesAsync(
        IEnumerable<PolicyEntry> policies,
        IProgress<(string policyId, bool success)>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var succeeded = 0;
        var failed = 0;

        foreach (var policy in policies)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                break;
            }

            var success = await RemovePolicyOverrideAsync(policy).ConfigureAwait(false);
            if (success)
            {
                succeeded++;
            }
            else
            {
                failed++;
            }

            progress?.Report((policy.Id, success));
        }

        return (succeeded, failed);
    }

    private static void CleanupEmptyPolicyKey(RegistryHive hive, string path)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive,
                Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default);
            using var subKey = baseKey.OpenSubKey(path, writable: false);

            if (subKey == null)
            {
                return;
            }

            if (subKey.GetValueNames().Length == 0 && subKey.GetSubKeyNames().Length == 0)
            {
                var parentPath = GetParentPath(path);
                if (!string.IsNullOrEmpty(parentPath) && parentPath.Contains("Policies", StringComparison.OrdinalIgnoreCase))
                {
                    using var parentKey = baseKey.OpenSubKey(parentPath, writable: true);
                    var keyName = Path.GetFileName(path);
                    parentKey?.DeleteSubKey(keyName, throwOnMissingSubKey: false);
                }
            }
        }
        catch
        {
            // Ignore cleanup errors - not critical
        }
    }

    private static string GetParentPath(string path)
    {
        var lastSeparator = path.LastIndexOf('\\');
        return lastSeparator > 0 ? path[..lastSeparator] : string.Empty;
    }

    public static async Task<IReadOnlyList<PolicyState>> GetConfiguredPoliciesAsync(
        CancellationToken cancellationToken = default)
    {
        var allStates = await DetectPolicyStatesAsync(cancellationToken).ConfigureAwait(false);
        return allStates.Where(s => s.IsConfigured).ToList();
    }

    public static async Task<IReadOnlyDictionary<string, (int total, int configured)>> GetPolicySummaryAsync(
        CancellationToken cancellationToken = default)
    {
        var allStates = await DetectPolicyStatesAsync(cancellationToken).ConfigureAwait(false);
        return allStates
            .GroupBy(s => s.Policy.Category)
            .ToDictionary(
                g => g.Key,
                g => (total: g.Count(), configured: g.Count(s => s.IsConfigured)));
    }
}
