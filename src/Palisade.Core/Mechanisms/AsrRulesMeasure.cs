// Hardentools
// Copyright (C) 2017-2023 Security Without Borders
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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

using System.Text;
using Palisade.Core.Models;
using Palisade.Core.Registry;

namespace Palisade.Core.Mechanisms;

/// <summary>
/// The Windows ASR (Attack Surface Reduction) rules measure. The rule set is transcribed
/// verbatim from <c>windows_asr.go:29-46</c>, including the omission of the prevalence rule
/// upstream leaves out because it would block the tool itself.
/// </summary>
/// <remarks>
/// Registry-only shape, recorded as a deliberate divergence: upstream applies the rules with
/// the <c>Add-MpPreference</c> PowerShell cmdlet and has no saved state at all
/// (<c>windows_asr.go:102</c> is a TODO). Palisade writes the same rules into the Defender
/// policy that <c>Add-MpPreference</c> maintains —
/// <c>HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit
/// Guard\ASR\Rules</c>, one <c>REG_DWORD</c> per rule GUID — and records the complete
/// original set, including which rules were absent, as the measure's non-registry saved
/// state. That is defect #3's fix: restore reinstates exactly what was recorded, deleting
/// rules that were absent before.
/// </remarks>
public sealed class AsrRulesMeasure(IRegistryKeyFactory registry) : INonRegistryMeasure
{
    public const string MeasureIdValue = "WindowsAsrRules";

    private static readonly string[] RuleIds =
    [
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", // Block executable content from email client and webmail.
        "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", // Block Office applications from creating child processes.
        "3B576869-A4EC-4529-8536-B80A7769E899", // Block Office applications from creating executable content.
        "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84", // Block Office applications from injecting code into other processes.
        "D3E037E1-3EB8-44C8-A917-57927947596D", // Block JavaScript or VBScript from launching downloaded executable content.
        "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", // Block execution of potentially obfuscated scripts.
        "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B", // Block Win32 API calls from Office macro.
        // "01443614-CD74-433A-B99E-2ECDC07BFC25" is deliberately absent, as upstream: it
        // would block Palisade itself and other tools Microsoft does not know.
        "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4", // Block untrusted and unsigned processes that run from USB.
        "C1DB55AB-C21A-4637-BB3F-A12568109D35", // Use advanced protection against ransomware.
        "D1E49AAC-8F56-4280-B9BA-993A6D77406C", // Block process creations originating from PSExec and WMI commands.
        "26190899-1602-49e8-8b27-eb1d0a1ce869", // Block Office communication application from creating child processes.
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", // Block Adobe Reader from creating child processes.
        "e6db77e5-3df2-4cf1-b95a-636979351e5b", // Block persistence through WMI event subscription.
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", // Block credential stealing from the Windows local security authority subsystem.
    ];

    private const string DefenderPolicyPath = @"SOFTWARE\Policies\Microsoft\Windows Defender";
    private const string DefenderPresencePath = @"SOFTWARE\Microsoft\Windows Defender";
    private const string AsrRulesPath = DefenderPolicyPath + @"\Windows Defender Exploit Guard\ASR\Rules";
    private const string AbsentMarker = "absent";
    private const char RecordSeparator = ';';
    private const char FieldSeparator = '=';

    public MeasureId Id => new(MeasureIdValue);

    public IReadOnlyList<AvailabilityRule> Availability { get; } =
    [
        new(
            "windows_defender_disabled",
            new Dictionary<string, string>(),
            "Windows Defender is not running on this machine, so this setting cannot be applied."),
    ];

    public bool IsAvailable()
    {
        using (var policy = registry.OpenKey(RegistryRoot.LocalMachine, DefenderPolicyPath, writable: false))
        {
            if (policy is not null && policy.TryGetDword("DisableAntiSpyware", out var disabled) && disabled == 1)
            {
                return false;
            }
        }

        // No Defender presence and no policy either: nothing on this machine can enforce the
        // rules, so the measure is unavailable rather than silently ineffective.
        using var presence = registry.OpenKey(RegistryRoot.LocalMachine, DefenderPresencePath, writable: false);
        return presence is not null;
    }

    public MeasureState Detect(SavedStateStore store)
    {
        var savedExists = store.TryGetNonReg(Id, out _);
        var current = ReadCurrentRules();
        var hardenedCount = RuleIds.Count(ruleId => current.TryGetValue(ruleId, out var action) && action == 1);

        if (hardenedCount == RuleIds.Length)
        {
            // Every rule is enabled: taut when Palisade recorded putting them there,
            // stressed when something else did.
            return savedExists ? MeasureState.Taut : MeasureState.Stressed;
        }

        if (hardenedCount == 0)
        {
            return MeasureState.Slack;
        }

        return savedExists ? MeasureState.Stressed : MeasureState.Slack;
    }

    public void Apply(SavedStateStore store)
    {
        var current = ReadCurrentRules();
        store.SaveNonReg(Id, RecordState(current));

        // Harden: every rule in the set, enabled.
        using var rules = registry.OpenKey(RegistryRoot.LocalMachine, AsrRulesPath, writable: true)
            ?? throw new InvalidOperationException($"The key 'LOCAL_MACHINE\\{AsrRulesPath}' could not be created or opened for writing.");
        foreach (var ruleId in RuleIds)
        {
            rules.SetDword(ruleId, 1);
        }
    }

    public void Restore(SavedStateStore store)
    {
        if (!store.TryGetNonReg(Id, out var record))
        {
            return;
        }

        using (var probe = registry.OpenKey(RegistryRoot.LocalMachine, AsrRulesPath, writable: false))
        {
            if (probe is not null)
            {
                using var rules = registry.OpenKey(RegistryRoot.LocalMachine, AsrRulesPath, writable: true)!;
                foreach (var (ruleId, action) in ParseState(record))
                {
                    if (action is null)
                    {
                        rules.DeleteValue(ruleId); // Was absent before hardening; remove it again.
                    }
                    else
                    {
                        rules.SetDword(ruleId, action.Value);
                    }
                }
            }
        }

        store.DeleteNonReg(Id);
    }

    /// <summary>Every value currently under the ASR rules key, keyed by rule GUID.</summary>
    private Dictionary<string, uint> ReadCurrentRules()
    {
        var current = new Dictionary<string, uint>(StringComparer.OrdinalIgnoreCase);
        using var rules = registry.OpenKey(RegistryRoot.LocalMachine, AsrRulesPath, writable: false);
        if (rules is null)
        {
            return current;
        }

        foreach (var name in rules.GetValueNames())
        {
            if (rules.TryGetDword(name, out var action))
            {
                current[name] = action;
            }
        }

        return current;
    }

    /// <summary>
    /// The complete original set: every rule of the set with its action, or the absent marker
    /// for one that was not set — plus any foreign rule present under the key, so restore can
    /// put the whole key back exactly as it was.
    /// </summary>
    private string RecordState(Dictionary<string, uint> current)
    {
        var builder = new StringBuilder();
        foreach (var ruleId in RuleIds)
        {
            AppendRule(builder, ruleId, current.TryGetValue(ruleId, out var action) ? action : null);
        }

        foreach (var (ruleId, action) in current)
        {
            if (!RuleIds.Contains(ruleId, StringComparer.OrdinalIgnoreCase))
            {
                AppendRule(builder, ruleId, action);
            }
        }

        return builder.ToString();
    }

    private static void AppendRule(StringBuilder builder, string ruleId, uint? action)
    {
        if (builder.Length > 0)
        {
            builder.Append(RecordSeparator);
        }

        builder.Append(ruleId).Append(FieldSeparator).Append(action is null ? AbsentMarker : action.Value.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    private static List<(string RuleId, uint? Action)> ParseState(string record)
    {
        var parsed = new List<(string, uint?)>();
        foreach (var part in record.Split(RecordSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var separator = part.IndexOf(FieldSeparator);
            if (separator <= 0)
            {
                continue; // A malformed record segment is skipped, never guessed at.
            }

            var ruleId = part[..separator];
            var rawAction = part[(separator + 1)..];
            if (rawAction == AbsentMarker)
            {
                parsed.Add((ruleId, null));
            }
            else if (uint.TryParse(rawAction, System.Globalization.CultureInfo.InvariantCulture, out var action))
            {
                parsed.Add((ruleId, action));
            }
        }

        return parsed;
    }
}
