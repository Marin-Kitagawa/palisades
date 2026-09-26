// Palisade
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

using System.Collections.Concurrent;
using Avalonia;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using Palisade.Core;
using Palisade.Core.Engine;
using Palisade.Core.Models;
using Palisade.Core.Registry;

namespace Palisade.App.ViewModels;

/// <summary>
/// Theme-aware brushes: resolves from the active variant's theme dictionary,
/// so dark mode needs no code changes at the call sites.
/// </summary>
public static class ThemePalette
{
    private static IBrush Get(string key)
    {
        if (Application.Current is { } app
            && app.Resources.TryGetResource(key, app.ActualThemeVariant, out var value)
            && value is IBrush brush)
        {
            return brush;
        }
        return Brushes.Gray;
    }

    public static IBrush Success => Get("SuccessBrush");
    public static IBrush Warning => Get("WarningBrush");
    public static IBrush Error => Get("ErrorBrush");
    public static IBrush Neutral => Get("TextSecondaryBrush");
    public static IBrush SuccessSoft => Get("SuccessSoftBrush");
    public static IBrush WarningSoft => Get("WarningSoftBrush");
    public static IBrush ErrorSoft => Get("ErrorSoftBrush");
    public static IBrush NeutralSoft => Get("LayerAltBrush");

    public static (IBrush Brush, IBrush Soft) ForState(MeasureState state) => state switch
    {
        MeasureState.Taut => (Success, SuccessSoft),
        MeasureState.Slack => (Neutral, NeutralSoft),
        MeasureState.Stressed => (Error, ErrorSoft),
        MeasureState.Unavailable => (Warning, WarningSoft),
        _ => (Neutral, NeutralSoft),
    };
}

/// <summary>
/// The engine surface the UI binds to. Mirrors the frozen
/// <see cref="PalisadeEngine"/> facade; the adapter is the only thing that
/// knows the concrete class, so a headless test harness can supply the real
/// one over an in-memory hive.
/// </summary>
public interface IHardeningEngine
{
    IReadOnlyList<MeasureDescriptor> Catalog { get; }

    IReadOnlyList<DetectionResult> Detect();

    ApplyReport Apply(IReadOnlyCollection<MeasureId> ids);

    ApplyReport RestoreAll();

    ApplyReport ReapplyDefaults();
}

public sealed class PalisadeEngineAdapter : IHardeningEngine
{
    private readonly PalisadeEngine _engine;

    public PalisadeEngineAdapter(PalisadeEngine engine) => _engine = engine;

    public IReadOnlyList<MeasureDescriptor> Catalog => _engine.Catalog;

    public IReadOnlyList<DetectionResult> Detect() => _engine.Detect();

    public ApplyReport Apply(IReadOnlyCollection<MeasureId> ids) => _engine.Apply(ids);

    public ApplyReport RestoreAll() => _engine.RestoreAll();

    public ApplyReport ReapplyDefaults() => _engine.ReapplyDefaults();
}

/// <summary>
/// The single composition root of the application. Later plans construct
/// <see cref="PalisadeEngine"/> and nothing else; this is where.
/// </summary>
public static class CompositionRoot
{
    public static bool IsElevated { get; } = DetectElevation();

    public static IHardeningEngine BuildEngine()
    {
        var logDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Palisade", "logs");
        Directory.CreateDirectory(logDirectory);

        var registry = new RegistryAccess();
        var engine = new PalisadeEngine(registry, RegistryOptions.Default, new AppPaths(logDirectory), () => IsElevated);
        return new PalisadeEngineAdapter(engine);
    }

    private static bool DetectElevation()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(identity)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch (Exception)
        {
            return false;
        }
    }
}

/// <summary>
/// Reads the recorded originals out of the saved-state key — read-only — so
/// every rod can print the recorded original next to the current value.
/// This is what makes the reversibility promise visible.
/// </summary>
public static class SavedStateReader
{
    public sealed record Entry(RegistryRoot Root, string KeyPath, string ValueName, string OriginalDisplay);

    private static readonly ConcurrentDictionary<string, IReadOnlyList<Entry>> Cache = new(StringComparer.Ordinal);

    public static IReadOnlyList<Entry> ReadAll()
    {
        return Cache.GetOrAdd("entries", _ => ReadAllCore());
    }

    private static IReadOnlyList<Entry> ReadAllCore()
    {
        try
        {
            var registry = new RegistryAccess();
            using var key = registry.OpenKey(
                RegistryRoot.CurrentUser, RegistryOptions.DefaultSavedStateKeyPath, writable: false);
            if (key is null)
            {
                return [];
            }

            var entries = new List<Entry>();
            foreach (var name in key.GetValueNames())
            {
                if (RegistryKeyNames.TryParse(name, out var kind, out var root, out var keyPath, out var valueName, out var warning))
                {
                    if (warning is not null)
                    {
                        continue; // Reported by the engine on restore; not displayable here.
                    }

                    entries.Add(new Entry(root, keyPath, valueName, Describe(kind, key, name)));
                }
                else if (RegistryKeyNames.TryParseNonReg(name, out var feature))
                {
                    var state = key.TryGetString(name, out var stored) ? stored : "";
                    entries.Add(new Entry(
                        RegistryRoot.CurrentUser, "(non-registry feature)", feature.Value,
                        state.Length == 0 ? "recorded" : state));
                }
            }

            return entries;
        }
        catch (Exception)
        {
            // A registry that will not open is normal on a fresh account;
            // the rod prints "no recorded original" and nothing else changes.
            return [];
        }
    }

    private static string Describe(SavedStateKind kind, IRegistryKey key, string name)
    {
        return kind switch
        {
            SavedStateKind.Dword => key.TryGetDword(name, out var value) ? value.ToString() : "recorded",
            SavedStateKind.String => key.TryGetString(name, out var value) ? value : "recorded",
            SavedStateKind.NotExisting => "did not exist",
            _ => "recorded",
        };
    }
}

/// <summary>
/// One rod: a measure, its state, its cost, its recorded original.
/// </summary>
public partial class RodViewModel : ObservableObject
{
    public RodViewModel(MeasureDescriptor descriptor, int index)
    {
        Descriptor = descriptor;
        Index = index;
        Id = descriptor.Id.Value;
        Name = descriptor.Name;
        LongName = descriptor.LongName;
        Consequence = descriptor.Consequence;
        GroupName = descriptor.Group switch
        {
            MeasureGroup.Windows => "Windows",
            MeasureGroup.MicrosoftOffice => "Microsoft Office",
            MeasureGroup.Adobe => "Adobe Reader",
            MeasureGroup.LibreOffice => "LibreOffice",
            MeasureGroup.OneNote => "OneNote",
            MeasureGroup.System => "System",
            _ => descriptor.Group.ToString(),
        };
        RequiresElevation = descriptor.RequiresElevation;
        IsDefault = descriptor.HardenByDefault;
        IsCheckedForApply = descriptor.HardenByDefault;
        IsEditable = true;
        Targets = [.. descriptor.Targets];
    }

    public MeasureDescriptor Descriptor { get; }

    public int Index { get; }

    public string Id { get; }

    public string Name { get; }

    public string LongName { get; }

    public string Consequence { get; }

    public string GroupName { get; }

    public bool RequiresElevation { get; }

    public bool IsDefault { get; }

    public IReadOnlyList<MeasureTarget> Targets { get; }

    [ObservableProperty]
    private MeasureState _state = MeasureState.Slack;

    [ObservableProperty]
    private string _stateWord = "reading…";

    [ObservableProperty]
    private Avalonia.Media.IBrush _stateBrush = Avalonia.Media.Brushes.Gray;

    [ObservableProperty]
    private Avalonia.Media.IBrush _stateSoftBrush = Avalonia.Media.Brushes.Transparent;

    [ObservableProperty]
    private string? _unavailableReason;

    [ObservableProperty]
    private bool _isSelected;

    [ObservableProperty]
    private bool _isEditable;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Checkable))]
    private bool _isCheckedForApply;

    public bool Checkable => IsEditable && State != MeasureState.Unavailable;

    [ObservableProperty]
    private string _recordedOriginal = "no recorded original";

    partial void OnStateChanged(MeasureState value) => ApplyStateVisuals(value);

    partial void OnIsEditableChanged(bool value) => OnPropertyChanged(nameof(Checkable));

    public void Update(DetectionResult result)
    {
        State = result.State;
        ApplyStateVisuals(result.State);
        UnavailableReason = result.Unavailable?.Reason;
        if (result.State == MeasureState.Unavailable)
        {
            IsCheckedForApply = false;
        }
        RecordedOriginal = BuildRecordedOriginal();
    }



    private static string WordFor(MeasureState state) => state switch
    {
        MeasureState.Taut => "hardened",
        MeasureState.Slack => "not applied",
        MeasureState.Stressed => "changed externally",
        MeasureState.Unavailable => "needs administrator",
        _ => state.ToString(),
    };

    /// <summary>Re-applies the state visuals; also invoked on theme change.</summary>
    public void ApplyStateVisuals(MeasureState state)
    {
        StateWord = WordFor(state);
        (StateBrush, StateSoftBrush) = ThemePalette.ForState(state);
    }

    /// <summary>
    /// The recorded original for this measure's first target, as read from
    /// the saved-state key — or the honest absence of one.
    /// </summary>
    private string BuildRecordedOriginal()
    {
        var entries = SavedStateReader.ReadAll();
        var first = Targets.FirstOrDefault();
        if (first is null)
        {
            return "no recorded original";
        }

        foreach (var entry in entries)
        {
            if (entry.Root == first.Root
                && string.Equals(entry.KeyPath, ExpandPath(first.Path), StringComparison.OrdinalIgnoreCase)
                && string.Equals(entry.ValueName, first.ValueName, StringComparison.OrdinalIgnoreCase))
            {
                return $"recorded original: {entry.OriginalDisplay}";
            }
        }

        return "no recorded original";
    }

    private static string ExpandPath(string path) => path;

    public string TargetsSummary
    {
        get
        {
            if (Targets.Count == 0)
            {
                return "applies outside the registry";
            }

            var first = Targets[0];
            var summary = $"{RootToken(first.Root)}\\{first.Path} · {first.ValueName} → " +
                (first.HardenedValue.Length == 0 ? "(empty)" : first.HardenedValue);
            if (Targets.Count > 1)
            {
                summary += $"  +{Targets.Count - 1} more";
            }

            return summary;
        }
    }

    public string ConstraintSummary
    {
        get
        {
            var own = Descriptor.ConstrainedBy
                .Select(c => $"this rod is pulled by {c.Target.Value}: {c.Reason}");
            var others = MeasureCatalog.All
                .Where(m => m.ConstrainedBy.Any(c => c.Target == Descriptor.Id))
                .Select(m => $"this rod pulls {m.Id.Value}: {m.ConstrainedBy.First(c => c.Target == Descriptor.Id).Reason}");
            var lines = own.Concat(others).ToList();
            return lines.Count == 0 ? "no declared constraints" : string.Join("\n", lines);
        }
    }

    private static string RootToken(RegistryRoot root) => root switch
    {
        RegistryRoot.ClassesRoot => "HKCR",
        RegistryRoot.CurrentUser => "HKCU",
        RegistryRoot.LocalMachine => "HKLM",
        RegistryRoot.Users => "HKU",
        RegistryRoot.CurrentConfig => "HKCC",
        RegistryRoot.PerformanceData => "HKPD",
        _ => root.ToString(),
    };
}

public sealed class RodGroupViewModel
{
    public RodGroupViewModel(string name, IReadOnlyList<RodViewModel> rods)
    {
        Name = name;
        Rods = rods;
    }

    public string Name { get; }

    public IReadOnlyList<RodViewModel> Rods { get; }
}

/// <summary>
/// The full-page confirmation before any write. This surface needs protected
/// focus, so it takes the whole page: every measure that will change, with
/// its cost in the user's own applications, named.
/// </summary>
public partial class ConfirmationViewModel : ObservableObject
{
    [ObservableProperty]
    private bool _isVisible;

    [ObservableProperty]
    private string _title = "";

    [ObservableProperty]
    private string _preamble = "";

    [ObservableProperty]
    private string _confirmLabel = "Apply now";

    public IReadOnlyList<MeasureId> MeasureIds { get; private set; } = [];

    public IReadOnlyList<ConfirmRow> Rows { get; private set; } = [];

    public void Open(
        string operation,
        IEnumerable<MeasureDescriptor> measures,
        string confirmLabel,
        string? preamble = null)
    {
        var list = measures.ToList();
        Title = $"Confirm — {operation} on this account";
        Preamble = preamble
            ?? "These changes are recorded so they can be reverted exactly. A restart is needed for the full effect of several measures. " +
               "Palisade is not an antivirus: it reduces the attack surface, it does not remove malware.";
        ConfirmLabel = confirmLabel;
        MeasureIds = [.. list.Select(m => m.Id)];
        Rows = [.. list.Select(m => new ConfirmRow(m.LongName, m.Consequence, m.RequiresElevation))];
        IsVisible = true;
    }

    public void OpenRestore(IEnumerable<MeasureDescriptor> measures, string preamble)
    {
        var list = measures.ToList();
        Title = "Confirm — restore this account";
        Preamble = preamble;
        ConfirmLabel = "Restore everything";
        MeasureIds = [.. list.Select(m => m.Id)];
        Rows = [.. list.Select(m => new ConfirmRow(m.LongName, m.Consequence, m.RequiresElevation))];
        IsVisible = true;
    }

    public void Dismiss() => IsVisible = false;

    public sealed record ConfirmRow(string Name, string Consequence, bool RequiresElevation);
}

/// <summary>
/// The receipt: what actually happened, per measure, with warnings that were
/// raised rather than swallowed. The user keeps the receipt.
/// </summary>
public partial class ReceiptViewModel : ObservableObject
{
    [ObservableProperty]
    private bool _isVisible;

    [ObservableProperty]
    private string _title = "";

    [ObservableProperty]
    private bool _requiresRestart;

    public IReadOnlyList<ResultRow> Rows { get; private set; } = [];

    public IReadOnlyList<string> Warnings { get; private set; } = [];

    public void Open(ApplyReport report, string title)
    {
        Title = title;
        RequiresRestart = report.RequiresRestart;
        Rows = [.. report.Results.Select(r => new ResultRow(
            r.Id.Value,
            r.Outcome switch
            {
                ApplyOutcome.Applied => "applied",
                ApplyOutcome.AlreadyApplied => "already hardened",
                ApplyOutcome.Restored => "restored",
                ApplyOutcome.NotRestored => "nothing recorded",
                ApplyOutcome.Unavailable => "unavailable",
                ApplyOutcome.Failed => "failed",
                _ => r.Outcome.ToString(),
            },
            r.Detail,
            r.Outcome switch
            {
                ApplyOutcome.Applied or ApplyOutcome.AlreadyApplied => MeasureState.Taut,
                ApplyOutcome.Restored => MeasureState.Slack,
                ApplyOutcome.Failed => MeasureState.Stressed,
                _ => MeasureState.Unavailable,
            }))];
        Warnings = report.Warnings;
        IsVisible = true;
    }

    public void Dismiss() => IsVisible = false;

    public sealed record ResultRow(string Id, string OutcomeWord, string? Detail, MeasureState Glyph);
}
