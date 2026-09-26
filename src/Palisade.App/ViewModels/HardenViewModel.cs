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

using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Palisade.Core.Engine;
using Palisade.Core.Models;

namespace Palisade.App.ViewModels;

/// <summary>
/// The hardening surface: the 26 rods, the red cord, the blast-radius
/// figure, and the apply / restore / harden-again operations.
///
/// Every state is carried by text and glyph as well as color. Every measure
/// names its cost in the user's own applications. Restore is the product.
/// </summary>
public partial class HardenViewModel : ObservableObject
{
    private readonly IHardeningEngine _engine;
    private IReadOnlyList<DetectionResult> _detection = [];

    public HardenViewModel() : this(CompositionRoot.BuildEngine())
    {
    }

    public HardenViewModel(IHardeningEngine engine)
    {
        _engine = engine;

        Rods = [.. MeasureCatalog.All
            .Select((descriptor, index) => new RodViewModel(descriptor, index))
            .OrderBy(r => r.GroupName)
            .ThenBy(r => r.LongName, StringComparer.OrdinalIgnoreCase)];

        RodGroups = [.. Rods
            .GroupBy(r => r.GroupName)
            .OrderBy(g => g.Min(r => r.Index))
            .Select(g => new RodGroupViewModel(g.Key, [.. g]))];

        SelectedRod = Rods.FirstOrDefault();
        IsElevated = CompositionRoot.IsElevated;
        PrivilegeLine = IsElevated
            ? "administrator — all 26 measures available"
            : "standard account — privileged measures need elevation";
        Confirm = new ConfirmationViewModel();
        Receipt = new ReceiptViewModel();

        foreach (var rod in Rods)
        {
            rod.PropertyChanged += (_, e) =>
            {
                if (e.PropertyName == nameof(RodViewModel.IsCheckedForApply))
                {
                    OnPropertyChanged(nameof(CheckedCount));
                    OnPropertyChanged(nameof(ApplyLine));
                }
            };
        }

        RefreshCommand = new AsyncRelayCommand(RefreshAsync);
        ApplyCommand = new AsyncRelayCommand(ApplyAsync, () => !IsBusy);
        RestoreCommand = new AsyncRelayCommand(RestoreAsync, () => !IsBusy);
        HardenAgainCommand = new AsyncRelayCommand(HardenAgainAsync, () => !IsBusy);
        ConfirmApplyCommand = new AsyncRelayCommand(ConfirmApplyAsync);
        DiscardCommand = new RelayCommand(() => Confirm.Dismiss());
        CloseReceiptCommand = new RelayCommand(() => Receipt.Dismiss());

        _ = RefreshAsync();
    }

    public IReadOnlyList<RodViewModel> Rods { get; }

    public IReadOnlyList<MeasureDescriptor> Catalog => MeasureCatalog.All;

    public IReadOnlyList<RodGroupViewModel> RodGroups { get; }

    public bool IsElevated { get; }

    public string PrivilegeLine { get; }

    public ConfirmationViewModel Confirm { get; }

    public ReceiptViewModel Receipt { get; }

    public IRelayCommand RefreshCommand { get; }

    public IAsyncRelayCommand ApplyCommand { get; }

    public IAsyncRelayCommand RestoreCommand { get; }

    public IAsyncRelayCommand HardenAgainCommand { get; }

    public IAsyncRelayCommand ConfirmApplyCommand { get; }

    public IRelayCommand DiscardCommand { get; }

    public IRelayCommand CloseReceiptCommand { get; }

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ApplyCommand))]
    [NotifyCanExecuteChangedFor(nameof(RestoreCommand))]
    [NotifyCanExecuteChangedFor(nameof(HardenAgainCommand))]
    private bool _isBusy;

    [ObservableProperty]
    private RodViewModel? _selectedRod;

    /// <summary>The selected rod's descriptor, for the blast-radius figure.</summary>
    [ObservableProperty]
    private MeasureDescriptor? _selectedDescriptor;

    [ObservableProperty]
    private bool _isExpertMode;

    [ObservableProperty]
    private string _statusLine = "reading the current state of this account…";

    partial void OnSelectedRodChanged(RodViewModel? value)
    {
        SelectedDescriptor = value?.Descriptor;
        foreach (var rod in Rods)
        {
            rod.IsSelected = rod == value;
        }
    }

    partial void OnIsExpertModeChanged(bool value)
    {
        foreach (var rod in Rods)
        {
            rod.IsEditable = value;
        }
        if (!value)
        {
            // Leaving expert mode returns the selection to the safe default path.
            foreach (var rod in Rods)
            {
                rod.IsCheckedForApply = rod.IsDefault && rod.State != MeasureState.Unavailable;
            }
        }
    }

    public int TautCount => Count(MeasureState.Taut);
    public int SlackCount => Count(MeasureState.Slack);
    public int StressedCount => Count(MeasureState.Stressed);
    public int UnavailableCount => Count(MeasureState.Unavailable);
    public int AvailableCount => Rods.Count(r => r.State != MeasureState.Unavailable);
    public int CheckedCount => Rods.Count(r => r.IsCheckedForApply && r.State != MeasureState.Unavailable);
    public string ApplyLine => $"{CheckedCount} of {AvailableCount} available measures selected";

    [RelayCommand]
    private void SelectRod(RodViewModel rod) => SelectedRod = rod;

    private int Count(MeasureState state) => Rods.Count(r => r.State == state);

    private async Task RefreshAsync()
    {
        IsBusy = true;
        StatusLine = "reading the current state of this account…";
        try
        {
            IReadOnlyList<DetectionResult> detection;
            try
            {
                detection = await Task.Run(_engine.Detect);
            }
            catch (Exception detectError)
            {
                UiLog.Error("detect failed", detectError);
                StatusLine = $"detection failed: {detectError.Message}";
                return;
            }

            _detection = detection;
            var byId = detection.ToDictionary(d => d.Id.Value);
            foreach (var rod in Rods)
            {
                if (byId.TryGetValue(rod.Id, out var result))
                {
                    try
                    {
                        rod.Update(result);
                    }
                    catch (Exception rodError)
                    {
                        UiLog.Error($"rod {rod.Id} update failed", rodError);
                    }
                }
            }
            OnPropertyChanged(nameof(TautCount));
            OnPropertyChanged(nameof(SlackCount));
            OnPropertyChanged(nameof(StressedCount));
            OnPropertyChanged(nameof(UnavailableCount));
            OnPropertyChanged(nameof(AvailableCount));
            OnPropertyChanged(nameof(CheckedCount));
            OnPropertyChanged(nameof(ApplyLine));
            StatusLine = BuildStatusLine();
        }
        finally
        {
            IsBusy = false;
        }
    }

    private string BuildStatusLine()
    {
        if (UnavailableCount == 0)
        {
            return $"{TautCount} hardened · {SlackCount} not applied · {StressedCount} changed externally";
        }
        return $"{TautCount} hardened · {SlackCount} not applied · {StressedCount} changed externally · {UnavailableCount} need administrator";
    }

    private async Task ApplyAsync()
    {
        var ids = Rods
            .Where(r => r.IsCheckedForApply && r.State != MeasureState.Unavailable)
            .Select(r => new MeasureId(r.Id))
            .ToList();
        if (ids.Count == 0)
        {
            return;
        }

        Confirm.Open(
            "apply",
            ids.Select(id => MeasureCatalog.Get(id)),
            confirmLabel: "Apply now");
    }

    private async Task ConfirmApplyAsync()
    {
        var ids = Confirm.MeasureIds
            .Select(id => new MeasureId(id))
            .ToList();
        Confirm.Dismiss();
        if (ids.Count == 0)
        {
            return;
        }

        IsBusy = true;
        StatusLine = "applying…";
        try
        {
            var report = await Task.Run(() => _engine.Apply(ids));
            await RefreshAsync();
            Receipt.Open(report, "Applied");
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task RestoreAsync()
    {
        Confirm.OpenRestore(
            MeasureCatalog.All,
            "Restore returns every measure recorded on this account to its original value, in deterministic order. Nothing else on this machine is touched.");
    }

    private async Task HardenAgainAsync()
    {
        Confirm.Open(
            "harden again",
            MeasureCatalog.All.Where(m => m.HardenByDefault),
            confirmLabel: "Restore, then apply defaults",
            preamble:
                "This first restores every applied measure to its recorded original, then applies the default set from this version. " +
                "Use it when Palisade has been updated, so every measure is fully in effect.");
    }
}
