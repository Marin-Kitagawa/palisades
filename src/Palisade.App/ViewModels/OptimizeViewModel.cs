// Palisade Tuning UI — view models for the Optimize surface.
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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Palisade.Tuning;
using Palisade.Tuning.Models;
using Palisade.Tuning.Runtime;

namespace Palisade.App.ViewModels;

public partial class OptimizeViewModel : ObservableObject
{
    public OptimizeViewModel()
    {
        AllToggles = [.. TuningCatalog.All
            .Select(o => new TuningToggleViewModel(o))
            .OrderBy(t => t.Category, StringComparer.OrdinalIgnoreCase)
            .ThenBy(t => t.Title, StringComparer.OrdinalIgnoreCase)];

        ApplyFilter("");

        ToggleCommand = new AsyncRelayCommand<TuningToggleViewModel>(ToggleAsync, _ => !IsBusy);
        RevertAllCommand = new AsyncRelayCommand(RevertAllAsync, () => !IsBusy && AppliedCount > 0);
    }

    private IReadOnlyList<TuningToggleViewModel> AllToggles { get; }

    public ObservableCollection<TuningToggleViewModel> Toggles { get; } = [];

    public ObservableCollection<ToggleGroupViewModel> Groups { get; } = [];

    public IAsyncRelayCommand ToggleCommand { get; }

    public IAsyncRelayCommand RevertAllCommand { get; }

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RevertAllCommand))]
    private bool _isBusy;

    [ObservableProperty]
    private string _searchText = "";

    [ObservableProperty]
    private string _statusLine = "";

    public int AppliedCount => AllToggles.Count(t => t.IsApplied);

    partial void OnSearchTextChanged(string value) => ApplyFilter(value);

    private void ApplyFilter(string search)
    {
        Toggles.Clear();
        foreach (var toggle in AllToggles)
        {
            if (search.Length == 0
                || toggle.Title.Contains(search, StringComparison.OrdinalIgnoreCase)
                || toggle.Description.Contains(search, StringComparison.OrdinalIgnoreCase)
                || toggle.Category.Contains(search, StringComparison.OrdinalIgnoreCase))
            {
                Toggles.Add(toggle);
            }
        }

        Groups.Clear();
        foreach (var group in Toggles.GroupBy(t => t.Category).OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase))
        {
            Groups.Add(new ToggleGroupViewModel(group.Key, [.. group]));
        }
    }

    private async Task ToggleAsync(TuningToggleViewModel? toggle)
    {
        if (toggle is null)
        {
            return;
        }

        IsBusy = true;
        try
        {
            if (toggle.IsApplied)
            {
                var result = await TuningEngine.RevertAsync(toggle.Id);
                toggle.IsApplied = !result.Ok ? toggle.IsApplied : false;
                StatusLine = result.Ok
                    ? $"Reverted: {toggle.Title}"
                    : $"Revert reported {result.FailedCommands} failing command(s) — see the log";
            }
            else
            {
                var result = await TuningEngine.ApplyAsync(toggle.Id);
                toggle.IsApplied = result.Ok;
                StatusLine = result.Ok
                    ? $"Applied: {toggle.Title}"
                    : $"Apply reported {result.FailedCommands} failing command(s) — see the log";
            }
            OnPropertyChanged(nameof(AppliedCount));
            RevertAllCommand.NotifyCanExecuteChanged();
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task RevertAllAsync()
    {
        IsBusy = true;
        try
        {
            foreach (var toggle in AllToggles.Where(t => t.IsApplied))
            {
                var result = await TuningEngine.RevertAsync(toggle.Id);
                if (result.Ok)
                {
                    toggle.IsApplied = false;
                }
            }
            OnPropertyChanged(nameof(AppliedCount));
            StatusLine = "All applied tuning options reverted.";
            RevertAllCommand.NotifyCanExecuteChanged();
        }
        finally
        {
            IsBusy = false;
        }
    }
}

public partial class TuningToggleViewModel : ObservableObject
{
    public TuningToggleViewModel(TuningOption option)
    {
        Option = option;
        Id = option.Id;
        Title = option.Title;
        Description = option.Description;
        Category = option.Category;
        RequiresElevation = option.RequiresElevation;
        _isApplied = TuningStateStore.IsApplied(option.Id);
    }

    public TuningOption Option { get; }

    public string Id { get; }

    public string Title { get; }

    public string Description { get; }

    public string Category { get; }

    public bool RequiresElevation { get; }

    [ObservableProperty]
    private bool _isApplied;
}

public sealed class ToggleGroupViewModel(string name, IReadOnlyList<TuningToggleViewModel> toggles)
{
    public string Name { get; } = name;

    public IReadOnlyList<TuningToggleViewModel> Toggles { get; } = toggles;
}
