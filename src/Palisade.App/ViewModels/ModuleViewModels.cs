﻿// Palisade Tuning UI â€” view models for the Policies, Startup, Debloat and
// Repair surfaces.
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
using Palisade.Tuning.Debloat;
using Palisade.Tuning.Policy;
using Palisade.Tuning.Repair;
using Palisade.Tuning.Startup;

namespace Palisade.App.ViewModels;

// ===================== Policies =====================

public partial class PoliciesViewModel : ObservableObject
{
    private IReadOnlyList<PolicyState> _states = [];

    public PoliciesViewModel()
    {
        ResetCommand = new AsyncRelayCommand<PolicyRowViewModel>(ResetAsync, _ => !IsBusy);
        ResetAllCommand = new AsyncRelayCommand(ResetAllAsync, () => !IsBusy && ConfiguredCount > 0);
        RefreshCommand = new AsyncRelayCommand(RefreshAsync, () => !IsBusy);
        _ = RefreshAsync();
    }

    public ObservableCollection<PolicyRowViewModel> Rows { get; } = [];

    public IAsyncRelayCommand RefreshCommand { get; }

    public IAsyncRelayCommand ResetCommand { get; }

    public IAsyncRelayCommand ResetAllCommand { get; }

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ResetAllCommand))]
    [NotifyCanExecuteChangedFor(nameof(RefreshCommand))]
    private bool _isBusy;

    [ObservableProperty]
    private string _statusLine = "Scanning group policy overridesâ€¦";

    [ObservableProperty]
    private int _configuredCount;

    private async Task RefreshAsync()
    {
        IsBusy = true;
        try
        {
            _states = await PolicyScanner.DetectPolicyStatesAsync().ConfigureAwait(true);
            Rows.Clear();
            foreach (var state in _states
                .OrderBy(s => s.Policy.Category, StringComparer.OrdinalIgnoreCase)
                .ThenBy(s => s.Policy.Name, StringComparer.OrdinalIgnoreCase))
            {
                Rows.Add(new PolicyRowViewModel(state));
            }
            ConfiguredCount = _states.Count(s => s.IsConfigured);
            StatusLine = ConfiguredCount == 0
                ? "No policy overrides found â€” every known policy is Not Configured."
                : $"{ConfiguredCount} of {_states.Count} known policies are configured on this machine.";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task ResetAsync(PolicyRowViewModel? row)
    {
        if (row is null)
        {
            return;
        }
        IsBusy = true;
        try
        {
            var ok = await PolicyScanner.RemovePolicyOverrideAsync(row.State.Policy).ConfigureAwait(true);
            await RefreshAsync().ConfigureAwait(true);
            StatusLine = ok
                ? $"Reset to Not Configured: {row.Name}"
                : $"Could not reset {row.Name} â€” access denied. Run as administrator.";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task ResetAllAsync()
    {
        IsBusy = true;
        try
        {
            var configured = _states.Where(s => s.IsConfigured).Select(s => s.Policy).ToList();
            var (succeeded, failed) = await PolicyScanner
                .RemovePolicyOverridesAsync(configured).ConfigureAwait(true);
            await RefreshAsync().ConfigureAwait(true);
            StatusLine = $"Reset {succeeded} policies" + (failed > 0 ? $", {failed} failed (access denied)." : ".");
        }
        finally
        {
            IsBusy = false;
        }
    }
}

public partial class PolicyRowViewModel : ObservableObject
{
    public PolicyRowViewModel(PolicyState state)
    {
        State = state;
        _name = state.Policy.Name;
        _description = state.Policy.Description;
        _category = state.Policy.Category;
        _isConfigured = state.IsConfigured;
        _currentValue = state.IsConfigured ? Format(state.CurrentValue) : "";
    }

    private static string Format(object? value) => value switch
    {
        int i => $"0x{i:X8} ({i})",
        long l => l.ToString(),
        byte[] bytes => Convert.ToHexString(bytes),
        string s => string.IsNullOrWhiteSpace(s) ? "(empty)" : s,
        null => "(null)",
        _ => value.ToString() ?? "",
    };

    public PolicyState State { get; }

    [ObservableProperty] private string _name;
    [ObservableProperty] private string _description;
    [ObservableProperty] private string _category;
    [ObservableProperty] private bool _isConfigured;
    [ObservableProperty] private string _currentValue;

    public string RegistryPath => $"{State.Policy.Hive}\\Software\\Policies\\{State.Policy.RegistryPath.TrimStart('\\')} · {State.Policy.ValueName}";
}

// ===================== Startup =====================

public partial class StartupViewModel : ObservableObject
{
    public StartupViewModel()
    {
        ToggleCommand = new AsyncRelayCommand<StartupRowViewModel>(ToggleAsync, _ => !IsBusy);
        RemoveCommand = new AsyncRelayCommand<StartupRowViewModel>(RemoveAsync, _ => !IsBusy);
        RefreshCommand = new AsyncRelayCommand(RefreshAsync, () => !IsBusy);
        _ = RefreshAsync();
    }

    public ObservableCollection<StartupRowViewModel> Rows { get; } = [];

    public IAsyncRelayCommand RefreshCommand { get; }

    public IAsyncRelayCommand ToggleCommand { get; }

    public IAsyncRelayCommand RemoveCommand { get; }

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private string _statusLine = "Enumerating startup entriesâ€¦";

    private async Task RefreshAsync()
    {
        IsBusy = true;
        try
        {
            var items = await StartupManager.GetStartupItemsAsync().ConfigureAwait(true);
            Rows.Clear();
            foreach (var item in items.OrderBy(i => i.Name, StringComparer.OrdinalIgnoreCase))
            {
                Rows.Add(new StartupRowViewModel(item));
            }
            StatusLine = $"{items.Count} startup entries · {items.Count(i => i.IsEnabled)} enabled";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task ToggleAsync(StartupRowViewModel? row)
    {
        if (row is null)
        {
            return;
        }
        IsBusy = true;
        try
        {
            var enable = !row.Item.IsEnabled;
            var ok = await StartupManager.SetStartupItemEnabledAsync(row.Item, enable).ConfigureAwait(true);
            if (ok)
            {
                row.Item.IsEnabled = enable;
                row.Refresh();
            }
            StatusLine = ok
                ? $"{(enable ? "Enabled" : "Disabled")}: {row.Name}"
                : $"Could not change {row.Name} â€” access denied. Run as administrator.";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task RemoveAsync(StartupRowViewModel? row)
    {
        if (row is null)
        {
            return;
        }
        IsBusy = true;
        try
        {
            var ok = await StartupManager.RemoveStartupItemAsync(row.Item).ConfigureAwait(true);
            if (ok)
            {
                Rows.Remove(row);
            }
            StatusLine = ok
                ? $"Removed: {row.Name}"
                : $"Could not remove {row.Name} â€” access denied. Run as administrator.";
        }
        finally
        {
            IsBusy = false;
        }
    }
}

public partial class StartupRowViewModel : ObservableObject
{
    public StartupRowViewModel(StartupItem item)
    {
        Item = item;
        _name = item.Name;
        _publisher = item.Publisher;
        _location = item.LocationDisplay;
        _impact = item.Impact.ToString();
        _isEnabled = item.IsEnabled;
    }

    public StartupItem Item { get; }

    public string Command => Item.Command;

    [ObservableProperty] private string _name;
    [ObservableProperty] private string _publisher;
    [ObservableProperty] private string _location;
    [ObservableProperty] private string _impact;
    [ObservableProperty] private bool _isEnabled;

    public void Refresh()
    {
        IsEnabled = Item.IsEnabled;
    }
}

// ===================== Debloat =====================

public partial class DebloatViewModel : ObservableObject
{
    public DebloatViewModel()
    {
        UninstallCommand = new AsyncRelayCommand<DebloatAppViewModel>(UninstallAsync, _ => !IsBusy);
        CleanTempCommand = new AsyncRelayCommand(CleanTempAsync, () => !IsBusy);
        RefreshCommand = new AsyncRelayCommand(RefreshAsync, () => !IsBusy);
        _ = RefreshAsync();
    }

    public ObservableCollection<DebloatAppViewModel> Apps { get; } = [];

    public IAsyncRelayCommand RefreshCommand { get; }

    public IAsyncRelayCommand UninstallCommand { get; }

    public IAsyncRelayCommand CleanTempCommand { get; }

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private string _searchText = "";

    [ObservableProperty]
    private string _statusLine = "Enumerating installed appsâ€¦";

    [ObservableProperty]
    private bool _showUwp = true;

    [ObservableProperty]
    private bool _showWin32 = true;

    private List<DebloatAppViewModel> _all = [];

    partial void OnSearchTextChanged(string value) => ApplyFilter();

    partial void OnShowUwpChanged(bool value) => ApplyFilter();

    partial void OnShowWin32Changed(bool value) => ApplyFilter();

    private void ApplyFilter()
    {
        Apps.Clear();
        foreach (var app in _all)
        {
            if ((app.Entry.IsWin32 && !ShowWin32) || (!app.Entry.IsWin32 && !ShowUwp))
            {
                continue;
            }
            if (SearchText.Length > 0 &&
                !app.Name.Contains(SearchText, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            Apps.Add(app);
        }
    }

    private async Task RefreshAsync()
    {
        IsBusy = true;
        try
        {
            StatusLine = "Enumerating installed appsâ€¦";
            var win32 = await DebloatManager.GetWin32AppsAsync().ConfigureAwait(true);
            var uwp = await DebloatManager.GetUwpAppsAsync().ConfigureAwait(true);
            _all = [.. win32.Select(a => new DebloatAppViewModel(a))
                .Concat(uwp.Select(a => new DebloatAppViewModel(a)))];
            ApplyFilter();
            StatusLine = $"{_all.Count} installed apps · {_all.Count(a => a.Entry.IsWin32)} Win32 · {_all.Count(a => !a.Entry.IsWin32)} Store";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task UninstallAsync(DebloatAppViewModel? app)
    {
        if (app is null)
        {
            return;
        }
        IsBusy = true;
        try
        {
            var ok = await DebloatManager.UninstallAsync(app.Entry).ConfigureAwait(true);
            if (ok)
            {
                _all.Remove(app);
                ApplyFilter();
            }
            StatusLine = ok
                ? $"Uninstalled: {app.Name}"
                : app.Name.Contains("edge", StringComparison.OrdinalIgnoreCase)
                    ? "Removing Microsoft Edge is deliberately not supported."
                    : $"Could not uninstall {app.Name}.";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task CleanTempAsync()
    {
        IsBusy = true;
        try
        {
            StatusLine = "Deep cleaning temp files â€” services stop, caches clear, the desktop may blink onceâ€¦";
            var (ok, bytes) = await TempCleaner.RemoveTempFilesAsync().ConfigureAwait(true);
            StatusLine = ok
                ? $"Deep clean finished â€” about {bytes / (1024.0 * 1024.0):F1} MB cleared."
                : "Deep clean hit an error partway; the desktop was restored.";
        }
        finally
        {
            IsBusy = false;
        }
    }
}

public partial class DebloatAppViewModel : ObservableObject
{
    public DebloatAppViewModel(DebloatManager.AppEntry entry)
    {
        Entry = entry;
        _name = entry.Name;
        _type = entry.IsWin32 ? "Win32" : "Store";
    }

    public DebloatManager.AppEntry Entry { get; }

    [ObservableProperty] private string _name;
    [ObservableProperty] private string _type;
}

// ===================== Repair =====================

public partial class RepairViewModel : ObservableObject
{
    public RepairViewModel()
    {
        CheckCommand = new AsyncRelayCommand(CheckAsync, () => !IsBusy);
        RepairCommand = new AsyncRelayCommand(RepairAsync, () => !IsBusy && NeedsRepair);
    }

    public ObservableCollection<RepairRowViewModel> Rows { get; } =
    [
        new("DISM"),
        new("SFC"),
        new("CHKDSK"),
    ];

    public IAsyncRelayCommand CheckCommand { get; }

    public IAsyncRelayCommand RepairCommand { get; }

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CheckCommand))]
    [NotifyCanExecuteChangedFor(nameof(RepairCommand))]
    private bool _isBusy;

    [ObservableProperty]
    private string _statusLine = "";

    [ObservableProperty]
    private bool _needsRepair;

    [ObservableProperty]
    private string _outputText = "";

    private async Task CheckAsync()
    {
        IsBusy = true;
        NeedsRepair = false;
        StatusLine = "Checking system health â€” DISM, SFC and CHKDSK. This can take several minutes.";
        OutputText = "";
        try
        {
            var results = await RepairManager.CheckAsync().ConfigureAwait(true);
            foreach (var result in results)
            {
                var row = Rows.First(r => r.Name == result.Name);
                row.Update(result.Health, result.OutputLines);
                OutputText += $"===== {result.Name} =====\n" + string.Join("\n", result.OutputLines) + "\n\n";
                if (result.Health == false)
                {
                    NeedsRepair = true;
                }
            }
            StatusLine = NeedsRepair
                ? "Issues found. Run Repair to fix the flagged components."
                : "All components healthy.";
        }
        catch (Exception ex)
        {
            StatusLine = $"Check failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task RepairAsync()
    {
        IsBusy = true;
        StatusLine = "Repairing flagged components â€” DISM /RestoreHealth and SFC /scannow run now; CHKDSK is scheduled for the next restart.";
        OutputText = "";
        try
        {
            var flagged = Rows.Where(r => r.Health == false).Select(r => r.Name).ToList();
            var results = await RepairManager.RepairAsync(flagged).ConfigureAwait(true);
            foreach (var result in results)
            {
                var row = Rows.First(r => r.Name == result.Name);
                row.Update(result.Scheduled ? null : result.Health, result.OutputLines);
                OutputText += $">>>>> {result.Name} (repair) <<<<<\n" + string.Join("\n", result.OutputLines) + "\n\n";
            }
            StatusLine = "Repair pass finished. Re-run Check to confirm; a restart completes the scheduled CHKDSK.";
        }
        catch (Exception ex)
        {
            StatusLine = $"Repair failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }
}

public partial class RepairRowViewModel : ObservableObject
{
    public RepairRowViewModel(string name)
    {
        Name = name;
        _friendlyName = RepairManager.FriendlyName(name);
        _healthWord = "not checked";
    }

    public string Name { get; }

    [ObservableProperty] private string _friendlyName;
    [ObservableProperty] private string _healthWord;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HealthWord))]
    private bool? _health;

    partial void OnHealthChanged(bool? value) =>
        HealthWord = value switch
        {
            true => "healthy",
            false => "needs attention",
            null => "unknown / scheduled",
        };

    public void Update(bool? health, IReadOnlyList<string> lines)
    {
        Health = health;
    }
}
