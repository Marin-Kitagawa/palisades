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

using System.Security.Principal;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform;
using Avalonia.Styling;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using Palisade.App.Views;

namespace Palisade.App.ViewModels;

/// <summary>
/// Application shell: navigation, elevation posture, attribution.
/// The not-an-antivirus boundary is stated here, in the shell, because a
/// security tool that implies protection it cannot deliver causes harm.
/// </summary>
public partial class ShellViewModel : ObservableObject
{
    [ObservableProperty]
    private Avalonia.Controls.Control? _currentPage;

    [ObservableProperty]
    private NavItemViewModel? _selectedNav;

    public bool IsElevated { get; } = IsRunningElevated();

    public string PrivilegeLine { get; }

    /// <summary>Persisted dark-mode preference.</summary>
    [ObservableProperty]
    private bool _isDarkTheme = ReadDarkPreference();

    partial void OnIsDarkThemeChanged(bool value)
    {
        Application.Current!.RequestedThemeVariant = value ? ThemeVariant.Dark : ThemeVariant.Light;
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey("SOFTWARE\\Palisade\\UI");
            key.SetValue("DarkMode", value ? 1 : 0, RegistryValueKind.DWord);
        }
        catch
        {
            // Preference persistence is best-effort.
        }
    }

    private static bool ReadDarkPreference()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Palisade\\UI");
            return key?.GetValue("DarkMode") is int v && v == 1;
        }
        catch
        {
            return false;
        }
    }

    public IReadOnlyList<NavItemViewModel> Navigation { get; }

    public ShellViewModel()
    {
        PrivilegeLine = IsElevated
            ? "administrator — all measures available"
            : "standard account — some measures need elevation";

        var harden = new HardenViewModel();
        Navigation =
        [
            new NavItemViewModel("Palisade", "the 26 hardening measures", "\uE80F", "harden", () => new HardenView { DataContext = harden }),
            new NavItemViewModel("Optimize", "tuning toggles from RyTuneX", "\uEC4A", "optimize", () => new OptimizeView { DataContext = new OptimizeViewModel() }),
            new NavItemViewModel("Policies", "group policy scanner", "\uE8B7", "policies", () => new PoliciesView { DataContext = new PoliciesViewModel() }),
            new NavItemViewModel("Startup", "startup entries", "\uE7E8", "startup", () => new StartupView { DataContext = new StartupViewModel() }),
            new NavItemViewModel("Debloat", "apps and temp files", "\uE74D", "debloat", () => new DebloatView { DataContext = new DebloatViewModel() }),
            new NavItemViewModel("Repair", "DISM, SFC and CHKDSK", "\uE90F", "repair", () => new RepairView { DataContext = new RepairViewModel() }),
            new NavItemViewModel("About", "license and provenance", "\uE946", "about", () => new AboutView { DataContext = new AboutViewModel() }),
        ];
        // Deep-link: Palisade.exe --page optimize
        var argv = Environment.GetCommandLineArgs();
        var pageIdx = Array.IndexOf(argv, "--page");
        var requested = pageIdx >= 0 && pageIdx + 1 < argv.Length ? argv[pageIdx + 1] : null;
        SelectedNav = requested is null
            ? Navigation[0]
            : Navigation.FirstOrDefault(n => n.Tag == requested) ?? Navigation[0];
        CurrentPage = SelectedNav.CreateView();

        // The toggle is authoritative: off = light, on = dark (never follow the OS).
        Application.Current!.RequestedThemeVariant = IsDarkTheme ? ThemeVariant.Dark : ThemeVariant.Light;
    }

    partial void OnSelectedNavChanged(NavItemViewModel? value)
    {
        if (value is not null)
        {
            CurrentPage = value.CreateView();
        }
    }

    [RelayCommand]
    private void RelaunchElevated()
    {
        if (IsElevated || Environment.ProcessPath is not { Length: > 0 } exe)
        {
            return;
        }

        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(exe)
            {
                UseShellExecute = true,
                Verb = "runas",
            });
            if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                desktop.Shutdown();
            }
        }
        catch (Exception)
        {
            // The user declined the UAC prompt; stay standard. Nothing to recover.
        }
    }

    private static bool IsRunningElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (Exception)
        {
            return false;
        }
    }
}

public partial class NavItemViewModel : ObservableObject
{
    public string Title { get; }

    public string Subtitle { get; }

    /// <summary>Segoe Fluent Icons glyph for the navigation pane.</summary>
    public string Icon { get; }

    private readonly Func<Control> _createView;

    public NavItemViewModel(string title, string subtitle, string icon, string tag, Func<Control> createView)
    {
        Title = title;
        Subtitle = subtitle;
        Icon = icon;
        Tag = tag;
        _createView = createView;
    }

    /// <summary>Stable id for deep-linking via --page.</summary>
    public string Tag { get; }

    public Control CreateView() => _createView();
}
