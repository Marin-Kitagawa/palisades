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

using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace Palisade.App.ViewModels;

/// <summary>Converters for the module pages. Word always travels with color.</summary>
public class ConfiguredToBrushConverter : IValueConverter
{
    public static readonly ConfiguredToBrushConverter Instance = new();
    private static IBrush On => ThemePalette.Error;
    private static IBrush Off => ThemePalette.Success;

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true ? On : Off;

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

public class BoolToFullOpacityConverter : IValueConverter
{
    public static readonly BoolToFullOpacityConverter Instance = new();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true ? 1.0 : 0.62;

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

public class EnabledToBrushConverter : IValueConverter
{
    public static readonly EnabledToBrushConverter Instance = new();
    private static IBrush On => ThemePalette.Success;
    private static IBrush Off => ThemePalette.Warning;

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true ? On : Off;

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

public class HealthToBrushConverter : IValueConverter
{
    public static readonly HealthToBrushConverter Instance = new();
    private static IBrush Healthy => ThemePalette.Success;
    private static IBrush Bad => ThemePalette.Error;
    private static IBrush Unknown => ThemePalette.Warning;

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value switch
        {
            true => Healthy,
            false => Bad,
            _ => Unknown,
        };

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

public class NameEqualsConverter : IValueConverter
{
    private readonly string _expected;

    public NameEqualsConverter(string expected) => _expected = expected;

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        Equals(value as string, _expected);

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

public class DismNameConverter : NameEqualsConverter
{
    private DismNameConverter() : base("DISM") { }

    public static readonly DismNameConverter Instance = new();
}

public class SfcNameConverter : NameEqualsConverter
{
    private SfcNameConverter() : base("SFC") { }

    public static readonly SfcNameConverter Instance = new();
}

public class ChkdskNameConverter : NameEqualsConverter
{
    private ChkdskNameConverter() : base("CHKDSK") { }

    public static readonly ChkdskNameConverter Instance = new();
}
