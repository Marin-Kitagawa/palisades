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
using Palisade.Core.Models;

namespace Palisade.App.ViewModels;

/// <summary>
/// MeasureState → semantic state dot color (WinUI semantic colors).
/// Never color alone: every pill pairs the dot with its word.
/// </summary>
public class StateToBrushConverter : IValueConverter
{
    public static readonly StateToBrushConverter Instance = new();

    private static readonly IBrush Success = new SolidColorBrush(Color.Parse("#0F7B0F"));
    private static readonly IBrush Neutral = new SolidColorBrush(Color.Parse("#5D5D5D"));
    private static readonly IBrush Error = new SolidColorBrush(Color.Parse("#C42B1C"));
    private static readonly IBrush Warning = new SolidColorBrush(Color.Parse("#9D5D00"));

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is MeasureState state ? state switch
        {
            MeasureState.Taut => Success,
            MeasureState.Slack => Neutral,
            MeasureState.Stressed => Error,
            MeasureState.Unavailable => Warning,
            _ => Neutral,
        } : Neutral;

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
