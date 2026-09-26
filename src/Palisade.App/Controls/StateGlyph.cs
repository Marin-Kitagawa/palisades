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

using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Palisade.Core.Models;

namespace Palisade.App.Controls;

/// <summary>
/// Draws the four hardening states as a drawn glyph, never color alone:
/// Taut â€” filled carbon square crossed by a taut red cord.
/// Slack â€” hollow ash square, cord dropped.
/// Stressed â€” filled square crossed by a stressed zigzag cord.
/// Unavailable â€” dashed ash square.
/// </summary>
public class StateGlyph : Control
{
    public static readonly StyledProperty<MeasureState> StateProperty =
        AvaloniaProperty.Register<StateGlyph, MeasureState>(nameof(State), MeasureState.Slack);

    public MeasureState State
    {
        get => GetValue(StateProperty);
        set => SetValue(StateProperty, value);
    }

    private static readonly IBrush Carbon = new SolidColorBrush(Color.Parse("#1B1B1B"));
    private static readonly IBrush Ash = new SolidColorBrush(Color.Parse("#8A8A8A"));
    private static readonly IBrush Red = new SolidColorBrush(Color.Parse("#C42B1C"));
    private static readonly Pen AshPen = new(Ash, 1.2, dashStyle: new DashStyle([2, 2], 0));
    private static readonly Pen RedPen = new(Red, 1.6);

    public override void Render(DrawingContext context)
    {
        var bounds = new Rect(Bounds.Size);
        double inset = Math.Max(1, Math.Min(bounds.Width, bounds.Height) * 0.08);
        var rect = bounds.Deflate(inset);
        double size = Math.Min(rect.Width, rect.Height);
        var square = new Rect(rect.Center.X - size / 2, rect.Center.Y - size / 2, size, size);

        switch (State)
        {
            case MeasureState.Taut:
                context.FillRectangle(Carbon, square);
                context.DrawLine(RedPen, square.TopLeft, square.BottomRight);
                break;

            case MeasureState.Stressed:
                context.FillRectangle(Carbon, square);
                double x0 = square.Left, x1 = square.Right;
                double yMid = square.Center.Y;
                context.DrawLine(RedPen, new Point(x0, yMid - size * 0.22), new Point(x0 + size * 0.34, yMid + size * 0.16));
                context.DrawLine(RedPen, new Point(x0 + size * 0.34, yMid + size * 0.16), new Point(x0 + size * 0.62, yMid - size * 0.18));
                context.DrawLine(RedPen, new Point(x0 + size * 0.62, yMid - size * 0.18), new Point(x1, yMid + size * 0.2));
                break;

            case MeasureState.Slack:
                context.DrawRectangle(AshPen, square);
                break;

            case MeasureState.Unavailable:
            default:
                context.DrawRectangle(AshPen, square);
                context.DrawLine(AshPen, new Point(square.Left, square.Center.Y), new Point(square.Right, square.Center.Y));
                break;
        }
    }
}
