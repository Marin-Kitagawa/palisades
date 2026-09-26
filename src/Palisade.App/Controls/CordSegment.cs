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
/// One segment of the red cord that zigzags down the measure column.
/// Each rod row reserves a 28px gutter and hosts one segment; the cord
/// enters at the top edge at the previous rod's anchor and leaves at the
/// bottom edge at the next rod's anchor, so the zigzag always lines up
/// regardless of how far the row's text wraps. Taut rods hold the cord in
/// red; slack rods let it drop to ash; stressed rods carry a stressed dash.
/// </summary>
public class CordSegment : Control
{
    public static readonly StyledProperty<MeasureState> StateProperty =
        AvaloniaProperty.Register<CordSegment, MeasureState>(nameof(State), MeasureState.Slack);

    public static readonly StyledProperty<int> IndexProperty =
        AvaloniaProperty.Register<CordSegment, int>(nameof(Index), 0);

    private const double GutterWidth = 28;

    public MeasureState State
    {
        get => GetValue(StateProperty);
        set => SetValue(StateProperty, value);
    }

    public int Index
    {
        get => GetValue(IndexProperty);
        set => SetValue(IndexProperty, value);
    }

    private static readonly IBrush Red = new SolidColorBrush(Color.Parse("#C22F26"));
    private static readonly IBrush Ash = new SolidColorBrush(Color.Parse("#8F918D"));
    private static readonly Pen RedPen = new(Red, 1.6);
    private static readonly Pen RedStressPen = new(Red, 1.6, dashStyle: new DashStyle([4, 2.4], 0));
    private static readonly Pen AshPen = new(Ash, 1.4, dashStyle: new DashStyle([2, 2.4], 0));

    private static double AnchorX(int index) => index % 2 == 0 ? GutterWidth * 0.26 : GutterWidth * 0.74;

    public override void Render(DrawingContext context)
    {
        double h = Bounds.Height;
        if (h <= 0)
        {
            return;
        }

        double prev = AnchorX(Index - 1);
        double here = AnchorX(Index);
        double next = AnchorX(Index + 1);
        var mid = new Point(here, h / 2);

        var geometry = new StreamGeometry();
        using (var ctx = geometry.Open())
        {
            ctx.BeginFigure(new Point(prev, 0), isFilled: false);
            ctx.LineTo(mid);
            ctx.LineTo(new Point(next, h));
            ctx.EndFigure(false);
        }

        var pen = State switch
        {
            MeasureState.Taut => RedPen,
            MeasureState.Stressed => RedStressPen,
            _ => AshPen,
        };

        context.DrawGeometry(null, pen, geometry);

        // Anchor node on the rod itself.
        var node = new Rect(mid.X - 2.5, mid.Y - 2.5, 5, 5);
        switch (State)
        {
            case MeasureState.Taut:
                context.FillRectangle(Red, node);
                break;
            case MeasureState.Stressed:
                context.FillRectangle(Red, node);
                context.DrawRectangle(new Pen(Ash, 1), node.Deflate(-1.5));
                break;
            default:
                context.DrawRectangle(AshPen, node);
                break;
        }
    }
}
