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
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Palisade.Core.Models;

namespace Palisade.App.Controls;

/// <summary>
/// The blast-radius force diagram: for the selected rod, the measures it
/// constrains and the measures that constrain it, drawn as an engineering
/// figure over the same pale concrete. Deterministic layout ” the same
/// machine always draws the same figure. Labels are real measure names and
/// the real constraint reasons; nothing here is illustrative.
/// </summary>
public class BlastRadius : Control
{
    public static readonly StyledProperty<MeasureDescriptor?> SelectedProperty =
        AvaloniaProperty.Register<BlastRadius, MeasureDescriptor?>(nameof(Selected));

    public static readonly StyledProperty<IReadOnlyList<MeasureDescriptor>?> CatalogProperty =
        AvaloniaProperty.Register<BlastRadius, IReadOnlyList<MeasureDescriptor>?>(
            nameof(Catalog),
            Palisade.Core.Models.MeasureCatalog.All);

    public MeasureDescriptor? Selected
    {
        get => GetValue(SelectedProperty);
        set => SetValue(SelectedProperty, value);
    }

    public IReadOnlyList<MeasureDescriptor>? Catalog
    {
        get => GetValue(CatalogProperty);
        set => SetValue(CatalogProperty, value);
    }

    private static readonly Typeface MonoType = new(FontFamily.Parse("Consolas, Courier New"));
    private static readonly IBrush InkPrimary = new SolidColorBrush(Color.Parse("#1B1B1B"));
    private static readonly IBrush Ink2 = new SolidColorBrush(Color.Parse("#5D5D5D"));
    private static readonly IBrush Accent = new SolidColorBrush(Color.Parse("#0078D4"));
    private static readonly IBrush LineStrong = new SolidColorBrush(Color.Parse("#D6D6D6"));
    private static readonly Pen EdgePen = new(LineStrong, 1);
    private static readonly Pen EdgeAccentPen = new(Accent, 1.2);

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (e.Property == SelectedProperty)
        {
            InvalidateVisual();
        }
    }

    public override void Render(DrawingContext context)
    {
        var selected = Selected;
        var catalog = Catalog;
        if (selected is null || catalog is null)
        {
            DrawEmptyState(context);
            return;
        }

        double width = Bounds.Width;
        double height = Bounds.Height;
        if (width < 120 || height < 80)
        {
            return;
        }

        // Forward edges: measures this rod constrains. Backward: rods constraining this one.
        var forward = selected.ConstrainedBy
            .Select(c => (Descriptor: Palisade.Core.Models.MeasureCatalog.Get(c.Target), Reason: c.Reason))
            .ToList();
        var backward = catalog
            .Where(m => m.ConstrainedBy.Any(c => c.Target == selected.Id))
            .Select(m => (Descriptor: m, Reason: m.ConstrainedBy.First(c => c.Target == selected.Id).Reason))
            .ToList();

        var origin = new Point(26, height / 2);
        double nodeSize = 10;

        // Selected node: accent square, ink ring.
        var originRect = new Rect(origin.X - nodeSize / 2, origin.Y - nodeSize / 2, nodeSize, nodeSize);
        context.FillRectangle(Accent, originRect);
        context.DrawRectangle(new Pen(InkPrimary, 1), originRect.Deflate(-3));

        DrawWrapped(context, selected.Name, 11.5, InkPrimary, width - 60, new Point(origin.X + 14, origin.Y - 18));
        DrawWrapped(context, selected.Id.Value, 10, Ink2, width - 60, new Point(origin.X + 14, origin.Y + 2));

        if (forward.Count == 0 && backward.Count == 0)
        {
            DrawWrapped(context, "no declared constraints - this rod stands alone", 10.5, Ink2, width - 60,
                new Point(origin.X + 14, origin.Y + 20));
            return;
        }

        // Right column of counter-force nodes; forward edges accent (this rod pulls them),
        // backward edges gray (they pull this rod).
        var rows = new List<(string Name, string Reason, bool Forward)>();
        foreach (var (d, reason) in forward)
        {
            rows.Add((d.Name, reason, true));
        }

        foreach (var (d, reason) in backward)
        {
            rows.Add((d.Name, reason, false));
        }

        double rowPitch = 44;
        double columnHeight = rows.Count * rowPitch;
        double y = Math.Max(14, (height - columnHeight) / 2 + rowPitch / 2);
        double nodeX = Math.Min(width - 190, origin.X + 120);

        foreach (var (name, reason, isForward) in rows)
        {
            var node = new Rect(nodeX - nodeSize / 2, y - nodeSize / 2, nodeSize, nodeSize);
            var pen = isForward ? EdgeAccentPen : EdgePen;

            double midX = (origin.X + 20 + nodeX - 8) / 2;
            context.DrawLine(pen, new Point(origin.X + nodeSize / 2 + 3, origin.Y), new Point(midX, origin.Y));
            context.DrawLine(pen, new Point(midX, origin.Y), new Point(midX, y));
            context.DrawLine(pen, new Point(midX, y), new Point(nodeX - nodeSize / 2 - 3, y));

            context.FillRectangle(isForward ? Accent : InkPrimary, node);

            DrawWrapped(context, name, 11, InkPrimary, width - nodeX - 26, new Point(nodeX + 12, y - 16));
            DrawWrapped(context, reason, 9.5, Ink2, width - nodeX - 26, new Point(nodeX + 12, y + 3));

            y += rowPitch;
        }
    }

    private void DrawEmptyState(DrawingContext context)
    {
        DrawWrapped(context, "select a rod to see the forces it carries", 11.5, Ink2,
            Math.Max(40, Bounds.Width - 24), new Point(16, 20));
    }

    /// <summary>
    /// Monospace text drawn with an explicit word-wrap, so the figure controls its own
    /// measure without depending on FormattedText constraints.
    /// </summary>
    private static void DrawWrapped(DrawingContext context, string text, double size, IBrush brush,
        double maxWidth, Point origin)
    {
        double pitch = size * 1.4;
        double y = origin.Y;
        var line = string.Empty;
        foreach (var word in text.Split(' '))
        {
            var candidate = line.Length == 0 ? word : line + " " + word;
            if (Measure(candidate, size, brush) <= maxWidth || line.Length == 0)
            {
                line = candidate;
            }
            else
            {
                Draw(context, line, size, brush, origin.X, y);
                y += pitch;
                line = word;
            }
        }
        if (line.Length > 0)
        {
            Draw(context, line, size, brush, origin.X, y);
        }
    }

    private static void Draw(DrawingContext context, string text, double size, IBrush brush, double x, double y)
    {
        var ft = new FormattedText(text, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, MonoType, size, brush);
        context.DrawText(ft, new Point(x, y));
    }

    private static double Measure(string text, double size, IBrush brush) =>
        new FormattedText(text, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, MonoType, size, brush).Width;
}
