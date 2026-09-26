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

namespace Palisade.App.ViewModels;

/// <summary>
/// UI-side error log under %LOCALAPPDATA%\Palisade\logs\ui.log. The engine
/// has its own log; this catches what the view model layer swallows.
/// </summary>
public static class UiLog
{
    private static readonly object Gate = new();
    private static readonly string Path = System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Palisade", "logs", "ui.log");

    public static void Error(string what, Exception error)
    {
        try
        {
            System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
            lock (Gate)
            {
                File.AppendAllText(Path, $"{DateTime.Now:O}  ERROR  {what}: {error}\n\n");
            }
        }
        catch
        {
            // Nowhere to log to; nothing else to do.
        }
    }
}
