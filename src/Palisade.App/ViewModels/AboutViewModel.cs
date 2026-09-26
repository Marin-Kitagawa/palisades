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

namespace Palisade.App.ViewModels;

public class AboutViewModel : ObservableObject
{
    public string Title => "About Palisade";

    public string Boundary => "Palisade is not an antivirus. It reduces the Windows attack surface by " +
        "disabling low-hanging-fruit features that are useless to regular users but are routinely abused to " +
        "execute malicious code. It does not identify, block, or remove malware, and it does not prevent its " +
        "own changes from being reverted by code that already runs with your privileges.";

    public string Reversibility => "Every change is recorded under HKCU\\SOFTWARE\\Security Without Borders\\ " +
        "so it can be reverted exactly, by this tool or by the original hardentools. Changes are scoped to the " +
        "account that ran the tool.";

    public string License => "GPLv3. Palisade is a C# port of hardentools by Claudio Guarnieri, Mariano " +
        "Graziano, and Florian Probst — Security Without Borders (https://hardentools.github.io). The measure " +
        "list and registry payloads come from the upstream project; its wiki documents every change in full.";

    public string TuningAttribution => "The tuning, policy scanner, startup, debloat, and repair facilities are " +
        "ported from RyTuneX (https://github.com/rayenghanmi/RyTuneX), also GPLv3.";

    public string IconCredit => "The hammer icon derives from the upstream project's icon by Travis Avery, " +
        "from the Noun Project.";
}
