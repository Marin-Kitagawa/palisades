// Hardentools
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

using Palisade.Core.Mechanisms;

namespace Palisade.Core.Tests;

/// <summary>
/// Fixed version lists for the mechanism tests. The parameterless construction returns empty
/// lists, which is what the non-versioned measures want: their resolution never consults a
/// version list at all.
/// </summary>
public sealed class StubVersionResolver(
    IReadOnlyList<string>? officeVersions = null,
    IReadOnlyList<string>? adobeVersions = null) : IVersionResolver
{
    public IReadOnlyList<string> ResolveOfficeVersions() => officeVersions ?? [];

    public IReadOnlyList<string> ResolveAdobeVersions() => adobeVersions ?? [];
}
