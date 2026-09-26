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

using Palisade.Core.Engine;
using Palisade.Core.Mechanisms;
using Palisade.Core.Models;
using Palisade.Core.Registry;

namespace Palisade.Core.Tests.Engine;

/// <summary>
/// The one place the handler dictionary and the non-registry dictionary are assembled for
/// the tests, so a later change to composition is made once. Mirrors
/// <see cref="PalisadeEngine"/>'s constructor exactly.
/// </summary>
internal static class EngineFactory
{
    public static MeasureDetector BuildDetector(IRegistry? registry = null, bool isElevated = true)
    {
        var hive = (IRegistryKeyFactory)(registry ?? new InMemoryRegistry());
        return new MeasureDetector(BuildHandlers(hive), BuildNonRegistryMeasures(hive), () => isElevated, hive);
    }

    public static PalisadeEngine BuildEngine(IRegistry? registry = null, bool isElevated = true) =>
        new(registry is null ? new InMemoryRegistry() : (IRegistryKeyFactory)registry, RegistryOptions.Default, new AppPaths("."), () => isElevated);

    internal static IReadOnlyDictionary<Mechanism, IMechanismHandler> BuildHandlers(IRegistryKeyFactory hive) => new Dictionary<Mechanism, IMechanismHandler>
    {
        [Mechanism.RegistryDword] = new RegistryDwordHandler(),
        [Mechanism.RegistryString] = new RegistryStringHandler(),
        [Mechanism.VersionedPath] = new VersionedPathHandler(),
        [Mechanism.DisallowRun] = new DisallowRunHandler(),
        [Mechanism.FileAssociation] = new FileAssociationHandler(),
        [Mechanism.NonRegistry] = new NonRegistryHandler(BuildNonRegistryMeasures(hive)),
    };

    internal static IReadOnlyDictionary<MeasureId, INonRegistryMeasure> BuildNonRegistryMeasures(IRegistryKeyFactory hive) =>
        new Dictionary<MeasureId, INonRegistryMeasure>
        {
            [new MeasureId(RecallMeasure.MeasureIdValue)] = new RecallMeasure(hive),
            [new MeasureId(AsrRulesMeasure.MeasureIdValue)] = new AsrRulesMeasure(hive),
        };
}
