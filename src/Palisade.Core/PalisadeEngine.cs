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

namespace Palisade.Core;

/// <summary>
/// The public facade of the library, and its single composition root: later sub-projects
/// construct this class and nothing else. It holds no logic beyond the wiring of the handler
/// dictionary, the non-registry measures, the saved-state store, the detector and the apply
/// engine.
/// </summary>
public sealed class PalisadeEngine
{
    public PalisadeEngine(IRegistryKeyFactory registry, RegistryOptions options, IAppPaths paths, Func<bool> isElevated)
    {
        Registry = registry;
        Options = options;
        Paths = paths;

        var nonRegistryMeasures = new Dictionary<MeasureId, INonRegistryMeasure>
        {
            [new MeasureId(RecallMeasure.MeasureIdValue)] = new RecallMeasure(registry),
            [new MeasureId(AsrRulesMeasure.MeasureIdValue)] = new AsrRulesMeasure(registry),
        };

        var handlers = new Dictionary<Mechanism, IMechanismHandler>
        {
            [Mechanism.RegistryDword] = new RegistryDwordHandler(),
            [Mechanism.RegistryString] = new RegistryStringHandler(),
            [Mechanism.VersionedPath] = new VersionedPathHandler(),
            [Mechanism.DisallowRun] = new DisallowRunHandler(),
            [Mechanism.FileAssociation] = new FileAssociationHandler(),
            [Mechanism.NonRegistry] = new NonRegistryHandler(nonRegistryMeasures),
        };

        Store = new SavedStateStore(registry, options);
        Detector = new MeasureDetector(handlers, nonRegistryMeasures, isElevated, registry);
        Engine = new ApplyEngine(Detector, handlers, nonRegistryMeasures, Store);
    }

    /// <summary>The hive this engine operates on — the in-memory one in tests, the real one in production.</summary>
    public IRegistryKeyFactory Registry { get; }

    /// <summary>Where the saved state lives; <see cref="RegistryOptions.Default"/> upstream.</summary>
    public RegistryOptions Options { get; }

    /// <summary>The filesystem locations the engine may write to, such as its log directory.</summary>
    public IAppPaths Paths { get; }

    /// <summary>The saved-state store the engine writes through.</summary>
    public SavedStateStore Store { get; }

    internal MeasureDetector Detector { get; }

    internal ApplyEngine Engine { get; }

    /// <summary>The full 26-measure catalog.</summary>
    public IReadOnlyList<MeasureDescriptor> Catalog => MeasureCatalog.All;

    /// <summary>Detects the four-state model for every measure in the catalog.</summary>
    public IReadOnlyList<DetectionResult> Detect() => Detector.DetectAll();

    /// <summary>Hardens the requested measures. See <see cref="ApplyEngine.Apply"/>.</summary>
    public ApplyReport Apply(IReadOnlyCollection<MeasureId> ids) => Engine.Apply(ids);

    /// <summary>Puts every measure with a recorded original back. See <see cref="ApplyEngine.RestoreAll"/>.</summary>
    public ApplyReport RestoreAll() => Engine.RestoreAll();

    /// <summary>Restores everything, then applies the default set. See <see cref="ApplyEngine.ReapplyDefaults"/>.</summary>
    public ApplyReport ReapplyDefaults() => Engine.ReapplyDefaults();
}
