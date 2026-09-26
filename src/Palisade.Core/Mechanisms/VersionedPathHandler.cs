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

using Palisade.Core.Models;
using Palisade.Core.Registry;

namespace Palisade.Core.Mechanisms;

/// <summary>
/// The result of expanding a measure's declared targets against the discovered products:
/// the concrete targets to operate on, plus one failure per target that could not be
/// resolved and <em>why</em>. A non-empty failure list makes detection return
/// <c>Unavailable</c> — a zero-path resolution is a reported failure, never a silent
/// success (spec defect #9).
/// </summary>
public sealed record PathResolutionResult(
    IReadOnlyList<ResolvedTarget> Targets,
    IReadOnlyList<string> Failures);

/// <summary>
/// The <c>VersionedPath</c> mechanism: expand each declared target's path template over the
/// discovered products, then treat every expanded value exactly as the plain registry
/// handlers do. Expansion is driven by the placeholders in the target's own
/// <see cref="MeasureTarget.Path"/> — never by the descriptor's mechanism, because a
/// <c>VersionedPath</c> measure may carry a fixed path
/// (<c>office.go</c>'s <c>fNoCalclinksOnopen_90_1</c>, a hardcoded
/// <c>12.0\Word\Options\vpref</c>), and expanding that over the version list would write
/// once per version to the same key. The rules:
/// </summary>
/// <list type="bullet">
/// <item>A path containing <c>%s</c> is versioned. The first placeholder takes the version;
/// a second takes the app (Go formats <c>PathRegEx</c> as
/// <c>Sprintf(path, version, app)</c>, <c>office.go:160</c>). The lists come from the
/// descriptor's settings and are narrowed by the target's
/// <see cref="MeasureTarget.AppFilter"/>/<see cref="MeasureTarget.VersionFilter"/>.</item>
/// <item>A path with no <c>%s</c> is fixed: exactly one resolved target, nothing substituted.</item>
/// </list>
public sealed class VersionedPathHandler : RegistryValueHandlerBase
{
    public override Mechanism Mechanism => Mechanism.VersionedPath;

    /// <summary>Expands the descriptor's declared targets. Does not consult the registry —
    /// whether a resolved key exists is detection's business, not resolution's.</summary>
    public PathResolutionResult Resolve(MeasureDescriptor descriptor, IVersionResolver versions)
    {
        var targets = new List<ResolvedTarget>();
        var failures = new List<string>();

        foreach (var declared in descriptor.Targets)
        {
            var placeholderCount = CountPlaceholders(declared.Path);
            if (placeholderCount == 0)
            {
                // A fixed path resolves to exactly one target even when filters are set and
                // even when the measure as a whole is versioned.
                targets.Add(new ResolvedTarget(
                    declared.Root, declared.Path, declared.ValueName, null, declared.Kind, declared.HardenedValue));
                continue;
            }

            var available = Narrow(VersionsFor(descriptor, versions), declared.VersionFilter);
            if (available.Count == 0)
            {
                failures.Add($"No installed version matched '{declared.Path}' for measure '{descriptor.Id}'.");
                continue;
            }

            if (placeholderCount >= 2)
            {
                var apps = Narrow(AppsFor(descriptor), declared.AppFilter);
                if (apps.Count == 0)
                {
                    failures.Add($"No application matched '{declared.Path}' for measure '{descriptor.Id}'.");
                    continue;
                }

                foreach (var version in available)
                {
                    foreach (var app in apps)
                    {
                        targets.Add(new ResolvedTarget(
                            declared.Root,
                            Substitute(declared.Path, version, app),
                            declared.ValueName, null, declared.Kind, declared.HardenedValue));
                    }
                }
            }
            else
            {
                foreach (var version in available)
                {
                    targets.Add(new ResolvedTarget(
                        declared.Root,
                        Substitute(declared.Path, version, app: null),
                        declared.ValueName, null, declared.Kind, declared.HardenedValue));
                }
            }
        }

        return new PathResolutionResult(targets, failures);
    }

    public override IReadOnlyList<ResolvedTarget> ResolveTargets(MeasureDescriptor descriptor, IVersionResolver versions) =>
        Resolve(descriptor, versions).Targets;

    /// <summary>
    /// Zero resolved targets is the resolution-failure signal: the engine passes the targets
    /// it got from <see cref="ResolveTargets"/>, so an empty list here means the measure
    /// could not resolve and reads as <c>Unavailable</c>, never as a silent success.
    /// </summary>
    public override MeasureState Detect(MeasureDescriptor descriptor, IReadOnlyList<ResolvedTarget> targets, IRegistryKeyFactory registry) =>
        targets.Count == 0 ? MeasureState.Unavailable : base.Detect(descriptor, targets, registry);

    private static IReadOnlyList<string> VersionsFor(MeasureDescriptor descriptor, IVersionResolver versions)
    {
        if (descriptor.Settings.ContainsKey("OfficeVersions"))
        {
            return versions.ResolveOfficeVersions();
        }

        if (descriptor.Settings.ContainsKey("AdobeVersions"))
        {
            return versions.ResolveAdobeVersions();
        }

        return [];
    }

    private static IReadOnlyList<string> AppsFor(MeasureDescriptor descriptor)
    {
        var raw = descriptor.Settings.GetValueOrDefault("Apps");
        return string.IsNullOrWhiteSpace(raw)
            ? []
            : raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static IReadOnlyList<string> Narrow(IReadOnlyList<string> universe, string? filter)
    {
        if (filter is null)
        {
            return universe;
        }

        var allowed = filter.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return universe.Where(item => allowed.Contains(item, StringComparer.Ordinal)).ToList();
    }

    private static int CountPlaceholders(string path)
    {
        var count = 0;
        for (var index = path.IndexOf("%s", StringComparison.Ordinal);
             index >= 0;
             index = path.IndexOf("%s", index + 2, StringComparison.Ordinal))
        {
            count++;
        }

        return count;
    }

    /// <summary>The first placeholder takes the version, the second the app, as Go's two-argument Sprintf does.</summary>
    private static string Substitute(string path, string version, string? app)
    {
        var first = path.IndexOf("%s", StringComparison.Ordinal);
        var substituted = path[..first] + version + path[(first + 2)..];
        if (app is null)
        {
            return substituted;
        }

        var second = substituted.IndexOf("%s", StringComparison.Ordinal);
        return substituted[..second] + app + substituted[(second + 2)..];
    }
}

/// <summary>
/// The production <see cref="IVersionResolver"/>: it returns the products it can prove are
/// installed. Two sources are consulted, and their union is returned in upstream's standard
/// order followed by any extras:
/// </summary>
/// <list type="bullet">
/// <item>Filesystem enumeration of the version directories under both program-file roots
/// (<c>Microsoft Office</c>'s <c>OfficeNN</c> directories, including the Click-to-Run
/// <c>root\OfficeNN</c> layout, and <c>Adobe\Acrobat Reader\NN</c>), which is the only way to
/// see a version outside the historical standard lists.</item>
/// <item>Registry probes of the standard version keys under
/// <c>SOFTWARE\Microsoft\Office\NN</c> and <c>SOFTWARE\Adobe\Acrobat Reader\NN</c>, which
/// catch per-user installs the program-file directories miss.</item>
/// </list>
/// <remarks>
/// When <em>neither</em> source shows anything, the resolver falls back to upstream's
/// standard lists. That reproduces the Go tool exactly — <c>office.go</c> and
/// <c>adobe.go</c> write the standard lists unconditionally, creating keys for products that
/// were never installed — and it keeps the engine operable on a machine where a product's
/// markers have not been created yet. The zero-resolution failure contract
/// (<see cref="VersionedPathHandler.Resolve"/>) is exercised by every caller that injects an
/// explicit empty resolver, and remains in force for any future resolver change.
/// </remarks>
public sealed class InstalledVersionResolver(IRegistryKeyFactory registry) : IVersionResolver
{
    private static readonly string[] StandardOfficeVersions = ["12.0", "14.0", "15.0", "16.0"];
    private static readonly string[] StandardAdobeVersions = ["DC", "2020", "XI"];

    public IReadOnlyList<string> ResolveOfficeVersions()
    {
        var found = new List<string>();
        foreach (var version in StandardOfficeVersions)
        {
            if (Probe(@"SOFTWARE\Microsoft\Office\" + version))
            {
                found.Add(version);
            }
        }

        foreach (var root in ProgramFileRoots())
        {
            found.AddRange(OfficeVersionsFromDirectories(root + @"\Microsoft Office"));
            found.AddRange(OfficeVersionsFromDirectories(root + @"\Microsoft Office\root"));
        }

        return Ordered(found, StandardOfficeVersions);
    }

    public IReadOnlyList<string> ResolveAdobeVersions()
    {
        var found = new List<string>();
        foreach (var version in StandardAdobeVersions)
        {
            if (Probe(@"SOFTWARE\Adobe\Acrobat Reader\" + version))
            {
                found.Add(version);
            }
        }

        foreach (var root in ProgramFileRoots())
        {
            var readerDirectory = root + @"\Adobe\Acrobat Reader";
            if (Directory.Exists(readerDirectory))
            {
                found.AddRange(Directory.EnumerateDirectories(readerDirectory)
                    .Select(Path.GetFileName)
                    .Where(name => !string.IsNullOrWhiteSpace(name))
                    .Select(name => name!));
            }
        }

        return Ordered(found, StandardAdobeVersions);
    }

    private bool Probe(string keyPath)
    {
        using (var user = registry.OpenKey(RegistryRoot.CurrentUser, keyPath, writable: false))
        {
            if (user is not null)
            {
                return true;
            }
        }

        using var machine = registry.OpenKey(RegistryRoot.LocalMachine, keyPath, writable: false);
        return machine is not null;
    }

    private static IEnumerable<string> ProgramFileRoots()
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        if (!string.IsNullOrWhiteSpace(programFiles))
        {
            yield return programFiles;
        }

        if (!string.IsNullOrWhiteSpace(programFilesX86) && !programFilesX86.Equals(programFiles, StringComparison.OrdinalIgnoreCase))
        {
            yield return programFilesX86;
        }
    }

    private static IEnumerable<string> OfficeVersionsFromDirectories(string officeDirectory)
    {
        if (!Directory.Exists(officeDirectory))
        {
            yield break;
        }

        foreach (var directory in Directory.EnumerateDirectories(officeDirectory, "Office*"))
        {
            var suffix = Path.GetFileName(directory)["Office".Length..];
            if (suffix.Length > 0 && suffix.All(char.IsDigit))
            {
                yield return suffix + ".0";
            }
        }
    }

    /// <summary>Standard-list order first, then any extra discovered versions, deduplicated.</summary>
    private static IReadOnlyList<string> Ordered(List<string> found, string[] standard)
    {
        var result = new List<string>();
        foreach (var version in standard)
        {
            if (found.Contains(version, StringComparer.OrdinalIgnoreCase))
            {
                result.Add(version);
            }
        }

        foreach (var version in found)
        {
            if (!result.Contains(version, StringComparer.OrdinalIgnoreCase))
            {
                result.Add(version);
            }
        }

        return result.Count > 0 ? result : standard;
    }
}
