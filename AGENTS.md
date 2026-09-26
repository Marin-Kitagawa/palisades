# AGENTS.md

Facts about this machine and repo that an agent cannot infer. Verified 2026-09-26.

## Build and test

**`dotnet` on `PATH` has no SDKs installed.** The working SDK 10.0.401 lives at:

```
C:\Users\Ahri\Software\dotnet10.0.401\dotnet.exe
```

Always invoke it by that full path. A bare `dotnet` fails with "No .NET SDKs were found",
which looks like a broken repo but is a machine quirk. `README.md` documents bare `dotnet`
because that is correct for a normal install — do not "fix" the README to match this machine.

```
& "C:\Users\Ahri\Software\dotnet10.0.401\dotnet.exe" build Palisade.slnx
& "C:\Users\Ahri\Software\dotnet10.0.401\dotnet.exe" test
```

A `global.json` would not help: it can only make the "SDK not found" error stricter.

## Git

The repo has **no configured identity**, so a bare `git commit` fails. Pass it explicitly:

```
git -c user.name="Marin Kitagawa" -c user.email="49131888+Marin-Kitagawa@users.noreply.github.com" commit
```

The email is the GitHub-provided privacy address; using it is what makes commits link to the
account. There is no remote configured and nothing has been pushed.

`core.autocrlf=true` is set, so committed text is LF-normalised and the working copy is CRLF.
This is expected — it is not a line-ending bug to fix.

## Project

- `Palisade` is a C# port of `hardentools` (Go, Security Without Borders, **GPLv3**). Every
  `.cs` file carries the GPL header retaining `Copyright (C) 2017-2023 Security Without Borders`.
- The upstream Go source at `C:\Users\Ahri\Projects\hardentools` is the **authority** for
  measure data, registry paths, hardened values and saved-state formats. Read it rather than
  inferring from the C# side.
- `Palisade.Core` must never reference Avalonia. It holds every security-critical operation and
  is tested entirely against an in-memory registry hive.
- **No test may open a real registry key.** This is enforced by the `IRegistry` abstraction, not
  by convention.
- Saved state must stay byte-compatible with the Go tool under
  `HKCU\SOFTWARE\Security Without Borders\`, so a machine hardened by either tool restores with
  the other. Two spellings are byte-compat surfaces and must not be "corrected":
  - root tokens are `CLASSES_ROOT`, `CURRENT_USER`, `LOCAL_MACHINE`, `USERS`,
    `CURRENT_CONFIG`, `PERFORMANCE_DATA` — **not** `HKCR`/`HKCU` abbreviations
  - the Recall `MeasureId` is lowercase `recall` (`recall_feature.go:50`), while the Windows
    optional feature name `Recall` passed to PowerShell is a separate value
- `Recall`'s lowercase id and the six root tokens are the two places where a "cleaner" spelling
  would silently break cross-tool restore.

## Working agreements

- The design spec is `docs/superpowers/specs/2026-09-26-palisade-design.md`; the active
  implementation plan is `docs/superpowers/plans/2026-09-26-palisade-core.md`. The plan is
  amended as rulings are made — read it, do not work from memory of it.
- `Mechanism`-family enums and handler contracts are pinned in the plan. Changing a pinned
  signature means checking every task that consumes it.
- When a plan requirement cannot be implemented as written, stop and escalate rather than
  guessing. A Task 2 implementer doing exactly that is what caught a defect where the
  `26/12/14/8` count tests would have passed while 10 of 26 measures silently lost their
  registry payloads.
