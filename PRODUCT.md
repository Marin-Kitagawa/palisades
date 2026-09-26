# Product

<!-- impeccable:product-schema 1 -->

## Platform

desktop — Windows 11 is the only supported target; the app is a portable single-folder executable with no installer and no MSIX, and runs per-user-account. Not cross-platform: every measure it applies is a Windows registry or file-association change.

## Stack

Chosen by the user after an explicit comparison. C# / .NET 10 with **Avalonia 12.1.3** (not WinUI 3) for the reasons confirmed: portable distribution without MSIX, headless unit-testable UI, and full custom styling control. CommunityToolkit.Mvvm 8.4.2 for MVVM. xunit + Avalonia.Headless for tests. `Microsoft.Win32.Registry` for registry access — no third-party registry library. Solution layout: `Palisade.Core` (no Avalonia reference, owns all security-critical behavior), `Palisade.App`, `Palisade.Cli`, plus `Palisade.Core.Tests` and `Palisade.App.Tests`.

## Users

**Individuals at risk** — the exact audience the original project named: people who want an extra level of security at the price of some usability, and who are not part of a corporate IT department that manages this through Group Policy. They are technically capable enough to run an unverified executable they downloaded from GitHub, and they accept documentation-driven risk.

Secondary audience, confirmed from the original project's own framing: technical support helpers and journalists/activists/researchers who harden a machine in front of a high-risk audience.

Explicitly **not** the audience: corporate environments, managed enterprise fleets, or users who expect the tool to protect them from malware.

## Product Purpose

Reduce the Windows attack surface by disabling low-hanging-fruit features that are useless to regular users but are routinely abused to execute malicious code — Windows Script Host, Office macros and DDE, Adobe Reader JavaScript and auto-actions, PowerShell from Office documents, LSA protection, ASR rules, Recall, and similar.

Success means the user understands precisely which usability features they gave up, has a working one-click path back if a given trade-off turns out to be unacceptable, and can tell at a glance which measures are currently applied to their account.

## Positioning

The distinguishing mechanism is **reversible, per-user-account, and self-documenting**: every change is recorded so it can be reverted exactly, changes are scoped to the signed-in account rather than machine-wide, and the app states the concrete cost of each measure ("complex Excel calculations stop working") rather than abstract risk scores.

The original project is explicit about what it is not, and that honesty is the positioning: **Palisade is not an antivirus.** It does not identify, block, or remove malware. It does not prevent software from being exploited. It does not prevent its own changes from being reverted by malicious code that runs with the user's privileges — the premise is defeated if that happens.

## Operating Context

- Launched by double-click. Depending on privileges the user is offered UAC elevation; declining it still allows a subset of measures against the current user account.
- The main flow is: read what will change → confirm → apply → restart when prompted. A reboot is required for the full effect of several measures.
- Re-running after hardening offers **Harden again (all defaults)** — which restores then re-applies from defaults, so a newer version's measures are fully in effect — and **Restore**, which reverts to the recorded original state.
- **Expert settings** exposes per-measure checkboxes for users who want to select or deselect individual measures. The original project's warning is preserved: only use this if you know what you are doing.
- Changes are exclusively contextual to the Windows user account that ran the tool. Hardening other accounts means running it once from each.
- ASR rule measures can fail if Windows Defender antivirus is disabled or a third-party AV is installed. This is a documented, user-actionable failure, not a crash.
- The complete list of changes is documented on the upstream project wiki; the app is the interactive form of that documentation, and per-measure detail panes are the in-app equivalent.

## Capabilities and Constraints

**Confirmed capabilities:**

- 26 hardening measures, each independently detectable, applicable, and restorable.
- Privilege split: measures that work at standard user privilege versus those requiring elevation.
- Five underlying mechanisms cover all 26: registry DWORD, registry string, versioned Office/Adobe path expansion, `DisallowRun`, file association, and PowerShell execution policy.
- Detect current state, apply a selection, restore, and re-apply defaults.
- CLI parity: `-harden` and `-restore` with default settings, for machines where the GUI cannot start.
- First-run warning step that states the concrete consequences before any write occurs, confirmed by the user.

**Technical constraints:**

- Must remain **GPLv3** and credit Security Without Borders; this is a port of their project.
- Pure C#. No Go runtime, no Fyne, no embedded webview.
- Registry state written by the Go original must be readable and restorable, byte-compatible, at `HKCU\SOFTWARE\Security Without Borders\`.
- Deliberate bug fixes over bug-for-bug reproduction: file-association `IsHardened` was broken; `DisallowRun` handle lifetime was unsafe; ASR state restoration was inexact; restore ordering was not deterministic; legacy saved-state parsing was unguarded; `markStatus` errors were silently swallowed; the Go tool called `os.Exit` after operations; label text did not wrap.
- Office/Adobe version patterns must be expanded into concrete descriptors before being applied, not passed through as wildcards.

**Scope expansion (user decision, 2026-09-26):** the RyTuneX feature set — approximately 185 tuning toggles, 7 system modules, a policy scanner, and a repair facility — now ships **in this app** rather than as later sub-projects. It arrives as the `Palisade.Tuning` port (logic only, no WinUI), surfaced as separate navigation pages against the same visual world. The 26 hardening measures remain the core; the hardening state engine keeps its byte-compatibility contract, and the tuning modules are held to the same reversibility discipline where the upstream RyTuneX records original values.

## Brand Commitments

- Name: **Palisade**, chosen by the user over keeping the Hardentools name, on the reasoning that a broader suite deserves a broader name.
- License and attribution are non-negotiable: GPLv3, original authors Claudio Guarnieri, Mariano Graziano, and Florian Probst, Security Without Borders, with the upstream project and wiki linked as the source of the measure list.
- The upstream hammer icon by Travis Avery from the Noun Project is available in the source tree. Any icon use must preserve that credit.
- Voice: plain, concrete, and unsensational. States what breaks, in the user's own applications, by name. No fear language, no security-theater claims, no invented reassurance.

## Evidence on Hand

- `C:\Users\Ahri\Projects\hardentools\` — the complete Go source of the upstream project, 26 subject implementations, the registry state engine, the GUI, and the CLI. Authoritative for behavior.
- Upstream wiki — the documented complete list of changes, referenced by the upstream README.
- `C:\Users\Ahri\Projects\hardentools\graphics\` — screenshots of the incumbent Fyne UI, including the admin-privileges prompt, main window, expert settings, and the already-hardened state.
- `C:\Users\Ahri\Projects\RyTuneX\` — 1.3 MB WinUI 3 source for the future sub-projects; ~452 KB of it is UI-independent logic that can be reused.
- `C:\Users\Ahri\Documents\Default Project\CardVault\`, `AsciiFolio\`, `NvimManager\`, `PerformanceTweaks\` — the user's existing local projects and the conventions to match.

**Absences future work must not fabricate:** no user testimonials, no adoption numbers, no benchmark data, no press, no security-audit claims. There is no evidence anyone has validated Palisade against malware; it must not imply otherwise.

## Product Principles

1. **Reversibility is the product.** A hardening change that cannot be undone exactly is a bug, not a limitation. This is why byte-compatible state and deterministic restore order are architectural commitments rather than implementation details.
2. **Say the cost out loud.** Every measure names what stops working in the user's actual applications. Abstract risk language is a failure to communicate.
3. **Scope changes to the account.** Never silently widen to machine-wide or other users' settings.
4. **Refuse to impersonate protection.** The not-an-antivirus boundary is stated in the app, not just the README, because a security tool that implies protection it cannot deliver causes harm.
5. **Expert means expert.** Default paths are safe and one-click; per-measure control is available but gated behind an explicit acknowledgment.

## Accessibility & Inclusion

Keyboard-complete operation for every action, including per-measure selection, apply, and restore. No information conveyed by color alone — each measure's applied/not-applied/unavailable state is carried by text and an icon as well as color. Text must wrap rather than truncate, since the primary content is explanatory prose. Sufficient contrast for body text and for the state colors in both themes.
