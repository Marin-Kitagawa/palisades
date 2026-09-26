# Measure applications — versioned-path templates

The authoritative table for every measure the `VersionedPath` mechanism expands,
transcribed from the Go source. `VersionedPathHandler` reads nothing from this file at
runtime; it is the audit record, and each entry cites the Go file and lines it came from.
Paths are below `HKEY_CURRENT_USER` unless a root column says otherwise.

Upstream version and app lists, verbatim (`office.go:19-26`, `adobe.go:25-31`):

```
standardOfficeVersions = {12.0, 14.0, 15.0, 16.0}   // 2007, 2010, 2013, 2016/2019/365
standardAdobeVersions  = {DC, 2020, XI}
standardOfficeApps     = {Excel, PowerPoint, Word}  // Outlook, Publisher, Access are not hardened upstream
```

## Office (all `office.go`)

| Measure | Template | Value | Hardened | Versions | Apps | Source |
|---|---|---|---|---|---|---|
| OfficeOle | `SOFTWARE\Microsoft\Office\%s\%s\Security` | `PackagerPrompt` | `2` | standardOfficeVersions | standardOfficeApps | `office.go:50-63` |
| OfficeMacros | `SOFTWARE\Microsoft\Office\%s\%s\Security` | `VBAWarnings` | `4` | standardOfficeVersions | standardOfficeApps | `office.go:65-78` |
| OfficeDde (AllowDDE) | `Software\Microsoft\Office\%s\%s\Security` | `AllowDDE` | `0` | 14.0, 15.0, 16.0 | Word | `office.go:154-166` |
| OfficeDde (WorkbookLinkWarnings) | `Software\Microsoft\Office\%s\%s\Security` | `WorkbookLinkWarnings` | `2` | standardOfficeVersions | Excel | `office.go:247-255` |
| OfficeDde (DontUpdateLinks) | `SOFTWARE\Microsoft\Office\%s\%s\Options` | `DontUpdateLinks` | `1` | 14.0, 15.0, 16.0 | Word, Excel | `office.go:260-272` |
| OfficeDde (DontUpdateLinks, WordMail) | `SOFTWARE\Microsoft\Office\%s\%s\Options\WordMail` | `DontUpdateLinks` | `1` | 14.0, 15.0, 16.0 | Word | `office.go:273-285` |
| OfficeDde (fixed path) | `Software\Microsoft\Office\12.0\Word\Options\vpref` | `fNoCalclinksOnopen_90_1` | `1` | none — no `%s` | none | `office.go:286-292` |

The DDE measure writes 17 values upstream: 3 + 4 + 6 + 3 + 1. The per-target
`AppFilter`/`VersionFilter` narrowing in the catalog reproduces exactly those 17.

Office 2007's `fNoCalclinksOnopen_90_1` is the fixed-path case: it carries no `%s`, so it
resolves to exactly one target regardless of what is installed (`office.go:286-292`).

## OneNote (`onenote.go:18-31`)

| Measure | Template | Value | Hardened | Versions | Apps |
|---|---|---|---|---|---|
| OneNoteBlockExtensions | `SOFTWARE\Microsoft\Office\%s\%s\Options` | `DisableEmbeddedFiles` | `1` | standardOfficeVersions | `onenote` |

## Adobe (all `adobe.go`)

| Measure | Template | Value | Hardened | Versions |
|---|---|---|---|---|
| AdobeJavaScript | `SOFTWARE\Adobe\Acrobat Reader\%s\JSPrefs` | `bEnableJS` | `0` | standardAdobeVersions |
| AdobeEmbeddedObjects | `SOFTWARE\Adobe\Acrobat Reader\%s\Originals` | `bAllowOpenFile` | `0` | standardAdobeVersions |
| AdobeEmbeddedObjects | `SOFTWARE\Adobe\Acrobat Reader\%s\Originals` | `bSecureOpenFile` | `1` | standardAdobeVersions |
| AdobeProtectedMode | `SOFTWARE\Adobe\Acrobat Reader\%s\Privileged` | `bProtectedMode` | `1` | standardAdobeVersions |
| AdobeProtectedView | `SOFTWARE\Adobe\Acrobat Reader\%s\TrustManager` | `iProtectedView` | `1` | standardAdobeVersions |
| AdobeEnhancedSecurity | `SOFTWARE\Adobe\Acrobat Reader\%s\TrustManager` | `bEnhancedSecurityInBrowser` | `1` | standardAdobeVersions |
| AdobeEnhancedSecurity | `SOFTWARE\Adobe\Acrobat Reader\%s\TrustManager` | `bEnhancedSecurityStandalone` | `1` | standardAdobeVersions |

## Discovery

Upstream formats the templates over the fixed lists above, whether or not the product is
installed. Palisade discovers what is installed — program-file directories (including the
Click-to-Run `root\OfficeNN` layout) and the standard version registry keys — and falls
back to the standard lists when it can prove nothing, which is upstream's own behaviour.
The zero-resolution failure contract lives in `VersionedPathHandler.Resolve` and is
exercised with an injected empty resolver.
