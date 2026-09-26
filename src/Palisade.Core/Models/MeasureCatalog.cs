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

namespace Palisade.Core.Models;

/// <summary>
/// The 26 measures, transcribed from the Go source as data. The split and the order of
/// the two blocks follow <c>global_vars.go</c>: <c>hardenSubjectsForUnprivilegedUsers</c>
/// (12) and then the 14 that <c>hardenSubjectsForPrivilegedUsers</c> adds.
/// </summary>
public static class MeasureCatalog
{
    private const string DwordKind = "Dword";
    private const string StringKind = "String";

    private const string OfficeVersions = "12.0,14.0,15.0,16.0";
    private const string AdobeVersions = "DC,2020,XI";
    private const string OfficeApps = "Excel,PowerPoint,Word";
    private const string DdeApps = "Excel,Word";
    private const string DdeWordApp = "Word";
    private const string DdeExcelApp = "Excel";

    // Office 2007 is in the discovery universe but upstream scopes every DDE sub-value that
    // is not WorkbookLinkWarnings to 2010 and later.
    private const string DdeModernVersions = "14.0,15.0,16.0";
    private const string OneNoteApp = "onenote";
    private const string CmdApps = "cmd.exe";
    private const string PowerShellApps = "powershell_ise.exe,powershell.exe";

    // office.go:28 spells the Office security template "SOFTWARE"; office.go:143 spells the
    // same template "Software" for the DDE measure. Both are transcribed as upstream has
    // them; the registry itself is case-insensitive, and saved state carries the path it
    // was written with, so neither spelling is load-bearing.
    private const string OfficeSecurityPathTemplate = @"SOFTWARE\Microsoft\Office\%s\%s\Security";
    private const string OfficeDdeSecurityPathTemplate = @"Software\Microsoft\Office\%s\%s\Security";
    private const string OfficeOptionsPathTemplate = @"SOFTWARE\Microsoft\Office\%s\%s\Options";
    private const string OfficeWordMailPathTemplate = @"SOFTWARE\Microsoft\Office\%s\%s\Options\WordMail";
    private const string OfficeWord2007Path = @"Software\Microsoft\Office\12.0\Word\Options\vpref";
    private const string OfficeCommonSecurityPath = @"SOFTWARE\Microsoft\Office\Common\Security";
    private const string AcrobatJsPrefsPathTemplate = @"SOFTWARE\Adobe\Acrobat Reader\%s\JSPrefs";
    private const string AcrobatOriginalsPathTemplate = @"SOFTWARE\Adobe\Acrobat Reader\%s\Originals";
    private const string AcrobatPrivilegedPathTemplate = @"SOFTWARE\Adobe\Acrobat Reader\%s\Privileged";
    private const string AcrobatTrustManagerPathTemplate = @"SOFTWARE\Adobe\Acrobat Reader\%s\TrustManager";
    private const string ExplorerAdvancedPath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
    private const string ExplorerPoliciesPath = @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";
    private const string AutoplayHandlersPath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers";
    private const string SystemPoliciesPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    private const string WindowsScriptHostSettingsPath = @"SOFTWARE\Microsoft\Windows Script Host\Settings";
    private const string LsaPath = @"SYSTEM\CurrentControlSet\Control\Lsa";
    private const string DefenderPolicyPath = @"SOFTWARE\Policies\Microsoft\Windows Defender";
    private const string DefenderMpEnginePolicyPath = @"SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine";
    private const string EdgePolicyPath = @"SOFTWARE\Policies\Microsoft\Edge";
    private const string LibreOfficeScriptingPath = @"SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Common\Security\Scripting";
    private const string LibreOfficeUpdateCheckPath = @"SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Jobs\Jobs\org.openoffice.Office.Jobs:Job['UpdateCheck']\Arguments\AutoCheckEnabled";
    private const string LibreOfficeCheckIntervalPath = @"SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Jobs\Jobs\org.openoffice.Office.Jobs:Job['UpdateCheck']\Arguments\CheckInterval";
    private const string LibreOfficeCalcLinkPath = @"SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Calc\Content\Update\Link";
    private const string LibreOfficeWriterLinkPath = @"SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Writer\Content\Update\Link";

    private static readonly IReadOnlyDictionary<string, string> NoSettings = new Dictionary<string, string>();
    private static readonly IReadOnlyDictionary<string, string> NoArguments = new Dictionary<string, string>();
    private static readonly IReadOnlyList<MeasureTarget> NoTargets = Array.Empty<MeasureTarget>();
    private static readonly IReadOnlyList<MeasureConstraint> NoConstraints = Array.Empty<MeasureConstraint>();

    private static readonly AvailabilityRule WindowsFeatureAbsent = new(
        "windows_feature_absent",
        NoArguments,
        "This feature is not available in this build of Windows, so there is nothing for this measure to harden.");

    private static readonly AvailabilityRule OfficeNotInstalled = new(
        "product_not_installed",
        NoArguments,
        "Microsoft Office was not found on this machine, so there is nothing for this measure to harden.");

    private static readonly AvailabilityRule OneNoteNotInstalled = new(
        "product_not_installed",
        NoArguments,
        "OneNote was not found on this machine, so there is nothing for this measure to harden.");

    private static readonly AvailabilityRule AdobeNotInstalled = new(
        "product_not_installed",
        NoArguments,
        "Adobe Acrobat Reader was not found on this machine, so there is nothing for this measure to harden.");

    private static readonly AvailabilityRule LibreOfficeNotInstalled = new(
        "product_not_installed",
        NoArguments,
        "LibreOffice was not found on this machine, so there is nothing for this measure to harden.");

    private static readonly AvailabilityRule WindowsDefenderDisabled = new(
        "windows_defender_disabled",
        NoArguments,
        "Windows Defender is not running on this machine, so this setting cannot be applied.");

    private static readonly AvailabilityRule DdeNotSupported = new(
        "dde_not_supported",
        NoArguments,
        "The installed version of Office does not support Dynamic Data Exchange, so there is nothing for this measure to harden.");

    private static readonly AvailabilityRule RecallFeatureAbsent = new(
        "windows_feature_absent",
        NoArguments,
        "Recall is not available in this build of Windows, so there is nothing for this measure to harden.");

    private static readonly MeasureDescriptor Wsh = new(
        new MeasureId("Wsh"),
        "WSH",
        "Windows Script Host",
        "You will not be able to run .vbs, .vbe, .js and .wsf scripts, and installers and logon scripts that rely on them will stop working.",
        Mechanism.RegistryDword,
        RequiresElevation: false,
        HardenByDefault: true,
        MeasureGroup.Windows,
        NoSettings,
        [Dword(RegistryRoot.CurrentUser, WindowsScriptHostSettingsPath, "Enabled", "0")],
        NoConstraints,
        [WindowsFeatureAbsent]);

    private static readonly MeasureDescriptor OfficeOle = new(
        new MeasureId("OfficeOle"),
        "Office OLE",
        "Office Packager Objects (OLE)",
        "Documents that embed another file as an OLE object will no longer open that object in Excel, PowerPoint or Word.",
        Mechanism.VersionedPath,
        RequiresElevation: false,
        HardenByDefault: true,
        MeasureGroup.MicrosoftOffice,
        Settings(officeVersions: OfficeVersions, apps: OfficeApps),
        [Dword(RegistryRoot.CurrentUser, OfficeSecurityPathTemplate, "PackagerPrompt", "2")],
        NoConstraints,
        [OfficeNotInstalled]);

    private static readonly MeasureId OfficeMacrosId = new("OfficeMacros");

    private static readonly MeasureDescriptor OfficeMacros = new(
        OfficeMacrosId,
        "Office Macros",
        "Office Macros",
        "Macros will not run in Excel, PowerPoint, or Word. Documents that rely on macros will not work.",
        Mechanism.VersionedPath,
        RequiresElevation: false,
        HardenByDefault: true,
        MeasureGroup.MicrosoftOffice,
        Settings(officeVersions: OfficeVersions, apps: OfficeApps),
        [Dword(RegistryRoot.CurrentUser, OfficeSecurityPathTemplate, "VBAWarnings", "4")],
        NoConstraints,
        [OfficeNotInstalled]);

    private static readonly MeasureDescriptor OfficeActiveX = new(
        new MeasureId("OfficeActiveX"),
        "Office ActiveX",
        "Office ActiveX",
        "Add-ins and forms that use ActiveX will stop working in Excel, PowerPoint or Word.",
        Mechanism.RegistryDword,
        RequiresElevation: false,
        HardenByDefault: true,
        MeasureGroup.MicrosoftOffice,
        NoSettings,
        [Dword(RegistryRoot.CurrentUser, OfficeCommonSecurityPath, "DisableAllActiveX", "1")],
        NoConstraints,
        [OfficeNotInstalled]);

    private static readonly MeasureDescriptor OfficeDde = new(
        new MeasureId("OfficeDde"),
        "Office DDE",
        "Office DDE Mitigations",
        "Excel workbooks and Word documents that pull live data from other files will no longer update that data when you open them. You can still update a field by hand from its right-click menu.",
        Mechanism.VersionedPath,
        RequiresElevation: false,
        HardenByDefault: true,
        MeasureGroup.MicrosoftOffice,
        Settings(officeVersions: OfficeVersions, apps: DdeApps),
        [
            // office.go:154-166: Word only, and 2010 and later.
            Dword(RegistryRoot.CurrentUser, OfficeDdeSecurityPathTemplate, "AllowDDE", "0", DdeWordApp, DdeModernVersions),
            // office.go:247-255: Excel only, on the full standard version list.
            Dword(RegistryRoot.CurrentUser, OfficeDdeSecurityPathTemplate, "WorkbookLinkWarnings", "2", DdeExcelApp),
            // office.go:260-272: Word and Excel, 2010 and later.
            Dword(RegistryRoot.CurrentUser, OfficeOptionsPathTemplate, "DontUpdateLinks", "1", DdeApps, DdeModernVersions),
            // office.go:273-285: Word only, 2010 and later. Outlook is reached through Word's
            // WordMail branch, so the app in the path is still Word.
            Dword(RegistryRoot.CurrentUser, OfficeWordMailPathTemplate, "DontUpdateLinks", "1", DdeWordApp, DdeModernVersions),
            // office.go:286-292: a fixed Office 2007 path with no version or app expansion.
            Dword(RegistryRoot.CurrentUser, OfficeWord2007Path, "fNoCalclinksOnopen_90_1", "1"),
        ],
        [new MeasureConstraint(OfficeMacrosId, "Both measures are policy values in the same Office version branch, so macros are restored first and the DDE mitigations afterwards, which keeps a partly expanded version branch from reading as a complete restore.")],
        [OfficeNotInstalled, DdeNotSupported]);

    private static readonly MeasureDescriptor AdobeJavaScript = new(
        new MeasureId("AdobeJavaScript"),
        "Adobe JavaScript",
        "Acrobat Reader JavaScript",
        "PDF documents that use JavaScript will open, but their scripts will no longer run.",
        Mechanism.VersionedPath,
        RequiresElevation: false,
        HardenByDefault: true,
        MeasureGroup.Adobe,
        Settings(adobeVersions: AdobeVersions),
        [Dword(RegistryRoot.CurrentUser, AcrobatJsPrefsPathTemplate, "bEnableJS", "0")],
        NoConstraints,
        [AdobeNotInstalled]);

    private static readonly MeasureDescriptor AdobeEmbeddedObjects = new(
        new MeasureId("AdobeEmbeddedObjects"),
        "Adobe Objects",
        "Acrobat Reader Embedded Objects",
        "PDF documents that carry embedded files will no longer open those files, and Acrobat Reader will refuse to save a PDF that has attachments.",
        Mechanism.VersionedPath,
        RequiresElevation: false,
        HardenByDefault: true,
        MeasureGroup.Adobe,
        Settings(adobeVersions: AdobeVersions),
        [
            Dword(RegistryRoot.CurrentUser, AcrobatOriginalsPathTemplate, "bAllowOpenFile", "0"),
            Dword(RegistryRoot.CurrentUser, AcrobatOriginalsPathTemplate, "bSecureOpenFile", "1"),
        ],
        NoConstraints,
        [AdobeNotInstalled]);

    private static readonly MeasureDescriptor AdobeProtectedMode = new(
        new MeasureId("AdobeProtectedMode"),
        "Adobe Protected Mode",
        "Acrobat Reader Protected Mode",
        "Very little changes: Protected Mode is already enabled in current Acrobat Reader versions, so you will only notice a difference on an old or customised installation.",
        Mechanism.VersionedPath,
        RequiresElevation: false,
        HardenByDefault: true,
        MeasureGroup.Adobe,
        Settings(adobeVersions: AdobeVersions),
        [Dword(RegistryRoot.CurrentUser, AcrobatPrivilegedPathTemplate, "bProtectedMode", "1")],
        NoConstraints,
        [AdobeNotInstalled]);

    private static readonly MeasureDescriptor AdobeProtectedView = new(
        new MeasureId("AdobeProtectedView"),
        "Adobe Protected View",
        "Acrobat Reader Protected View",
        "PDF documents that come from email, the web or any other untrusted source will open in Protected View, where most features stay disabled until you click Enable All Features.",
        Mechanism.VersionedPath,
        RequiresElevation: false,
        HardenByDefault: true,
        MeasureGroup.Adobe,
        Settings(adobeVersions: AdobeVersions),
        [Dword(RegistryRoot.CurrentUser, AcrobatTrustManagerPathTemplate, "iProtectedView", "1")],
        NoConstraints,
        [AdobeNotInstalled]);

    private static readonly MeasureDescriptor AdobeEnhancedSecurity = new(
        new MeasureId("AdobeEnhancedSecurity"),
        "Adobe Enhanced Security",
        "Acrobat Reader Enhanced Security",
        "Very little changes: enhanced security is already enabled in current Acrobat Reader versions, so only PDF documents that deliberately rely on JavaScript are affected.",
        Mechanism.VersionedPath,
        RequiresElevation: false,
        HardenByDefault: true,
        MeasureGroup.Adobe,
        Settings(adobeVersions: AdobeVersions),
        [
            Dword(RegistryRoot.CurrentUser, AcrobatTrustManagerPathTemplate, "bEnhancedSecurityInBrowser", "1"),
            Dword(RegistryRoot.CurrentUser, AcrobatTrustManagerPathTemplate, "bEnhancedSecurityStandalone", "1"),
        ],
        NoConstraints,
        [AdobeNotInstalled]);

    private static readonly MeasureDescriptor ShowFileExtensions = new(
        new MeasureId("ShowFileExtensions"),
        "Show File Ext",
        "Show File Extensions",
        "You will start seeing file extensions such as .exe and .doc on every file in File Explorer.",
        Mechanism.RegistryDword,
        RequiresElevation: false,
        HardenByDefault: true,
        MeasureGroup.Windows,
        NoSettings,
        [
            Dword(RegistryRoot.CurrentUser, ExplorerAdvancedPath, "HideFileExt", "0"),
            Dword(RegistryRoot.CurrentUser, ExplorerAdvancedPath, "Hidden", "1"),
            Dword(RegistryRoot.CurrentUser, ExplorerAdvancedPath, "ShowSuperHidden", "1"),
        ],
        NoConstraints,
        [WindowsFeatureAbsent]);

    private static readonly MeasureDescriptor OneNoteBlockExtensions = new(
        new MeasureId("OneNoteBlockExtensions"),
        "OneNote Attachments",
        "Block OneNote Attachments",
        "You will not be able to open a file attached to a OneNote page any more.",
        Mechanism.VersionedPath,
        RequiresElevation: false,
        HardenByDefault: true,
        MeasureGroup.OneNote,
        Settings(officeVersions: OfficeVersions, apps: OneNoteApp),
        [Dword(RegistryRoot.CurrentUser, OfficeOptionsPathTemplate, "DisableEmbeddedFiles", "1")],
        NoConstraints,
        [OneNoteNotInstalled]);

    private static readonly MeasureDescriptor Autorun = new(
        new MeasureId("Autorun"),
        "Autorun",
        "AutoRun and AutoPlay",
        "CDs, DVDs and USB drives will no longer start a program or an installer when you open or double-click them. You will still have to start the program yourself.",
        Mechanism.RegistryDword,
        RequiresElevation: true,
        HardenByDefault: true,
        MeasureGroup.Windows,
        NoSettings,
        [
            Dword(RegistryRoot.CurrentUser, ExplorerPoliciesPath, "NoDriveTypeAutoRun", "181"),
            Dword(RegistryRoot.CurrentUser, ExplorerPoliciesPath, "NoAutorun", "1"),
            Dword(RegistryRoot.CurrentUser, AutoplayHandlersPath, "DisableAutoplay", "1"),
        ],
        NoConstraints,
        [WindowsFeatureAbsent]);

    private static readonly MeasureId PowerShellId = new("PowerShell");

    private static readonly MeasureDescriptor PowerShell = new(
        PowerShellId,
        "PowerShell",
        "Disable PowerShell",
        "PowerShell and the PowerShell ISE will not start, and any installer or Office document that relies on PowerShell will fail. Most administration scripts will stop working.",
        Mechanism.DisallowRun,
        RequiresElevation: true,
        HardenByDefault: true,
        MeasureGroup.Windows,
        Settings(apps: PowerShellApps),
        NoTargets,
        NoConstraints,
        [WindowsFeatureAbsent]);

    private static readonly MeasureDescriptor Cmd = new(
        new MeasureId("Cmd"),
        "Disable cmd.exe",
        "Disable cmd.exe",
        "You will not be able to open the Windows command prompt (cmd.exe) any more.",
        Mechanism.DisallowRun,
        RequiresElevation: true,
        HardenByDefault: false,
        MeasureGroup.Windows,
        Settings(apps: CmdApps),
        NoTargets,
        [new MeasureConstraint(PowerShellId, "Both measures add entries to the same Explorer DisallowRun list, so the PowerShell entries are restored first and the shared list is never renumbered while this measure is still applied.")],
        [WindowsFeatureAbsent]);

    private static readonly MeasureDescriptor Uac = new(
        new MeasureId("Uac"),
        "UAC",
        "User Account Control",
        "Windows will ask for an administrator password on the secure desktop for every change to system settings, including installing programs.",
        Mechanism.RegistryDword,
        RequiresElevation: true,
        HardenByDefault: true,
        MeasureGroup.Windows,
        NoSettings,
        [
            Dword(RegistryRoot.LocalMachine, SystemPoliciesPath, "ConsentPromptBehaviorAdmin", "3"),
            Dword(RegistryRoot.LocalMachine, SystemPoliciesPath, "PromptOnSecureDesktop", "1"),
            Dword(RegistryRoot.LocalMachine, SystemPoliciesPath, "EnableLUA", "1"),
        ],
        NoConstraints,
        [WindowsFeatureAbsent]);

    private static readonly MeasureDescriptor FileAssociations = new(
        new MeasureId("FileAssociations"),
        "File Associations",
        "File associations",
        "Double-clicking a .hta, .js, .JSE, .WSH, .WSF, .scf, .scr, .vbs, .VBE, .pif or .mht file in File Explorer will no longer open it.",
        Mechanism.FileAssociation,
        RequiresElevation: true,
        HardenByDefault: true,
        MeasureGroup.Windows,
        NoSettings,
        NoTargets,
        NoConstraints,
        [WindowsFeatureAbsent]);

    private static readonly MeasureId DefenderPuaId = new("DefenderPua");

    private static readonly MeasureDescriptor WindowsAsrRules = new(
        new MeasureId("WindowsAsrRules"),
        "Windows ASR rules",
        "Windows ASR rules",
        "Office and browser applications that run executable content, such as email attachments, downloaded documents and scripts launched by Office, will be blocked or opened in a reduced mode, and some files from colleagues and sites you rely on will not open at all.",
        Mechanism.NonRegistry,
        RequiresElevation: true,
        HardenByDefault: true,
        MeasureGroup.Windows,
        NoSettings,
        NoTargets,
        [new MeasureConstraint(DefenderPuaId, "Windows Defender is what enforces the ASR rules, so the Defender policy measure is restored first and the rule set is removed afterwards.")],
        [WindowsDefenderDisabled]);

    private static readonly MeasureDescriptor Lsa = new(
        new MeasureId("Lsa"),
        "LSA",
        "LSA Protection",
        "Software that injects code into the Local Security Authority process will stop working, which includes some security tools and some graphics drivers.",
        Mechanism.RegistryDword,
        RequiresElevation: true,
        HardenByDefault: false,
        MeasureGroup.System,
        NoSettings,
        [Dword(RegistryRoot.LocalMachine, LsaPath, "RunAsPPL", "1")],
        NoConstraints,
        [WindowsFeatureAbsent]);

    private static readonly MeasureDescriptor DefenderPua = new(
        DefenderPuaId,
        "PUA Protection",
        "Defender PUA Protection",
        "Programs that Windows Defender or Microsoft Edge class as potentially unwanted will be blocked from downloading and installing, so some free or lightly tested software will no longer install.",
        Mechanism.RegistryDword,
        RequiresElevation: true,
        HardenByDefault: true,
        MeasureGroup.System,
        NoSettings,
        [
            Dword(RegistryRoot.LocalMachine, DefenderPolicyPath, "PUAProtection", "1"),
            Dword(RegistryRoot.LocalMachine, DefenderMpEnginePolicyPath, "MpEnablePus", "1"),
            Dword(RegistryRoot.LocalMachine, EdgePolicyPath, "SmartScreenPuaEnabled", "1"),
        ],
        NoConstraints,
        [WindowsDefenderDisabled]);

    private static readonly MeasureDescriptor LibreOfficeMacroSecurity = new(
        new MeasureId("LibreOfficeMacroSecurity"),
        "LibreOffice Macro Security",
        "LibreOffice Macro Security",
        "No macro will run in LibreOffice any more, not even one from a document in a folder you have marked as trusted. SecureURL is also cleared, which stops LibreOffice from treating remote documents as trusted.",
        Mechanism.RegistryString,
        RequiresElevation: true,
        HardenByDefault: false,
        MeasureGroup.LibreOffice,
        NoSettings,
        [
            Sz(RegistryRoot.LocalMachine, LibreOfficeScriptingPath + @"\MacroSecurityLevel", "Value", "3"),
            Dword(RegistryRoot.LocalMachine, LibreOfficeScriptingPath + @"\MacroSecurityLevel", "Final", "1"),
            Sz(RegistryRoot.LocalMachine, LibreOfficeScriptingPath + @"\SecureURL", "Value", ""),
            Dword(RegistryRoot.LocalMachine, LibreOfficeScriptingPath + @"\SecureURL", "Final", "0"),
        ],
        NoConstraints,
        [LibreOfficeNotInstalled]);

    private static readonly MeasureDescriptor LibreOfficeCtrlClickHyperlinks = new(
        new MeasureId("LibreOfficeCtrlClickHyperlinks"),
        "LibreOffice Ctrl-Click Hyperlinks",
        "LibreOffice Ctrl-Click to follow Hyperlinks",
        "You will have to hold Ctrl while clicking a link in a LibreOffice document to follow it.",
        Mechanism.RegistryString,
        RequiresElevation: true,
        HardenByDefault: false,
        MeasureGroup.LibreOffice,
        NoSettings,
        [
            Sz(RegistryRoot.LocalMachine, LibreOfficeScriptingPath + @"\HyperlinksWithCtrlClick", "Value", "true"),
            Dword(RegistryRoot.LocalMachine, LibreOfficeScriptingPath + @"\HyperlinksWithCtrlClick", "Final", "1"),
        ],
        NoConstraints,
        [LibreOfficeNotInstalled]);

    private static readonly MeasureDescriptor LibreOfficeUntrustedRefererLinks = new(
        new MeasureId("LibreOfficeUntrustedRefererLinks"),
        "LibreOffice Block Untrusted Referer Links",
        "LibreOffice Block Untrusted Referer Links",
        "Images in a LibreOffice document that are loaded from another web page will not appear. Images stored inside the document itself are unaffected.",
        Mechanism.RegistryString,
        RequiresElevation: true,
        HardenByDefault: false,
        MeasureGroup.LibreOffice,
        NoSettings,
        [
            Sz(RegistryRoot.LocalMachine, LibreOfficeScriptingPath + @"\BlockUntrustedRefererLinks", "Value", "true"),
            Dword(RegistryRoot.LocalMachine, LibreOfficeScriptingPath + @"\BlockUntrustedRefererLinks", "Final", "1"),
        ],
        NoConstraints,
        [LibreOfficeNotInstalled]);

    private static readonly MeasureDescriptor LibreOfficeEnforceUpdateChecks = new(
        new MeasureId("LibreOfficeEnforceUpdateChecks"),
        "LibreOffice Enforce Update Checks",
        "LibreOffice Enforce Update Checks",
        "LibreOffice will check for updates every day instead of every week, and you will be reminded about them in the background. The daily interval does not currently take effect through the registry, and it did not work in LibreOffice 7.5.4; the weekly check is disabled regardless.",
        Mechanism.RegistryString,
        RequiresElevation: true,
        HardenByDefault: false,
        MeasureGroup.LibreOffice,
        NoSettings,
        [
            Sz(RegistryRoot.LocalMachine, LibreOfficeUpdateCheckPath, "Value", "true"),
            Dword(RegistryRoot.LocalMachine, LibreOfficeUpdateCheckPath, "Final", "1"),
            Sz(RegistryRoot.LocalMachine, LibreOfficeCheckIntervalPath, "Value", "86400"),
            Dword(RegistryRoot.LocalMachine, LibreOfficeCheckIntervalPath, "Final", "1"),
        ],
        NoConstraints,
        [LibreOfficeNotInstalled]);

    private static readonly MeasureDescriptor LibreOfficeDisableUpdateLinks = new(
        new MeasureId("LibreOfficeDisableUpdateLinks"),
        "LibreOffice Disable Links",
        "LibreOffice Disable Updates from Links",
        "When you open a LibreOffice Writer or Calc document that pulls values from another file, those values will not be loaded until you update the links yourself. LibreOffice honours this policy in Calc but not in Writer as of 7.5.4, so in Writer the setting may have no effect.",
        Mechanism.RegistryString,
        RequiresElevation: true,
        HardenByDefault: false,
        MeasureGroup.LibreOffice,
        NoSettings,
        [
            Sz(RegistryRoot.LocalMachine, LibreOfficeCalcLinkPath, "Value", "1"),
            Dword(RegistryRoot.LocalMachine, LibreOfficeCalcLinkPath, "Final", "1"),
            Sz(RegistryRoot.LocalMachine, LibreOfficeWriterLinkPath, "Value", "1"),
            Dword(RegistryRoot.LocalMachine, LibreOfficeWriterLinkPath, "Final", "1"),
        ],
        NoConstraints,
        [LibreOfficeNotInstalled]);

    private static readonly MeasureDescriptor Recall = new(
        new MeasureId("recall"),
        "Recall Windows Feature",
        "Recall Windows Feature",
        "Windows Recall, which keeps a searchable history of everything you see on screen and stores it on this machine, will be removed together with its snapshots.",
        Mechanism.NonRegistry,
        RequiresElevation: true,
        HardenByDefault: false,
        MeasureGroup.Windows,
        NoSettings,
        NoTargets,
        NoConstraints,
        [RecallFeatureAbsent]);

    public static IReadOnlyList<MeasureDescriptor> All { get; } =
    [
        Wsh,
        OfficeOle,
        OfficeMacros,
        OfficeActiveX,
        OfficeDde,
        AdobeJavaScript,
        AdobeEmbeddedObjects,
        AdobeProtectedMode,
        AdobeProtectedView,
        AdobeEnhancedSecurity,
        ShowFileExtensions,
        OneNoteBlockExtensions,
        Autorun,
        PowerShell,
        Cmd,
        Uac,
        FileAssociations,
        WindowsAsrRules,
        Lsa,
        DefenderPua,
        LibreOfficeMacroSecurity,
        LibreOfficeCtrlClickHyperlinks,
        LibreOfficeUntrustedRefererLinks,
        LibreOfficeEnforceUpdateChecks,
        LibreOfficeDisableUpdateLinks,
        Recall,
    ];

    private static readonly Dictionary<MeasureId, MeasureDescriptor> ById =
        All.ToDictionary(descriptor => descriptor.Id);

    public static MeasureDescriptor Get(MeasureId id) =>
        ById.TryGetValue(id, out var descriptor)
            ? descriptor
            : throw new KeyNotFoundException($"No measure with id '{id.Value}' is in the catalog.");

    public static IReadOnlyList<MeasureDescriptor> InGroup(MeasureGroup group) =>
        All.Where(descriptor => descriptor.Group == group).ToList();

    private static IReadOnlyDictionary<string, string> Settings(
        string? officeVersions = null,
        string? adobeVersions = null,
        string? apps = null)
    {
        var settings = new Dictionary<string, string>(StringComparer.Ordinal);
        if (officeVersions is not null)
        {
            settings["OfficeVersions"] = officeVersions;
        }

        if (adobeVersions is not null)
        {
            settings["AdobeVersions"] = adobeVersions;
        }

        if (apps is not null)
        {
            settings["Apps"] = apps;
        }

        return settings;
    }

    private static MeasureTarget Dword(
        RegistryRoot root,
        string path,
        string valueName,
        string hardenedValue,
        string? appFilter = null,
        string? versionFilter = null) =>
        new(root, path, valueName, DwordKind, hardenedValue, appFilter, versionFilter);

    private static MeasureTarget Sz(
        RegistryRoot root,
        string path,
        string valueName,
        string hardenedValue,
        string? appFilter = null,
        string? versionFilter = null) =>
        new(root, path, valueName, StringKind, hardenedValue, appFilter, versionFilter);
}
