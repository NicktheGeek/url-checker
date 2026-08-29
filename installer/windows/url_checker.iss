; Inno Setup script for the URL Checker Windows installer, built by
; .github/workflows/release-installers.yml against the PyInstaller onedir
; output at dist/URL Checker/.
;
; Compile with (from the repo root):
;   ISCC /DMyAppVersion=1.2.3 installer\windows\url_checker.iss
;
; AppId below is fixed permanently -- it's what lets a newer release's
; installer be recognized as an upgrade of the same product (same
; Add/Remove Programs entry, same install path) rather than a duplicate
; install. Never change it after the first real release ships.
#define MyAppName "URL Checker"
#ifndef MyAppVersion
  #define MyAppVersion "0.0.0-dev"
#endif
#define MyAppPublisher "Nick Croft"
#define MyAppExeName "URL Checker.exe"

[Setup]
AppId={{4D7BA281-73F8-4015-A5B7-3B16D91FFB93}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=output
OutputBaseFilename=URL-Checker-Setup
SetupIconFile=..\..\static\icons\app.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible

[Files]
Source: "..\..\dist\URL Checker\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; Flags: unchecked
