; Installateur AntiDDoS (Inno Setup 6)
#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif

[Setup]
AppId={{381242A1-CD05-49C1-9CC9-68412C480EBC}
AppName=AntiDDoS
AppVersion={#AppVersion}
AppPublisher=AntiDDoS
DefaultDirName={autopf}\AntiDDoS
DefaultGroupName=AntiDDoS
OutputDir=installer_output
OutputBaseFilename=AntiDDoS-Setup
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\AntiDDoS.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
DisableProgramGroupPage=yes

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "desktopicon"; Description: "Créer un raccourci sur le Bureau"; GroupDescription: "Raccourcis :"

[Files]
Source: "dist\AntiDDoS.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\AntiDDoS"; Filename: "{app}\AntiDDoS.exe"
Name: "{autodesktop}\AntiDDoS"; Filename: "{app}\AntiDDoS.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\AntiDDoS.exe"; Description: "Lancer AntiDDoS maintenant"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Retire les règles de pare-feu (AntiDDoS-Block et -1 à -7) si l'application a été tuée sans s'arrêter proprement
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=AntiDDoS-Block"; Flags: runhidden; RunOnceId: "DelFwRule"
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=AntiDDoS-Block-1"; Flags: runhidden; RunOnceId: "DelFwRule1"
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=AntiDDoS-Block-2"; Flags: runhidden; RunOnceId: "DelFwRule2"
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=AntiDDoS-Block-3"; Flags: runhidden; RunOnceId: "DelFwRule3"
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=AntiDDoS-Block-4"; Flags: runhidden; RunOnceId: "DelFwRule4"
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=AntiDDoS-Block-5"; Flags: runhidden; RunOnceId: "DelFwRule5"
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=AntiDDoS-Block-6"; Flags: runhidden; RunOnceId: "DelFwRule6"
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=AntiDDoS-Block-7"; Flags: runhidden; RunOnceId: "DelFwRule7"
