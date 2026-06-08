; SovereignKernel Vault — NSIS Installer Script
; Requires: NSIS 3.x (https://nsis.sourceforge.io)
; Build: makensis sovereignkernel.nsi

!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"
!include "x64.nsh"

; ===== General =====
Name "SovereignKernel Vault"
OutFile "SovereignKernel-Setup.exe"
InstallDir "$PROGRAMFILES64\SovereignKernel"
InstallDirRegKey HKLM "Software\SovereignKernel" "InstallDir"
RequestExecutionLevel admin
Unicode True

; ===== Version Info =====
!define VERSION "0.3.0"
!define PUBLISHER "SovereignKernel"
VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "SovereignKernel Vault"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "CompanyName" "${PUBLISHER}"
VIAddVersionKey "FileDescription" "Hardware-backed Security Vault"
VIAddVersionKey "FileVersion" "${VERSION}.0"
VIAddVersionKey "LegalCopyright" "© 2025 ${PUBLISHER}"

; ===== Interface Settings =====
!define MUI_ABORTWARNING
!define MUI_ICON "..\electron-ui\assets\icon.ico"
!define MUI_UNICON "..\electron-ui\assets\icon.ico"
!define MUI_WELCOMEPAGE_TITLE "Welkom bij SovereignKernel Vault"
!define MUI_WELCOMEPAGE_TEXT "Deze wizard installeert SovereignKernel Vault ${VERSION} op uw computer.$\r$\n$\r$\nKenmerken:$\r$\n• TPM 2.0 hardware-beschermde encryptie$\r$\n• AES-256-GCM versleuteling$\r$\n• Shamir Secret Sharing (3-van-5)$\r$\n• Automatische backups$\r$\n$\r$\nKlik op Volgende om door te gaan."
!define MUI_FINISHPAGE_RUN "$INSTDIR\UI\SovereignKernel.exe"
!define MUI_FINISHPAGE_RUN_TEXT "SovereignKernel UI starten"
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\LEES-MIJ.md"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "Release notes openen"

; ===== Pages =====
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\LICENSE"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; ===== Languages =====
!insertmacro MUI_LANGUAGE "Dutch"

; ===== Installer Sections =====
Section "Windows Service (vereist)" SecService
    SectionIn RO ; Required, cannot deselect

    SetOutPath "$INSTDIR\bin"
    File "..\build\bin\SovereignKernelVault.exe"
    File "..\build\bin\vault-db-tool.exe"

    ; Create data directories with restricted permissions
    CreateDirectory "$COMMONFILES64\SovereignKernel\Data"
    CreateDirectory "$COMMONFILES64\SovereignKernel\Logs"
    CreateDirectory "$COMMONFILES64\SovereignKernel\Data\backups"

    ; Set ACL: SYSTEM + Administrators only
    nsExec::ExecToLog 'icacls "$COMMONFILES64\SovereignKernel" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" /grant:r "Administrators:(OI)(CI)F"'

    ; Install and start service
    nsExec::ExecToLog '"$INSTDIR\bin\SovereignKernelVault.exe" --install'
    ; Fallback to sc.exe if --install not supported
    nsExec::ExecToLog 'sc.exe create SovereignKernelVault binPath="$INSTDIR\bin\SovereignKernelVault.exe --service" start=auto DisplayName="SovereignKernel Vault"'
    nsExec::ExecToLog 'sc.exe description SovereignKernelVault "Hardware-backed security vault met TPM 2.0 ondersteuning"'
    nsExec::ExecToLog 'sc.exe failure SovereignKernelVault reset=86400 actions=restart/5000/restart/10000/restart/30000'
    nsExec::ExecToLog 'sc.exe start SovereignKernelVault'

    ; Add to PATH
    EnVar::AddValue "PATH" "$INSTDIR\bin"

    ; Registry keys
    WriteRegStr HKLM "Software\SovereignKernel" "InstallDir" "$INSTDIR"
    WriteRegStr HKLM "Software\SovereignKernel" "Version" "${VERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SovereignKernel" "DisplayName" "SovereignKernel Vault"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SovereignKernel" "UninstallString" "$\"$INSTDIR\Uninstall.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SovereignKernel" "InstallLocation" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SovereignKernel" "DisplayIcon" "$INSTDIR\UI\SovereignKernel.exe"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SovereignKernel" "Publisher" "${PUBLISHER}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SovereignKernel" "DisplayVersion" "${VERSION}"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SovereignKernel" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SovereignKernel" "NoRepair" 1
    ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
    IntFmt $0 "0x%08X" $0
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SovereignKernel" "EstimatedSize" "$0"

    ; Create uninstaller
    WriteUninstaller "$INSTDIR\Uninstall.exe"
SectionEnd

Section "Desktop UI" SecUI
    SetOutPath "$INSTDIR\UI"
    File /r "..\build\SovereignKernel-UI\*.*"

    ; Start Menu shortcuts
    CreateDirectory "$SMPROGRAMS\SovereignKernel"
    CreateShortCut "$SMPROGRAMS\SovereignKernel\SovereignKernel Vault.lnk" "$INSTDIR\UI\SovereignKernel.exe"
    CreateShortCut "$SMPROGRAMS\SovereignKernel\Verwijderen.lnk" "$INSTDIR\Uninstall.exe"

    ; Desktop shortcut
    CreateShortCut "$DESKTOP\SovereignKernel Vault.lnk" "$INSTDIR\UI\SovereignKernel.exe"
SectionEnd

Section "Documentatie" SecDocs
    SetOutPath "$INSTDIR\docs"
    File "..\docs\ARCHITECTURE.md"
    File "..\docs\API.md"
    File "..\LEES-MIJ.md"
    File "..\SECURITY.md"

    SetOutPath "$INSTDIR"
    File "..\LEES-MIJ.md"
SectionEnd

; ===== Section Descriptions =====
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecService} "De achtergrondservice die de vault beheert. Vereist voor werking."
    !insertmacro MUI_DESCRIPTION_TEXT ${SecUI} "Grafische desktop interface met setup wizard en systeem-tray."
    !insertmacro MUI_DESCRIPTION_TEXT ${SecDocs} "Architectuurdocumentatie, API-referentie en leesmij."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; ===== Uninstaller =====
Section "Uninstall"
    ; Stop and remove service
    nsExec::ExecToLog 'sc.exe stop SovereignKernelVault'
    ; Wait for service to stop
    Sleep 3000
    nsExec::ExecToLog 'sc.exe delete SovereignKernelVault'

    ; Remove PATH entry
    EnVar::DeleteValue "PATH" "$INSTDIR\bin"

    ; Remove files
    RMDir /r "$INSTDIR\bin"
    RMDir /r "$INSTDIR\UI"
    RMDir /r "$INSTDIR\docs"
    Delete "$INSTDIR\LEES-MIJ.md"
    Delete "$INSTDIR\Uninstall.exe"
    RMDir "$INSTDIR"

    ; Remove shortcuts
    Delete "$DESKTOP\SovereignKernel Vault.lnk"
    RMDir /r "$SMPROGRAMS\SovereignKernel"

    ; Remove registry keys
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SovereignKernel"
    DeleteRegKey HKLM "Software\SovereignKernel"

    ; Note: Data is NOT removed. User must delete manually:
    ; C:\Program Files (x86)\Common Files\SovereignKernel\
    MessageBox MB_ICONINFORMATION|MB_OK "De SovereignKernel service is verwijderd.$\r$\n$\r$\nUw versleutelde vault data is NIET verwijderd.$\r$\nLocatie: $COMMONFILES64\SovereignKernel\Data$\r$\n$\r$\nVerwijder deze map handmatig als u de data niet meer nodig heeft."
SectionEnd

; ===== Callbacks =====
Function .onInit
    ; Verify 64-bit Windows
    ${IfNot} ${RunningX64}
        MessageBox MB_OK|MB_ICONSTOP "SovereignKernel vereist een 64-bit versie van Windows."
        Abort
    ${EndIf}

    ; Check Windows version (Windows 10+)
    ${If} ${AtLeastWin10}
        ; OK
    ${Else}
        MessageBox MB_OK|MB_ICONSTOP "SovereignKernel vereist Windows 10 of hoger."
        Abort
    ${EndIf}

    ; Check for existing installation
    ReadRegStr $0 HKLM "Software\SovereignKernel" "InstallDir"
    ${If} $0 != ""
        MessageBox MB_YESNO|MB_ICONQUESTION "SovereignKernel is al geïnstalleerd in:$\r$\n$0$\r$\n$\r$\nWilt u updaten?" IDYES +2
        Abort
    ${EndIf}
FunctionEnd
