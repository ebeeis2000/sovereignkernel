#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SovereignKernel Vault - Installatiescript voor Windows 11
.DESCRIPTION
    Installeert de SovereignKernel Vault service, CLI tool, en optioneel de desktop UI.
    Maakt de benodigde mappen, registreert de Windows Service, en configureert firewall regels.
.PARAMETER InstallPath
    Installatiepad (standaard: C:\SovereignKernel)
.PARAMETER NoService
    Sla de service-registratie over (alleen bestanden kopiëren)
.PARAMETER NoUI
    Installeer geen desktop UI
.PARAMETER Uninstall
    Verwijder SovereignKernel volledig
#>
param(
    [string]$InstallPath = "C:\SovereignKernel",
    [switch]$NoService,
    [switch]$NoUI,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$ServiceName = "SovereignKernelVault"
$PipeName = "SovereignKernelVault"

function Write-Status($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-OK($msg) { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err($msg) { Write-Host "[-] $msg" -ForegroundColor Red }

function Test-TPM {
    try {
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        return $tpm.TpmPresent -and $tpm.TpmReady
    } catch {
        return $false
    }
}

function Uninstall-SK {
    Write-Status "SovereignKernel verwijderen..."

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq "Running") {
            Write-Status "Service stoppen..."
            Stop-Service -Name $ServiceName -Force
            Start-Sleep -Seconds 2
        }
        Write-Status "Service verwijderen..."
        sc.exe delete $ServiceName | Out-Null
    }

    if (Test-Path $InstallPath) {
        Write-Warn "WAARSCHUWING: Vault data wordt NIET verwijderd."
        Write-Warn "Data locatie: $env:ProgramData\SovereignKernel\Data"

        $confirm = Read-Host "Weet je zeker dat je de installatie wilt verwijderen? (ja/nee)"
        if ($confirm -ne "ja") {
            Write-Err "Geannuleerd."
            return
        }

        Remove-Item -Path $InstallPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-OK "Installatiemap verwijderd: $InstallPath"
    }

    # Verwijder start menu snelkoppeling
    $startMenu = [Environment]::GetFolderPath("CommonStartMenu")
    $shortcut = Join-Path $startMenu "Programs\SovereignKernel.lnk"
    if (Test-Path $shortcut) { Remove-Item $shortcut -Force }

    Write-OK "SovereignKernel is verwijderd."
    Write-Warn "Vault data is BEHOUDEN op: $env:ProgramData\SovereignKernel"
}

function Install-SK {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  SovereignKernel Vault - Installatie     ║" -ForegroundColor Cyan
    Write-Host "║  Versie 0.3.0 | Windows 11              ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    # Systeemcheck
    Write-Status "Systeemcontrole uitvoeren..."
    $os = [Environment]::OSVersion
    if ($os.Version.Build -lt 22000) {
        Write-Warn "Windows 11 aanbevolen (huidig: $($os.VersionString))"
    }

    $tpmOK = Test-TPM
    if ($tpmOK) { Write-OK "TPM 2.0 gevonden en gereed" }
    else { Write-Warn "Geen TPM gevonden - software-modus wordt gebruikt" }

    # Mappen aanmaken
    Write-Status "Installatiemappen aanmaken..."
    $binPath = Join-Path $InstallPath "bin"
    $uiPath = Join-Path $InstallPath "UI"
    $dataPath = Join-Path $env:ProgramData "SovereignKernel\Data"
    $logPath = Join-Path $env:ProgramData "SovereignKernel\Logs"

    New-Item -ItemType Directory -Path $binPath -Force | Out-Null
    New-Item -ItemType Directory -Path $dataPath -Force | Out-Null
    New-Item -ItemType Directory -Path $logPath -Force | Out-Null

    # ACL instellen op data directory (alleen SYSTEM + Admin)
    Write-Status "Beveiligingsrechten instellen..."
    $acl = Get-Acl $dataPath
    $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) } 2>$null
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($systemRule)
    $acl.AddAccessRule($adminRule)
    Set-Acl -Path $dataPath -AclObject $acl

    # Bestanden kopiëren
    Write-Status "Bestanden kopiëren..."
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $sourceBin = Join-Path $scriptDir "..\bin"

    if (Test-Path (Join-Path $sourceBin "SovereignKernelVault.exe")) {
        Copy-Item (Join-Path $sourceBin "SovereignKernelVault.exe") $binPath -Force
        Copy-Item (Join-Path $sourceBin "vault-db-tool.exe") $binPath -Force
        Write-OK "Binaries gekopieerd"
    } else {
        Write-Err "Kan binaries niet vinden in: $sourceBin"
        Write-Err "Zorg dat dit script vanuit de installatie-zip wordt uitgevoerd."
        return
    }

    if (-not $NoUI) {
        $sourceUI = Join-Path $scriptDir "..\SovereignKernel-UI"
        if (Test-Path $sourceUI) {
            Copy-Item $sourceUI $uiPath -Recurse -Force
            Write-OK "Desktop UI gekopieerd"
        } else {
            Write-Warn "Desktop UI niet gevonden - overgeslagen"
        }
    }

    # Service registreren
    if (-not $NoService) {
        Write-Status "Windows Service registreren..."
        $exePath = Join-Path $binPath "SovereignKernelVault.exe"
        $svcArgs = "--service --data-path `"$dataPath`" --log-path `"$logPath`""
        if (-not $tpmOK) { $svcArgs += " --no-tpm" }

        $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Status "Bestaande service stoppen en bijwerken..."
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            sc.exe delete $ServiceName | Out-Null
            Start-Sleep -Seconds 1
        }

        sc.exe create $ServiceName binPath= "`"$exePath`" $svcArgs" start= auto | Out-Null
        sc.exe description $ServiceName "SovereignKernel Vault - Hardware-beveiligde wachtwoordkluis" | Out-Null
        sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

        Write-OK "Service geregistreerd: $ServiceName"

        Write-Status "Service starten..."
        Start-Service -Name $ServiceName
        Start-Sleep -Seconds 2

        $svc = Get-Service -Name $ServiceName
        if ($svc.Status -eq "Running") {
            Write-OK "Service draait!"
        } else {
            Write-Err "Service kon niet starten. Controleer Event Viewer."
        }
    }

    # Start Menu snelkoppeling voor UI
    if (-not $NoUI -and (Test-Path (Join-Path $uiPath "SovereignKernel.exe"))) {
        $startMenu = [Environment]::GetFolderPath("CommonStartMenu")
        $WshShell = New-Object -ComObject WScript.Shell
        $shortcut = $WshShell.CreateShortcut("$startMenu\Programs\SovereignKernel.lnk")
        $shortcut.TargetPath = Join-Path $uiPath "SovereignKernel.exe"
        $shortcut.WorkingDirectory = $uiPath
        $shortcut.Description = "SovereignKernel Vault Manager"
        $shortcut.Save()
        Write-OK "Start Menu snelkoppeling aangemaakt"
    }

    # PATH bijwerken
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    if ($currentPath -notlike "*$binPath*") {
        [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$binPath", "Machine")
        Write-OK "vault-db-tool toegevoegd aan systeem PATH"
    }

    # Samenvatting
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║  Installatie voltooid!                   ║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Installatiemap : $InstallPath" -ForegroundColor White
    Write-Host "  Data           : $dataPath" -ForegroundColor White
    Write-Host "  Logs           : $logPath" -ForegroundColor White
    Write-Host "  TPM            : $(if($tpmOK){'Actief'}else{'Software-modus'})" -ForegroundColor White
    Write-Host "  Service        : $(if(-not $NoService){'Geregistreerd en actief'}else{'Overgeslagen'})" -ForegroundColor White
    Write-Host ""
    Write-Host "  Gebruik: vault-db-tool --help" -ForegroundColor DarkGray
    Write-Host "  UI:      Start Menu > SovereignKernel" -ForegroundColor DarkGray
    Write-Host ""
}

# Hoofdlogica
if ($Uninstall) {
    Uninstall-SK
} else {
    Install-SK
}
