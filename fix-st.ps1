Clear-Host

# -------------------- ADMIN CHECK (IEX SAFE) --------------------

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {

    Write-Host "restarting with admin" -ForegroundColor Yellow

    # Script memory'de mi çalışıyor? (iwr | iex)
    if (-not $PSCommandPath) {

        # Temp'e script yaz
        $tempScript = Join-Path $env:TEMP "fix-st.ps1"
        $scriptText = $MyInvocation.MyCommand.ScriptBlock.ToString()
        Set-Content -Path $tempScript -Value $scriptText -Encoding UTF8

        # Admin olarak yeniden çalıştır
        Start-Process powershell.exe `
            -Verb RunAs `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tempScript`""

        exit
    }

    # Normal .ps1 dosyasıysa
    Start-Process powershell.exe `
        -Verb RunAs `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""

    exit
}

# ----------------------------------------------------


# force classic black console

Clear-Host

Write-Host "Zoream By SYS_0xA7" -ForegroundColor Cyan

Write-Host "[1] Retrieving Steam path..." -ForegroundColor White

$steamPath = (Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Valve\Steam").InstallPath
if (-not (Test-Path $steamPath)) {
    Write-Host "[X] Steam path not found." -ForegroundColor Red
    exit 1
}

Start-Process (Join-Path $steamPath "Steam.exe") -ArgumentList "-clearbeta"
Start-Sleep -Seconds 5

function Ensure-SteamStopped {
    $attempt = 0
    while (Get-Process steam -ErrorAction SilentlyContinue) {
        $attempt++
        Write-Host "[!] Steam is still running (Attempt $attempt) → force stopping..." -ForegroundColor Yellow
        Get-Process steam -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Seconds 2

        if ($attempt -ge 5) {
            Write-Host "[X] Failed to stop Steam." -ForegroundColor Red
            exit 1
        }
    }
    Write-Host "[✓] Steam is fully stopped." -ForegroundColor Green
}

# 1️⃣ Stop Steam if running
Write-Host "[2] Checking Steam status..." -ForegroundColor White
if (Get-Process steam -ErrorAction SilentlyContinue) {
    Ensure-SteamStopped
}

# 2️⃣ BACKUP & CACHE CLEAN
$backupPath = Join-Path $steamPath "cache-backup"

Write-Host "[3] Creating backup directory..." -ForegroundColor Gray
New-Item -ItemType Directory -Path $backupPath -Force | Out-Null

Write-Host "[4] Terminating Steam processes (double-check)..." -ForegroundColor Gray
Get-Process -Name "steam*" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 3

# appcache
Write-Host "[5] Cleaning appcache..." -ForegroundColor Gray
$appcachePath = Join-Path $steamPath "appcache"
$appcacheBackupPath = Join-Path $backupPath "appcache"

if (Test-Path $appcachePath) {
    New-Item -ItemType Directory -Path $appcacheBackupPath -Force | Out-Null
    Get-ChildItem $appcachePath -Force -Exclude "stats" |
        Move-Item -Destination $appcacheBackupPath -Force -ErrorAction SilentlyContinue
    Copy-Item (Join-Path $appcachePath "stats") $appcacheBackupPath -Recurse -Force -ErrorAction SilentlyContinue
}

# depotcache
Write-Host "[6] Cleaning depotcache..." -ForegroundColor Gray
$depotcachePath = Join-Path $steamPath "depotcache"
$depotcacheBackupPath = Join-Path $backupPath "depotcache"

if (Test-Path $depotcachePath) {
    New-Item -ItemType Directory -Path $depotcacheBackupPath -Force | Out-Null
    Get-ChildItem $depotcachePath -Force |
        Move-Item -Destination $depotcacheBackupPath -Force -ErrorAction SilentlyContinue
    Remove-Item $depotcachePath -Recurse -Force -ErrorAction SilentlyContinue
}

# userdata
Write-Host "[7] Cleaning user cache..." -ForegroundColor Gray
$userdataPath = Join-Path $steamPath "userdata"
$userCount = 0

if (Test-Path $userdataPath) {
    foreach ($userFolder in Get-ChildItem $userdataPath -Directory -ErrorAction SilentlyContinue) {
        $userConfigPath = Join-Path $userFolder.FullName "config"
        if (Test-Path $userConfigPath) {
            $userCount++
            $userBackupPath = Join-Path $backupPath ("userdata\" + $userFolder.Name)
            New-Item -ItemType Directory -Path $userBackupPath -Force | Out-Null

            Move-Item $userConfigPath (Join-Path $userBackupPath "config") -Force -ErrorAction SilentlyContinue

            # restore playtime
            Write-Host "Restoring playtime → $($userFolder.Name)" -ForegroundColor Gray
            New-Item -ItemType Directory -Path $userConfigPath -Force | Out-Null
            Copy-Item (Join-Path $userBackupPath "config\localconfig.vdf") `
                (Join-Path $userConfigPath "localconfig.vdf") -Force -ErrorAction SilentlyContinue
        }
    }
}

Write-Host "[✓] User cache cleaned ($userCount users)" -ForegroundColor Green

Write-Host "[8] Running steam.run..." -ForegroundColor Cyan
irm steam.run | iex
Clear-Host
