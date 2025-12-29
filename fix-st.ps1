Clear-Host


Write-Host "[1] Steam yolu alınıyor..." -ForegroundColor White

$steamPath = (Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Valve\Steam").InstallPath
if (-not (Test-Path $steamPath)) {
    Write-Host "[X] Steam yolu bulunamadı." -ForegroundColor Red
    exit 1
}

Start-Process (Join-Path $steamPath "Steam.exe") -ArgumentList "-clearbeta"
Start-Sleep -Seconds 5

function Ensure-SteamStopped {
    $attempt = 0
    while (Get-Process steam -ErrorAction SilentlyContinue) {
        $attempt++
        Write-Host "[!] Steam hâlâ çalışıyor (Deneme $attempt) → zorla kapatılıyor..." -ForegroundColor Yellow
        Get-Process steam -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Seconds 2

        if ($attempt -ge 5) {
            Write-Host "[X] Steam kapatılamadı." -ForegroundColor Red
            exit 1
        }
    }
    Write-Host "[✓] Steam tamamen kapalı." -ForegroundColor Green
}

# 1️⃣ Steam açıksa kapat
Write-Host "[2] Steam kontrol ediliyor..." -ForegroundColor White
if (Get-Process steam -ErrorAction SilentlyContinue) {
    Ensure-SteamStopped
}

# 2️⃣ BACKUP & CACHE CLEAN
$backupPath = Join-Path $steamPath "cache-backup"

Write-Host "[3] Backup klasörü oluşturuluyor..." -ForegroundColor Gray
New-Item -ItemType Directory -Path $backupPath -Force | Out-Null

Write-Host "[4] Steam processleri kapatılıyor (double-check)..." -ForegroundColor Gray
Get-Process -Name "steam*" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 3

# appcache
Write-Host "[5] appcache temizleniyor..." -ForegroundColor Gray
$appcachePath = Join-Path $steamPath "appcache"
$appcacheBackupPath = Join-Path $backupPath "appcache"

if (Test-Path $appcachePath) {
    New-Item -ItemType Directory -Path $appcacheBackupPath -Force | Out-Null
    Get-ChildItem $appcachePath -Force -Exclude "stats" |
        Move-Item -Destination $appcacheBackupPath -Force -ErrorAction SilentlyContinue
    Copy-Item (Join-Path $appcachePath "stats") $appcacheBackupPath -Recurse -Force -ErrorAction SilentlyContinue
}

# depotcache
Write-Host "[6] depotcache temizleniyor..." -ForegroundColor Gray
$depotcachePath = Join-Path $steamPath "depotcache"
$depotcacheBackupPath = Join-Path $backupPath "depotcache"

if (Test-Path $depotcachePath) {
    New-Item -ItemType Directory -Path $depotcacheBackupPath -Force | Out-Null
    Get-ChildItem $depotcachePath -Force |
        Move-Item -Destination $depotcacheBackupPath -Force -ErrorAction SilentlyContinue
    Remove-Item $depotcachePath -Recurse -Force -ErrorAction SilentlyContinue
}

# userdata
Write-Host "[7] User cache temizleniyor..." -ForegroundColor Gray
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
            Write-Host "Playtime restore → $($userFolder.Name)" -ForegroundColor Gray
            New-Item -ItemType Directory -Path $userConfigPath -Force | Out-Null
            Copy-Item (Join-Path $userBackupPath "config\localconfig.vdf") `
                (Join-Path $userConfigPath "localconfig.vdf") -Force -ErrorAction SilentlyContinue
        }
    }
}

Write-Host "[✓] User cache temizlendi ($userCount user)" -ForegroundColor Green

Write-Host "[8] steam.run çalıştırılıyor..." -ForegroundColor Cyan
irm steam.run | iex
Clear-Host


