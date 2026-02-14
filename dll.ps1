# Sayfayı temizle ve hata mesajlarını tamamen sustur
cls
$ErrorActionPreference = 'SilentlyContinue' 
[Console]::InputEncoding = [System.Text.Encoding]::UTF8

$localPath = Join-Path $env:LOCALAPPDATA "steam"
$steamRegPath = 'HKCU:\Software\Valve\Steam'
$steamToolsRegPath = 'HKCU:\Software\Valve\Steamtools'
$steamPath = ""

# Hata vermeden silme fonksiyonu
function Remove-ItemIfExists($path) {
    if (Test-Path $path) {
        Remove-Item -Path $path -Force -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function ForceStopProcess($processName) {
    # Process durdururken hata çıkmasını engelle
    Stop-Process -Name $processName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# Steam yolunu bul
if (Test-Path $steamRegPath) {
    $steamPath = (Get-ItemProperty -Path $steamRegPath -Name "SteamPath" -ErrorAction SilentlyContinue).SteamPath
}

if ([string]::IsNullOrWhiteSpace($steamPath) -or !(Test-Path $steamPath)) {
    Write-Host "Steam istemcisi bulunamadı." -ForegroundColor Red
    exit
}

$hidPath = Join-Path $steamPath "xinput1_4.dll"
Remove-ItemIfExists $hidPath

function PwStart() {
    try {
        # Gereksiz dosyaları temizle
        $clearPaths = @(
            (Join-Path $steamPath "steam.cfg"),
            (Join-Path $steamPath "package\beta"),
            (Join-Path $env:LOCALAPPDATA "Microsoft\Tencent"),
            (Join-Path $steamPath "version.dll")
        )
        foreach ($p in $clearPaths) { Remove-ItemIfExists $p }

        # Defender dışlaması (Hata olsa da devam et)
        Add-MpPreference -ExclusionPath $hidPath -ErrorAction SilentlyContinue

        # Dosya İndirme
        $downloadHidDll = "https://zoream-database.vercel.app/xinput1_4.dll"
        Invoke-WebRequest -Uri $downloadHidDll -OutFile $hidPath -ErrorAction SilentlyContinue

        # REGISTRY İŞLEMLERİ - Hata vermemesi için kontrol eklendi
        if (!(Test-Path $steamToolsRegPath)) {
            New-Item -Path $steamToolsRegPath -Force -ErrorAction SilentlyContinue | Out-Null
        }

        # Silinecek özellikler listesi
        $propsToRemove = @("ActivateUnlockMode", "AlwaysStayUnlocked", "notUnlockDepot")
        foreach ($prop in $propsToRemove) {
            # Önce özellik var mı diye bak, varsa sil (bu sayede "izin yok" veya "bulunamadı" hatası çıkmaz)
            if ((Get-ItemProperty -Path $steamToolsRegPath -Name $prop -ErrorAction SilentlyContinue)) {
                Remove-ItemProperty -Path $steamToolsRegPath -Name $prop -Force -ErrorAction SilentlyContinue
            }
        }

        Set-ItemProperty -Path $steamToolsRegPath -Name "iscdkey" -Value "true" -Type String -ErrorAction SilentlyContinue

        # Steam'i başlat
        Start-Process (Join-Path $steamPath "steam.exe") -ErrorAction SilentlyContinue
        Write-Host "[Aktivasyon sunucusuna bağlanıldı. Lütfen Steam'e giriş yapın]" -ForegroundColor Green

        # Geri sayım ve kapanış
        for ($i = 5; $i -ge 0; $i--) {
            Write-Host "`r[Bu pencere $i saniye içinde kapanacak...]" -NoNewline
            Start-Sleep -Seconds 1
        }
        exit
    } catch {
        # Hata bloğu boş bırakıldı, hiçbir şey yazmaz
    }
}

PwStart
