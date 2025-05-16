#2025 - ZAC update
#Run with Admin rights
#download and install

# === CONFIGURATION ===
$downloadFolder = "C:\Windows\Temp\ZAC"
$mirrorBaseUrl = "https://mirror.zultys.biz/ZAC/"
$installerPath = Join-Path $downloadFolder "zac.exe"
$logPath = Join-Path $downloadFolder "zac_install_log.txt"

# === CREATE WORK DIR ===
if (-not (Test-Path $downloadFolder)) {
    New-Item -ItemType Directory -Path $downloadFolder -Force | Out-Null
}

# === LOG FUNCTION ===
function Log {
    param ([string]$msg)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp`t$msg" | Out-File -FilePath $logPath -Append
    Write-Host $msg
}

# === LOG HEADER ===
$dateStr = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
"==== LOG STARTS HERE FOR THIS INSTALL - $dateStr ====" | Out-File -FilePath $logPath -Append

# === VERSION CHECK ===
function Get-LatestZACVersionFromServer {
    try {
        $html = Invoke-WebRequest -Uri $mirrorBaseUrl -UseBasicParsing
        $matches = Select-String -InputObject $html.Content -Pattern 'ZAC_x64-(\d+\.\d+\.\d+)\.exe' -AllMatches

        if ($matches.Matches.Count -eq 0) {
            Log "No ZAC installers found on the server."
            return $null
        }

        $versions = $matches.Matches | ForEach-Object {
            [PSCustomObject]@{
                Version = [version]$_.Groups[1].Value
                File    = $_.Value
            }
        }

        return $versions | Sort-Object Version -Descending | Select-Object -First 1
    } catch {
        Log "Failed to retrieve version from server: $_"
        return $null
    }
}

function Get-InstalledZACVersion {
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($path in $regPaths) {
        Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $app = Get-ItemProperty $_.PSPath
                if ($app.DisplayName -like "*ZAC*" -and $app.DisplayName -notlike "*Fax*") {
                    return [version]$app.DisplayVersion
                }
            } catch {}
        }
    }

    return $null
}

# --- Main Check ---
$latest = Get-LatestZACVersionFromServer
$installed = Get-InstalledZACVersion

if ($latest -eq $null) {
    Log "Could not determine latest version from server."
    exit 1
}

Log "Latest available ZAC version on server: $($latest.Version)"
Log "Installer filename: $($latest.File)"

if ($installed) {
    Log "Installed ZAC version on this machine: $installed"

    if ($installed -lt $latest.Version) {
        Log "ZAC is outdated. An update is available."
    } elseif ($installed -eq $latest.Version) {
        Log "ZAC is up to date."
    } else {
        Log "Installed version is newer than server version."
    }
} else {
    Log "ZAC is not installed on this machine."
}

# === CONTINUE INSTALL IF OUTDATED OR MISSING ===
$downloadUrl   = "$mirrorBaseUrl$($latest.File)"
$latestVersion = $latest.Version.ToString()

# === STEP 1: DOWNLOAD INSTALLER IF NOT PRESENT ===
if (-Not (Test-Path $installerPath)) {
    try {
        Log "Downloading latest ZAC from mirror..."
        Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath -UseBasicParsing
        Log "Download complete: $installerPath"
    } catch {
        Log "Download failed: $_"
        exit 1
    }
} else {
    Log "Installer already exists, skipping download: $installerPath"
}

# === STEP 2: FORCE KILL ZAC.EXE ===
try {
    $proc = Get-Process -Name "ZAC" -ErrorAction SilentlyContinue
    if ($proc) {
        Log "Killing ZAC process..."
        Stop-Process -Name "ZAC" -Force
        Log "ZAC process killed."
    }
} catch {
    Log "Failed to stop ZAC process: $_"
}

# === STEP 3: UNINSTALL OLD ZAC ===
function Uninstall-ZAC {
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    $uninstalled = $false

    foreach ($path in $regPaths) {
        Get-ChildItem -Path $path | ForEach-Object {
            try {
                $app = Get-ItemProperty $_.PSPath
                if ($app.DisplayName -like "*ZAC*" -and $app.DisplayName -notlike "*Fax*") {
                    Log "Found: $($app.DisplayName) $($app.DisplayVersion)"
                    $uninst = $app.UninstallString
                    if ($uninst -match "\{.*\}") {
                        $guid = $matches[0]
                        Log "Uninstalling via GUID: $guid"
                        Start-Process "msiexec.exe" -ArgumentList "/X $guid /qn" -Wait
                    } elseif ($uninst) {
                        Log "Uninstalling using raw string: $uninst"
                        Start-Process "cmd.exe" -ArgumentList "/c $uninst /qn" -Wait
                    }
                    $uninstalled = $true
                }
            } catch {
                Log "Error during uninstall: $_"
            }
        }
    }

    if (-not $uninstalled) {
        Log "No existing ZAC installation found."
    }
}
Uninstall-ZAC

# === STEP 4: INSTALL ZAC SILENTLY (InstallShield) ===
if (Test-Path $installerPath) {
    try {
        Log "Installing ZAC silently using InstallShield syntax..."
        Start-Process -FilePath $installerPath -ArgumentList '/S', '/v"/qn"' -Wait
        Log "ZAC installation complete."
    } catch {
        Log "Installation failed: $_"
        exit 2
    }
} else {
    Log "Installer file not found after download."
    exit 3
}

Log "=== Script Finished Successfully ==="
exit 0
