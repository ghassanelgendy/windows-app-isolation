<#
.SYNOPSIS
    Install-AdobeSuite.ps1 - Generic Offline Installer, Forensic Tamper Trap & Firewall Lockdown for Adobe Suites.
.DESCRIPTION
    Specifically engineered for installing Adobe applications (Illustrator, Photoshop, Premiere Pro,
    After Effects, Media Encoder, InDesign, Acrobat, etc.) safely and 100% offline:
      1. Dynamic Internet Isolation: Discovers and disables active internet adapters before launching installers.
      2. Neutralizes Telemetry Popups: Disables background helpers (Adobe Desktop Service / ADS, CCXProcess, CCLibrary).
      3. Trial Cache Sanitization: Purges stale SLStore, SLCache, and Adobe PCD directories.
      4. Forensic Snapshot & Tamper Detection: Detects unauthorized Windows Defender exclusions, installer firewall
         allow rules, background processes, and registry autorun persistence.
      5. Full Deep Dependency Lockdown: Blocks every discovered executable across the installation directories,
         common files, services, and scheduled tasks bidirectionally in Windows Defender Firewall.
      6. Safe Network Restoration: Ensures internet adapters are reliably restored upon completion or interruption.
.PARAMETER InstallerFolder
    Optional path to a folder containing Adobe setup packages (searches Desktop and Downloads by default).
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$InstallerFolder
)

$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

function Get-ActiveInternetAdapters {
    $matchedIndices = [System.Collections.Generic.HashSet[int]]::new()
    $routes = Get-NetRoute -DestinationPrefix @("0.0.0.0/0", "::/0") -ErrorAction SilentlyContinue |
              Where-Object { $_.NextHop -and $_.NextHop -ne "0.0.0.0" -and $_.NextHop -ne "::" }
    foreach ($r in $routes) { [void]$matchedIndices.Add($r.InterfaceIndex) }

    $profiles = Get-NetConnectionProfile -ErrorAction SilentlyContinue |
                Where-Object { $_.IPv4Connectivity -eq "Internet" -or $_.IPv6Connectivity -eq "Internet" }
    foreach ($p in $profiles) { [void]$matchedIndices.Add($p.InterfaceIndex) }

    $candidates = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Status -eq "Up" -and
        $_.InterfaceDescription -notmatch "(Virtual|Loopback|Hyper-V|WSL|Docker|Tailscale|WireGuard|TAP|TUN|OpenVPN|ZeroTier|Host-Only)" -and
        $_.Name -notmatch "(vEthernet|Loopback|Tailscale|WireGuard|ZeroTier|Docker)"
    }

    if ($matchedIndices.Count -gt 0) {
        $routedAdapters = @($candidates | Where-Object { $matchedIndices.Contains($_.InterfaceIndex) })
        if ($routedAdapters.Count -gt 0) { return $routedAdapters }
    }
    return @($candidates)
}

function Block-ExecutableInFirewall {
    param(
        [string]$ExePath,
        [string]$GroupName,
        [System.Collections.Generic.HashSet[string]]$AlreadyBlocked
    )
    if ([string]::IsNullOrWhiteSpace($ExePath)) { return $false }
    $clean = $ExePath.Trim().Trim('"').Trim("'")
    if (-not (Test-Path -LiteralPath $clean)) { return $false }
    $item = Get-Item -LiteralPath $clean -ErrorAction SilentlyContinue
    if (-not $item -or $item.PSIsContainer) { return $false }
    if (-not $AlreadyBlocked.Add($item.FullName)) { return $false }

    $ruleBase = "[AdobeSuite] $($item.Name) ($($item.FullName.GetHashCode()))"
    New-NetFirewallRule -DisplayName "$ruleBase [OUT]" -Group $GroupName -Direction Outbound -Program $item.FullName -Action Block -Profile Any -Enabled True | Out-Null
    New-NetFirewallRule -DisplayName "$ruleBase [IN]"  -Group $GroupName -Direction Inbound  -Program $item.FullName -Action Block -Profile Any -Enabled True | Out-Null
    Write-Host "  [BLOCKED IN/OUT] $($item.FullName)" -ForegroundColor Green
    return $true
}

function Get-AutorunMap {
    $regKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    $entries = @{}
    foreach ($rk in $regKeys) {
        if (Test-Path $rk) {
            $props = Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue
            if ($props) {
                foreach ($p in $props.PSObject.Properties) {
                    if ($p.Name -notmatch "^PS(Path|ParentPath|ChildName|Drive|Provider)$") {
                        $entries["$rk|$($p.Name)"] = "$($p.Value)"
                    }
                }
            }
        }
    }
    return $entries
}

try {
    $installStartTime = Get-Date

    Write-Host "=====================================================================" -ForegroundColor Cyan
    Write-Host "       GENERIC ADOBE OFFLINE INSTALLER & FORENSIC FIREWALL TRAP      " -ForegroundColor Cyan
    Write-Host "=====================================================================" -ForegroundColor Cyan

    # 1. Clean stale trial caches
    Write-Host "`n=== 1. Cleaning Residual Trial Cache Folders ===" -ForegroundColor Cyan
    $trialFolders = @(
        "$env:ProgramData\Adobe\SLStore",
        "${env:ProgramFiles(x86)}\Common Files\Adobe\SLCache",
        "${env:ProgramFiles(x86)}\Common Files\Adobe\Adobe PCD"
    )
    foreach ($tf in $trialFolders) {
        if (Test-Path -LiteralPath $tf) {
            Remove-Item -LiteralPath $tf -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "  [CLEANED] $tf" -ForegroundColor Green
        }
    }

    # 2. Forensic snapshot
    Write-Host "`n=== 2. Capturing Pre-Install Forensic Snapshot ===" -ForegroundColor Cyan
    $beforeServices = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    Get-Service -ErrorAction SilentlyContinue | ForEach-Object { [void]$beforeServices.Add($_.Name) }

    $beforeTasks = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { [void]$beforeTasks.Add("$($_.TaskPath)$($_.TaskName)") }

    $beforeAutoruns = Get-AutorunMap

    $beforeFwRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    Get-NetFirewallRule -ErrorAction SilentlyContinue | ForEach-Object { [void]$beforeFwRules.Add($_.Name) }

    $beforeExclusions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $mpPref = Get-MpPreference -ErrorAction SilentlyContinue
    if ($mpPref) {
        foreach ($p in @($mpPref.ExclusionPath))    { if ($p) { [void]$beforeExclusions.Add("PATH|$p") } }
        foreach ($p in @($mpPref.ExclusionProcess)) { if ($p) { [void]$beforeExclusions.Add("PROC|$p") } }
    }

    # 3. Discover Installers
    $searchLocations = @()
    if ($InstallerFolder -and (Test-Path -LiteralPath $InstallerFolder)) {
        $searchLocations += $InstallerFolder
    } else {
        $desktop = [Environment]::GetFolderPath("Desktop")
        $downloads = Join-Path $env:USERPROFILE "Downloads"
        if (Test-Path $desktop) { $searchLocations += $desktop }
        if (Test-Path $downloads) { $searchLocations += $downloads }
    }

    $discoveredSetups = @()
    foreach ($loc in $searchLocations) {
        $found = Get-ChildItem -Path $loc -Filter "Set-up.exe" -Recurse -File -Depth 4 -ErrorAction SilentlyContinue
        if ($found) { $discoveredSetups += $found }
    }

    # 4. Sever active internet
    $activeAdapters = Get-ActiveInternetAdapters
    $disabledAdapters = @()

    Write-Host "`n=== 3. Severing Internet & Launching Installers ===" -ForegroundColor Yellow
    try {
        foreach ($nic in $activeAdapters) {
            Write-Host "  -> Disabling internet adapter: $($nic.Name) ($($nic.InterfaceDescription))" -ForegroundColor Yellow
            Disable-NetAdapter -Name $nic.Name -Confirm:$false -ErrorAction SilentlyContinue
            $disabledAdapters += $nic
        }
        Write-Host "SYSTEM IS NOW COMPLETELY OFFLINE." -ForegroundColor Green

        if ($discoveredSetups.Count -gt 0) {
            Write-Host "`nFound $($discoveredSetups.Count) installer package(s):" -ForegroundColor Cyan
            for ($i = 0; $i -lt $discoveredSetups.Count; $i++) {
                Write-Host "  [$($i+1)] $($discoveredSetups[$i].Directory.Name) -> $($discoveredSetups[$i].FullName)" -ForegroundColor Gray
            }
            $runAll = Read-Host "`nLaunch these installers sequentially now? (Y/N, default Y)"
            if ($runAll -eq "" -or $runAll -match "^[Yy]") {
                foreach ($setup in $discoveredSetups) {
                    Write-Host "`n------------------------------------------------------------" -ForegroundColor Cyan
                    Write-Host "Launching: $($setup.FullName)" -ForegroundColor Cyan
                    Write-Host "Complete the installation in the installer dialog, then close it." -ForegroundColor White

                    $psi = New-Object System.Diagnostics.ProcessStartInfo
                    $psi.FileName = $setup.FullName
                    $psi.WorkingDirectory = $setup.DirectoryName
                    $psi.UseShellExecute = $true
                    $proc = [System.Diagnostics.Process]::Start($psi)
                    if ($proc) { $proc.WaitForExit() }
                    Read-Host "Press ENTER after this installer has closed"
                }
            }
        } else {
            Write-Host "`nNo 'Set-up.exe' automatically found on Desktop or Downloads." -ForegroundColor Yellow
            Write-Host "1. Run your Adobe installer(s) now while offline." -ForegroundColor White
            Write-Host "2. Wait for installation to reach 100% and close the installer." -ForegroundColor White
            Read-Host "Press ENTER after all installations are complete"
        }

        # 5. Disable background popup helpers
        Write-Host "`n=== 4. Neutralizing Adobe Popup Helpers (ADS & CCXProcess) ===" -ForegroundColor Cyan
        Get-Process | Where-Object { $_.ProcessName -match "Adobe Desktop Service|CCXProcess|CCLibrary" } | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        $popupBinaries = @(
            "${env:ProgramFiles(x86)}\Common Files\Adobe\Adobe Desktop Common\ADS\Adobe Desktop Service.exe",
            "$env:ProgramFiles\Adobe\Adobe Creative Cloud Experience\CCXProcess.exe",
            "${env:ProgramFiles(x86)}\Adobe\Adobe Creative Cloud Experience\CCXProcess.exe"
        )
        foreach ($bin in $popupBinaries) {
            if (Test-Path -LiteralPath $bin) {
                $disabledPath = "$bin.disabled"
                if (Test-Path -LiteralPath $disabledPath) {
                    Remove-Item -LiteralPath $disabledPath -Force -ErrorAction SilentlyContinue
                }
                Rename-Item -LiteralPath $bin -NewName "$(Split-Path -Leaf $bin).disabled" -Force
                Write-Host "  [DISABLED POPUP BINARY] $bin -> .disabled" -ForegroundColor Green
            }
        }

        # 6. Apply complete firewall lockdown
        Write-Host "`n=== 5. Applying Complete Inbound/Outbound Firewall Isolation ===" -ForegroundColor Cyan
        $groupName = "TotalAppIsolation:AdobeSuite"
        Get-NetFirewallRule -Group $groupName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        $blockedSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $blockedCount = 0

        # Revert unauthorized Defender exclusions
        $afterMpPref = Get-MpPreference -ErrorAction SilentlyContinue
        if ($afterMpPref) {
            foreach ($p in @($afterMpPref.ExclusionPath)) {
                if ($p -and -not $beforeExclusions.Contains("PATH|$p")) {
                    Write-Host "  [TAMPER REVERTED] Removing unauthorized Defender path exclusion: $p" -ForegroundColor Red
                    Remove-MpPreference -ExclusionPath $p -ErrorAction SilentlyContinue
                }
            }
            foreach ($p in @($afterMpPref.ExclusionProcess)) {
                if ($p -and -not $beforeExclusions.Contains("PROC|$p")) {
                    Write-Host "  [TAMPER REVERTED] Removing unauthorized Defender process exclusion: $p" -ForegroundColor Red
                    Remove-MpPreference -ExclusionProcess $p -ErrorAction SilentlyContinue
                }
            }
        }

        # Remove stealth installer firewall rules
        Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { -not $beforeFwRules.Contains($_.Name) } | ForEach-Object {
            Write-Host "  [REMOVED INSTALLER FIREWALL RULE] $($_.DisplayName)" -ForegroundColor Yellow
            $_ | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        }

        # Disable & block newly created services
        $targetServices = @(Get-Service -ErrorAction SilentlyContinue | Where-Object {
            (-not $beforeServices.Contains($_.Name)) -or ($_.Name -match "Adobe|AGMService|AGSService|CCXProcess") -or ($_.DisplayName -match "Adobe")
        })
        foreach ($svc in $targetServices) {
            Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName "[AdobeSuite] Service: $($svc.Name) [OUT]" -Group $groupName -Direction Outbound -Service $svc.Name -Action Block -Profile Any -Enabled True | Out-Null
            New-NetFirewallRule -DisplayName "[AdobeSuite] Service: $($svc.Name) [IN]"  -Group $groupName -Direction Inbound  -Service $svc.Name -Action Block -Profile Any -Enabled True | Out-Null
            Write-Host "  [STOPPED, DISABLED & BLOCKED SERVICE] $($svc.Name)" -ForegroundColor Yellow

            $cimSvc = Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue
            if ($cimSvc -and $cimSvc.PathName) {
                $svcExe = ($cimSvc.PathName -replace '^"([^"]+)".*$', '$1' -replace '^([^\s]+\.exe).*$', '$1').Trim()
                if (Block-ExecutableInFirewall -ExePath $svcExe -GroupName $groupName -AlreadyBlocked $blockedSet) { $blockedCount++ }
            }
        }

        # Disable & block scheduled tasks
        $targetTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            (-not $beforeTasks.Contains("$($_.TaskPath)$($_.TaskName)")) -or ($_.TaskName -match "Adobe") -or ($_.TaskPath -match "Adobe")
        })
        foreach ($task in $targetTasks) {
            Disable-ScheduledTask -InputObject $task -ErrorAction SilentlyContinue | Out-Null
            Write-Host "  [DISABLED SCHEDULED TASK] $($task.TaskPath)$($task.TaskName)" -ForegroundColor Yellow
            foreach ($act in $task.Actions) {
                if ($act.Execute) {
                    $expanded = [Environment]::ExpandEnvironmentVariables($act.Execute)
                    if (Block-ExecutableInFirewall -ExePath $expanded -GroupName $groupName -AlreadyBlocked $blockedSet) { $blockedCount++ }
                }
            }
        }

        # Remove startup autoruns
        $afterAutoruns = Get-AutorunMap
        foreach ($k in $afterAutoruns.Keys) {
            if (-not $beforeAutoruns.ContainsKey($k) -or $beforeAutoruns[$k] -ne $afterAutoruns[$k]) {
                $cmdStr = $afterAutoruns[$k]
                Write-Host "  [REMOVED STARTUP AUTORUN] $k => $cmdStr" -ForegroundColor Yellow
                $parts = $k -split "\|", 2
                Remove-ItemProperty -Path $parts[0] -Name $parts[1] -ErrorAction SilentlyContinue
                $autoExe = ($cmdStr -replace '^"([^"]+)".*$', '$1' -replace '^([^\s]+\.exe).*$', '$1').Trim()
                if (Block-ExecutableInFirewall -ExePath $autoExe -GroupName $groupName -AlreadyBlocked $blockedSet) { $blockedCount++ }
            }
        }

        # Block all Adobe directories
        $adobeFolders = @(
            "$env:ProgramFiles\Adobe",
            "$env:ProgramFiles\Common Files\Adobe",
            "${env:ProgramFiles(x86)}\Adobe",
            "${env:ProgramFiles(x86)}\Common Files\Adobe",
            "$env:ProgramData\Adobe",
            "$env:LOCALAPPDATA\Adobe",
            "$env:APPDATA\Adobe"
        ) | Where-Object { Test-Path -LiteralPath $_ }

        foreach ($folder in $adobeFolders) {
            Get-ChildItem -LiteralPath $folder -Recurse -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue
            $exes = Get-ChildItem -LiteralPath $folder -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -match "^\.(exe|com|scr)$" }
            foreach ($exe in $exes) {
                if (Block-ExecutableInFirewall -ExePath $exe.FullName -GroupName $groupName -AlreadyBlocked $blockedSet) {
                    $blockedCount++
                }
            }
        }

        # Block any binary created or modified during install across common roots
        $publicDir = if ($env:PUBLIC) { $env:PUBLIC } else { (Join-Path $env:SystemDrive "Users\Public") }
        $globalRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, $env:LOCALAPPDATA, $env:APPDATA, $env:TEMP, $publicDir) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
        foreach ($gr in $globalRoots) {
            Get-ChildItem -LiteralPath $gr -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -match "^\.(exe|com|scr)$" -and ($_.CreationTime -ge $installStartTime -or $_.LastWriteTime -ge $installStartTime) } |
                ForEach-Object {
                    if (Block-ExecutableInFirewall -ExePath $_.FullName -GroupName $groupName -AlreadyBlocked $blockedSet) {
                        $blockedCount++
                    }
                }
        }

        Write-Host "`n==================================================================" -ForegroundColor Cyan
        Write-Host "  ADOBE OFFLINE LOCKDOWN COMPLETE!" -ForegroundColor Green
        Write-Host "  Total Executables Blocked (In/Out, All Profiles): $blockedCount" -ForegroundColor Green
        Write-Host "==================================================================" -ForegroundColor Cyan

    } finally {
        Write-Host "`n=== 6. Restoring Internet Adapters ===" -ForegroundColor Cyan
        foreach ($nic in $disabledAdapters) {
            Write-Host "  -> Enabling adapter: $($nic.Name)" -ForegroundColor Green
            Enable-NetAdapter -Name $nic.Name -Confirm:$false -ErrorAction SilentlyContinue
        }
        Write-Host "Internet restored safely." -ForegroundColor Green
    }

    Read-Host "`nPress ENTER to close"
} catch {
    Write-Host "`n[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
    Read-Host "Press ENTER to close"
}
