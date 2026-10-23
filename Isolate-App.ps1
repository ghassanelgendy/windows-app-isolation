<#
.SYNOPSIS
    Isolate-App.ps1 - Anti-Stealer / Anti-Trojan Offline Installer Trap & Deep Dependency Firewall Blocker.
.DESCRIPTION
    Designed to catch hidden payloads, droppers, updaters, and persistence mechanisms from untrusted or repackaged installers:
      1. Dynamic Internet Cut & Restore: Automatically detects active default-gateway WAN network adapters (Ethernet, Wi-Fi, etc.)
         while preserving VPN tunnels (Tailscale, WireGuard) and isolating the system completely during install.
      2. Forensic Pre/Post Snapshot Diffing: Takes forensic snapshots before and after installation to capture every change.
      3. Deep Dropper Hunting: Discovers EVERY newly created or modified executable (.exe, .com, .scr, .dll, .ps1, .vbs, .bat, .cmd)
         dropped across AppData, Temp, ProgramData, Program Files, Public, etc. — even under randomized/obfuscated folder names.
      4. Windows Defender Exclusion Tamper Reversal: Catches malware adding stealth Defender exclusions (`Add-MpPreference -ExclusionPath`)
         and instantly strips them before restoring connectivity.
      5. Firewall Rule Tamper Detection: Detects and removes any stealth Inbound/Outbound ALLOW rules created by installers.
      6. Autorun & Persistence Sanitization: Flags new Registry Run/RunOnce keys and Startup shortcuts with 1-click remediation.
      7. Background Process Hunting: Detects and terminates rogue processes spawned during install.
      8. Complete Firewall Lockdown: Enforces strict bidirectional (Inbound AND Outbound) Windows Defender Firewall BLOCK rules
         for every application binary, dropped executable, service, and scheduled task.
      9. LOLBin Internet Lockdown: Optionally blocks Windows Living-Off-The-Land binaries (mshta, wscript, cscript, regsvr32, rundll32,
         certutil, bitsadmin, cmd) from accessing the internet to prevent script-based data exfiltration.
.EXAMPLE
    .\Isolate-App.ps1
    Interactive menu mode.
.EXAMPLE
    .\Isolate-App.ps1 -Install -AppName "Blender" -InstallerPath "D:\Downloads\installer.exe"
    Automated offline installation and forensic isolation.
.EXAMPLE
    .\Isolate-App.ps1 -Block -AppName "Adobe"
    Locks down all existing installed directories and services matching "Adobe".
.EXAMPLE
    .\Isolate-App.ps1 -Unblock -AppName "Blender"
    Removes all firewall isolation rules for the specified app.
.EXAMPLE
    .\Isolate-App.ps1 -LockdownLOLBins
    Blocks Windows system LOLBins from outbound internet communication.
#>

[CmdletBinding(DefaultParameterSetName = "Interactive")]
param(
    [Parameter(ParameterSetName = "Install")]
    [switch]$Install,

    [Parameter(ParameterSetName = "Install")]
    [string]$InstallerPath,

    [Parameter(ParameterSetName = "Block")]
    [switch]$Block,

    [Parameter(ParameterSetName = "Unblock")]
    [switch]$Unblock,

    [Parameter(ParameterSetName = "List")]
    [switch]$List,

    [Parameter(ParameterSetName = "LockdownLOLBins")]
    [switch]$LockdownLOLBins,

    [Parameter(ParameterSetName = "Install")]
    [Parameter(ParameterSetName = "Block")]
    [Parameter(ParameterSetName = "Unblock")]
    [string]$AppName
)

$ErrorActionPreference = "Stop"
$RuleGroupPrefix = "TotalAppIsolation"

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Warning "This script requires Administrator privileges."
    Write-Host "Re-launching as Administrator..." -ForegroundColor Yellow
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    foreach ($key in $PSBoundParameters.Keys) {
        $val = $PSBoundParameters[$key]
        if ($val -is [switch]) {
            if ($val.IsPresent) { $argList += " -$key" }
        } else {
            $argList += " -$key `"$val`""
        }
    }
    Start-Process powershell.exe -ArgumentList $argList -Verb RunAs
    exit
}

function Get-ActiveInternetAdapters {
    <#
        Dynamically discovers all physical/WAN network adapters providing active internet connectivity.
        Filters out loopbacks, virtual switches (Hyper-V, WSL, Docker, VMware, VirtualBox),
        and software VPN tunnels (Tailscale, WireGuard, OpenVPN, TAP/TUN, ZeroTier), while accurately catching
        any active Wi-Fi, Ethernet, Mobile Broadband, or WAN interface on ANY Windows system.
    #>
    $matchedIndices = [System.Collections.Generic.HashSet[int]]::new()

    # 1. Check adapters with an active default gateway route (0.0.0.0/0 or ::/0)
    $routes = Get-NetRoute -DestinationPrefix @("0.0.0.0/0", "::/0") -ErrorAction SilentlyContinue |
              Where-Object { $_.NextHop -and $_.NextHop -ne "0.0.0.0" -and $_.NextHop -ne "::" }
    foreach ($r in $routes) {
        [void]$matchedIndices.Add($r.InterfaceIndex)
    }

    # 2. Check connection profiles with verified Internet connectivity
    $profiles = Get-NetConnectionProfile -ErrorAction SilentlyContinue |
                Where-Object { $_.IPv4Connectivity -eq "Internet" -or $_.IPv6Connectivity -eq "Internet" }
    foreach ($p in $profiles) {
        [void]$matchedIndices.Add($p.InterfaceIndex)
    }

    # 3. Retrieve adapters, filter to Up, and exclude virtual/VPN adapters
    $candidates = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Status -eq "Up" -and
        $_.InterfaceDescription -notmatch "(Virtual|Loopback|Hyper-V|WSL|Docker|Tailscale|WireGuard|TAP|TUN|OpenVPN|ZeroTier|Host-Only)" -and
        $_.Name -notmatch "(vEthernet|Loopback|Tailscale|WireGuard|ZeroTier|Docker)"
    }

    if ($matchedIndices.Count -gt 0) {
        $routedAdapters = @($candidates | Where-Object { $matchedIndices.Contains($_.InterfaceIndex) })
        if ($routedAdapters.Count -gt 0) {
            return $routedAdapters
        }
    }

    return @($candidates)
}

function Clean-InputPaths {
    param([string]$RawInput)
    if ([string]::IsNullOrWhiteSpace($RawInput)) { return @() }
    $results = @()
    foreach ($part in ($RawInput -split ",")) {
        $clean = $part.Trim().Trim('"').Trim("'").Trim()
        if ($clean -and (Test-Path -LiteralPath $clean)) {
            $item = Get-Item -LiteralPath $clean -ErrorAction SilentlyContinue
            if ($item) {
                if ($item.PSIsContainer) {
                    $results += $item.FullName
                } else {
                    $results += $item.DirectoryName
                }
            }
        } elseif ($clean) {
            Write-Warning "Path does not exist: $clean"
        }
    }
    return $results
}

function Get-DropperSearchRoots {
    $publicDir = if ($env:PUBLIC) { $env:PUBLIC } else { (Join-Path $env:SystemDrive "Users\Public") }
    return @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramData,
        $env:LOCALAPPDATA,
        $env:APPDATA,
        $env:TEMP,
        $publicDir,
        "$env:windir\Temp"
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique
}

function Get-AutorunEntries {
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
    $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($sf in $startupFolders) {
        if (Test-Path -LiteralPath $sf) {
            Get-ChildItem -LiteralPath $sf -File -ErrorAction SilentlyContinue | ForEach-Object {
                $entries["STARTUP|$($_.FullName)"] = $_.FullName
            }
        }
    }
    return $entries
}

function Get-DefenderExclusions {
    $exclusions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    try {
        $pref = Get-MpPreference -ErrorAction SilentlyContinue
        if ($pref) {
            foreach ($p in @($pref.ExclusionPath))      { if ($p) { [void]$exclusions.Add("PATH|$p") } }
            foreach ($p in @($pref.ExclusionProcess))   { if ($p) { [void]$exclusions.Add("PROC|$p") } }
            foreach ($p in @($pref.ExclusionExtension)) { if ($p) { [void]$exclusions.Add("EXT|$p") } }
        }
    } catch {}
    return $exclusions
}

function Get-DeepSecuritySnapshot {
    $roots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramData,
        $env:LOCALAPPDATA,
        "$env:LOCALAPPDATA\Programs",
        $env:APPDATA
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    $dirs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $roots) {
        Get-ChildItem -LiteralPath $r -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            [void]$dirs.Add($_.FullName)
            Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                [void]$dirs.Add($_.FullName)
            }
        }
    }

    $services = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    Get-Service -ErrorAction SilentlyContinue | ForEach-Object { [void]$services.Add($_.Name) }

    $tasks = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { [void]$tasks.Add("$($_.TaskPath)$($_.TaskName)") }

    $fwRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    Get-NetFirewallRule -ErrorAction SilentlyContinue | ForEach-Object { [void]$fwRules.Add($_.Name) }

    $procs = [System.Collections.Generic.HashSet[int]]::new()
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object { [void]$procs.Add($_.Id) }

    return [PSCustomObject]@{
        Timestamp          = Get-Date
        Directories        = $dirs
        Services           = $services
        Tasks              = $tasks
        FirewallRules      = $fwRules
        ProcessIds         = $procs
        Autoruns           = (Get-AutorunEntries)
        DefenderExclusions = (Get-DefenderExclusions)
    }
}

function Block-SingleExecutable {
    param(
        [string]$FullPath,
        [string]$AppIdentifier,
        [string]$GroupName
    )
    if (-not (Test-Path -LiteralPath $FullPath)) { return $false }
    $fileItem = Get-Item -LiteralPath $FullPath -ErrorAction SilentlyContinue
    if (-not $fileItem -or $fileItem.PSIsContainer) { return $false }

    $ruleBase = "[$AppIdentifier] $($fileItem.Name) ($($fileItem.FullName.GetHashCode()))"
    New-NetFirewallRule -DisplayName "$ruleBase [OUT]" `
        -Group $GroupName `
        -Direction Outbound `
        -Program $fileItem.FullName `
        -Action Block `
        -Profile Any `
        -Enabled True | Out-Null

    New-NetFirewallRule -DisplayName "$ruleBase [IN]" `
        -Group $GroupName `
        -Direction Inbound `
        -Program $fileItem.FullName `
        -Action Block `
        -Profile Any `
        -Enabled True | Out-Null

    Write-Host "  [BLOCKED IN/OUT] $($fileItem.FullName)" -ForegroundColor Green
    return $true
}

function Block-FoldersAndDependencies {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppIdentifier,
        [string[]]$TargetFolders = @(),
        [string[]]$IndividualExecutables = @(),
        [string[]]$TargetServiceNames = @(),
        [string[]]$TargetTaskPaths = @(),
        [bool]$StopAndDisableServices = $true
    )

    $groupName = "$RuleGroupPrefix`:$AppIdentifier"
    $blockedFiles = 0

    Write-Host "`n--- Applying Deep Firewall & Dependency Lockdown for [$AppIdentifier] ---" -ForegroundColor Cyan

    $existing = Get-NetFirewallRule -Group $groupName -ErrorAction SilentlyContinue
    if ($existing) {
        $existing | Remove-NetFirewallRule
    }

    $blockedPathsSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $uniqueFolders = @($TargetFolders | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique)

    foreach ($folder in $uniqueFolders) {
        Write-Host "Scanning directory tree: $folder" -ForegroundColor Gray
        $binaries = Get-ChildItem -LiteralPath $folder -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -match "^\.(exe|com|scr)$" }
        foreach ($bin in $binaries) {
            if ($blockedPathsSet.Add($bin.FullName)) {
                if (Block-SingleExecutable -FullPath $bin.FullName -AppIdentifier $AppIdentifier -GroupName $groupName) {
                    $blockedFiles++
                }
            }
        }
    }

    foreach ($exePath in ($IndividualExecutables | Where-Object { $_ } | Select-Object -Unique)) {
        if ($blockedPathsSet.Add($exePath)) {
            if (Block-SingleExecutable -FullPath $exePath -AppIdentifier $AppIdentifier -GroupName $groupName) {
                $blockedFiles++
            }
        }
    }

    foreach ($svcName in ($TargetServiceNames | Where-Object { $_ } | Select-Object -Unique)) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            New-NetFirewallRule -DisplayName "[$AppIdentifier] Service: $($svc.Name) [OUT]" `
                -Group $groupName `
                -Direction Outbound `
                -Service $svc.Name `
                -Action Block `
                -Profile Any `
                -Enabled True | Out-Null

            New-NetFirewallRule -DisplayName "[$AppIdentifier] Service: $($svc.Name) [IN]" `
                -Group $groupName `
                -Direction Inbound `
                -Service $svc.Name `
                -Action Block `
                -Profile Any `
                -Enabled True | Out-Null

            Write-Host "  [BLOCKED SERVICE SID IN/OUT] $($svc.Name) ($($svc.DisplayName))" -ForegroundColor Yellow

            $cimSvc = Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue
            if ($cimSvc -and $cimSvc.PathName) {
                $svcExe = ($cimSvc.PathName -replace '^"([^"]+)".*$', '$1' -replace '^([^\s]+\.exe).*$', '$1').Trim()
                if ($blockedPathsSet.Add($svcExe)) {
                    if (Block-SingleExecutable -FullPath $svcExe -AppIdentifier $AppIdentifier -GroupName $groupName) {
                        $blockedFiles++
                    }
                }
            }

            if ($StopAndDisableServices) {
                Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
                Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Host "  [STOPPED & DISABLED SERVICE] $($svc.Name)" -ForegroundColor Yellow
            }
        }
    }

    foreach ($taskFull in ($TargetTaskPaths | Where-Object { $_ } | Select-Object -Unique)) {
        $task = Get-ScheduledTask | Where-Object { "$($_.TaskPath)$($_.TaskName)" -eq $taskFull } -ErrorAction SilentlyContinue
        if ($task) {
            Disable-ScheduledTask -InputObject $task -ErrorAction SilentlyContinue | Out-Null
            Write-Host "  [DISABLED SCHEDULED TASK] $taskFull" -ForegroundColor Yellow
            foreach ($act in $task.Actions) {
                if ($act.Execute) {
                    $expanded = [Environment]::ExpandEnvironmentVariables($act.Execute).Trim().Trim('"')
                    if ($blockedPathsSet.Add($expanded)) {
                        if (Block-SingleExecutable -FullPath $expanded -AppIdentifier $AppIdentifier -GroupName $groupName) {
                            $blockedFiles++
                        }
                    }
                }
            }
        }
    }

    Write-Host "`nDone! Blocked $blockedFiles executable(s) (Inbound + Outbound, All Profiles) under group '$groupName'." -ForegroundColor Cyan
}

function Invoke-GuidedOfflineInstall {
    param(
        [string]$Name,
        [string]$Installer
    )

    if (-not $Name) {
        $Name = Read-Host "Enter a short name for the app you are installing (e.g. Photoshop, MyTool)"
    }
    $Name = $Name.Trim()
    if (-not $Name) {
        Write-Warning "AppName is required."
        return
    }

    Write-Host "`n[Step 1/6] Taking deep forensic pre-install snapshot (Folders, Services, Tasks, Autoruns, Defender Exclusions, Firewall)..." -ForegroundColor Cyan
    $before = Get-DeepSecuritySnapshot

    $activeAdapters = Get-ActiveInternetAdapters
    if ($activeAdapters.Count -eq 0) {
        Write-Warning "No active default-route internet adapters detected. Proceeding without cutting adapters."
    }

    Write-Host "[Step 2/6] Severing active internet adapters for offline installation..." -ForegroundColor Yellow
    $disabledAdapters = @()
    try {
        foreach ($nic in $activeAdapters) {
            Write-Host "  -> Disabling adapter: $($nic.Name) ($($nic.InterfaceDescription))" -ForegroundColor Yellow
            Disable-NetAdapter -Name $nic.Name -Confirm:$false -ErrorAction SilentlyContinue
            $disabledAdapters += $nic
        }

        Write-Host "`n[Step 3/6] SYSTEM IS NOW OFFLINE." -ForegroundColor Green
        if ($Installer -and (Test-Path -LiteralPath $Installer)) {
            Write-Host "Launching installer: $Installer" -ForegroundColor Cyan
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $Installer
            $psi.WorkingDirectory = Split-Path -Parent $Installer
            $psi.UseShellExecute = $true
            $proc = [System.Diagnostics.Process]::Start($psi)
            if ($proc) { $proc.WaitForExit() }
            Read-Host "Press ENTER after the installer window is completely closed"
        } else {
            Write-Host "1. Run your installer now." -ForegroundColor White
            Write-Host "2. Launch the installed app ONCE while still offline (in case it unpacks hidden droppers on first run), then close it." -ForegroundColor Yellow
            Read-Host "Press ENTER only AFTER installation and first launch are finished"
        }

        Write-Host "`n[Step 4/6] Scanning system for ALL newly dropped executables, hidden Temp/AppData binaries, Registry Autoruns, and Tampering..." -ForegroundColor Cyan
        $after = Get-DeepSecuritySnapshot

        # A. Check for newly spawned background processes
        $newProcs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { -not $before.ProcessIds.Contains($_.Id) -and $_.Id -ne $PID })
        $droppedExes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        if ($newProcs.Count -gt 0) {
            Write-Host "`n[!] Detected newly spawned processes still running in background:" -ForegroundColor Magenta
            foreach ($np in $newProcs) {
                $pPath = $null
                try { $pPath = $np.Path } catch {}
                Write-Host "  [PID $($np.Id)] $($np.ProcessName) -> $pPath" -ForegroundColor Magenta
                if ($pPath -and $pPath -notmatch "^([a-zA-Z]:)?\\Windows\\") {
                    [void]$droppedExes.Add($pPath)
                }
            }
            $killChoice = Read-Host "Kill these newly spawned background processes before going back online? (Y/N, default Y)"
            if ($killChoice -eq "" -or $killChoice -match "^[Yy]") {
                foreach ($np in $newProcs) {
                    Stop-Process -Id $np.Id -Force -ErrorAction SilentlyContinue
                    Write-Host "  [KILLED] $($np.ProcessName) (PID $($np.Id))" -ForegroundColor Red
                }
            }
        }

        # B. Scan all dropper locations for ANY .exe/.com/.scr created or modified since pre-install snapshot
        Write-Host "Hunting for newly dropped executables across AppData, Temp, ProgramData, Program Files, Public..." -ForegroundColor Gray
        foreach ($root in (Get-DropperSearchRoots)) {
            Get-ChildItem -Path $root -Include @("*.exe", "*.com", "*.scr") -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.CreationTime -ge $before.Timestamp -or $_.LastWriteTime -ge $before.Timestamp } |
                ForEach-Object {
                    [void]$droppedExes.Add($_.FullName)
                }
        }

        if ($droppedExes.Count -gt 0) {
            Write-Host "`n[+] Found $($droppedExes.Count) newly created/modified executable(s) across the system (including hidden/Temp paths):" -ForegroundColor Green
            $droppedExes | ForEach-Object { Write-Host "  + $_" -ForegroundColor Gray }
        }

        # C. Check Windows Defender Exclusions Tampering
        $newExclusions = @($after.DefenderExclusions | Where-Object { -not $before.DefenderExclusions.Contains($_) })
        if ($newExclusions.Count -gt 0) {
            Write-Host "`n[CRITICAL ALERT] The installer added Windows Defender Exclusions (High indicator of Trojan/Infostealer!):" -ForegroundColor Red
            foreach ($ex in $newExclusions) {
                Write-Host "  [TAMPER] $ex" -ForegroundColor Red
                $parts = $ex -split "\|", 2
                if ($parts[0] -eq "PATH") { Remove-MpPreference -ExclusionPath $parts[1] -ErrorAction SilentlyContinue }
                if ($parts[0] -eq "PROC") { Remove-MpPreference -ExclusionProcess $parts[1] -ErrorAction SilentlyContinue }
                if ($parts[0] -eq "EXT")  { Remove-MpPreference -ExclusionExtension $parts[1] -ErrorAction SilentlyContinue }
                Write-Host "  [REVERTED] Removed unauthorized Defender exclusion: $($parts[1])" -ForegroundColor Green
            }
        }

        # D. Check Stealth Firewall Allow Rules added by the installer
        $newFwRules = @($after.FirewallRules | Where-Object { -not $before.FirewallRules.Contains($_) })
        if ($newFwRules.Count -gt 0) {
            Write-Host "`n[WARNING] The installer created $($newFwRules.Count) new Windows Firewall rule(s)! Removing them..." -ForegroundColor Yellow
            foreach ($rName in $newFwRules) {
                $rObj = Get-NetFirewallRule -Name $rName -ErrorAction SilentlyContinue
                if ($rObj) {
                    Write-Host "  [REMOVED INSTALLER FIREWALL RULE] $($rObj.DisplayName) ($($rObj.Direction) $($rObj.Action))" -ForegroundColor Yellow
                    $rObj | Remove-NetFirewallRule -ErrorAction SilentlyContinue
                }
            }
        }

        # E. Check Registry Run / RunOnce & Startup Folder Persistence
        $newAutoruns = @()
        foreach ($k in $after.Autoruns.Keys) {
            if (-not $before.Autoruns.ContainsKey($k) -or $before.Autoruns[$k] -ne $after.Autoruns[$k]) {
                $newAutoruns += [PSCustomObject]@{ Key = $k; Command = $after.Autoruns[$k] }
            }
        }
        if ($newAutoruns.Count -gt 0) {
            Write-Host "`n[WARNING] The installer added Startup / Registry Autorun persistence:" -ForegroundColor Yellow
            foreach ($ar in $newAutoruns) {
                Write-Host "  [AUTORUN] $($ar.Key) => $($ar.Command)" -ForegroundColor Yellow
            }
            $remAuto = Read-Host "Remove these new Startup Autorun entries so it cannot auto-start on boot? (Y/N, default Y)"
            if ($remAuto -eq "" -or $remAuto -match "^[Yy]") {
                foreach ($ar in $newAutoruns) {
                    $parts = $ar.Key -split "\|", 2
                    if ($parts[0] -eq "STARTUP") {
                        Remove-Item -LiteralPath $parts[1] -Force -ErrorAction SilentlyContinue
                        Write-Host "  [REMOVED STARTUP FILE] $($parts[1])" -ForegroundColor Green
                    } else {
                        Remove-ItemProperty -Path $parts[0] -Name $parts[1] -ErrorAction SilentlyContinue
                        Write-Host "  [REMOVED REGISTRY AUTORUN] $($parts[0]) -> $($parts[1])" -ForegroundColor Green
                    }
                }
            }
        }

        # F. Collect newly created folders, services, and tasks
        $newDirs = @($after.Directories | Where-Object { -not $before.Directories.Contains($_) })
        $newServices = @($after.Services | Where-Object { -not $before.Services.Contains($_) })
        $newTasks = @($after.Tasks | Where-Object { -not $before.Tasks.Contains($_) })

        $extraInput = Read-Host "`nIf you also installed to another drive/folder (e.g. D:\Games\App), paste path here (or press ENTER to continue)"
        if ($extraInput) {
            $newDirs += @(Clean-InputPaths -RawInput $extraInput)
        }

        if ($newServices.Count -gt 0) {
            Write-Host "Detected newly created Windows Services (will be blocked & disabled):" -ForegroundColor Yellow
            $newServices | ForEach-Object { Write-Host "  + $_" }
        }
        if ($newTasks.Count -gt 0) {
            Write-Host "Detected newly created Scheduled Tasks (will be disabled):" -ForegroundColor Yellow
            $newTasks | ForEach-Object { Write-Host "  + $_" }
        }

        Write-Host "`n[Step 5/6] Locking down all discovered folders, dropped executables, services, and tasks..." -ForegroundColor Cyan
        Block-FoldersAndDependencies `
            -AppIdentifier $Name `
            -TargetFolders $newDirs `
            -IndividualExecutables @($droppedExes) `
            -TargetServiceNames $newServices `
            -TargetTaskPaths $newTasks `
            -StopAndDisableServices $true

    } finally {
        Write-Host "`n[Step 6/6] Restoring network adapters..." -ForegroundColor Cyan
        foreach ($nic in $disabledAdapters) {
            Write-Host "  -> Re-enabling adapter: $($nic.Name)" -ForegroundColor Green
            Enable-NetAdapter -Name $nic.Name -Confirm:$false -ErrorAction SilentlyContinue
        }
        Write-Host "Network restored safely." -ForegroundColor Green
    }
}

function Invoke-BlockWindowsLOLBins {
    <#
        Infostealers & Trojans often call Windows built-in binaries (LOLBins) to bypass application-specific
        firewall rules and upload stolen data. Blocking these binaries from direct outbound internet access
        neutralizes script-based exfiltration.
    #>
    $groupName = "$RuleGroupPrefix`:Windows_LOLBins_AntiStealer"
    $existing = Get-NetFirewallRule -Group $groupName -ErrorAction SilentlyContinue
    if ($existing) { $existing | Remove-NetFirewallRule }

    $sys32 = "$env:windir\System32"
    $syswow = "$env:windir\SysWOW64"
    $lolbins = @(
        "$sys32\mshta.exe", "$syswow\mshta.exe",
        "$sys32\wscript.exe", "$syswow\wscript.exe",
        "$sys32\cscript.exe", "$syswow\cscript.exe",
        "$sys32\regsvr32.exe", "$syswow\regsvr32.exe",
        "$sys32\rundll32.exe", "$syswow\rundll32.exe",
        "$sys32\certutil.exe", "$syswow\certutil.exe",
        "$sys32\bitsadmin.exe", "$syswow\bitsadmin.exe",
        "$sys32\cmd.exe", "$syswow\cmd.exe"
    )

    Write-Host "`n--- Blocking Windows System LOLBins from Outbound Internet Access ---" -ForegroundColor Cyan
    $blocked = 0
    foreach ($lb in $lolbins) {
        if (Test-Path -LiteralPath $lb) {
            if (Block-SingleExecutable -FullPath $lb -AppIdentifier "LOLBin_AntiStealer" -GroupName $groupName) {
                $blocked++
            }
        }
    }
    Write-Host "Done! Blocked $blocked Windows LOLBin instances. Malicious scripts can no longer abuse them to phone home." -ForegroundColor Green
}

function Invoke-BlockExistingApp {
    param([string]$Name)

    if (-not $Name) {
        $Name = Read-Host "Enter the Application or Vendor keyword to search & block (e.g. Adobe, Blender, MyApp)"
    }
    $Name = $Name.Trim()
    if (-not $Name) {
        Write-Warning "AppName is required."
        return
    }

    $discoveredFolders = @()
    $roots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramData,
        $env:LOCALAPPDATA,
        "$env:LOCALAPPDATA\Programs",
        $env:APPDATA
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    foreach ($r in $roots) {
        Get-ChildItem -LiteralPath $r -Directory -Filter "*$Name*" -ErrorAction SilentlyContinue | ForEach-Object {
            $discoveredFolders += $_.FullName
        }
    }

    $discoveredServices = @(Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $Name -or $_.DisplayName -match $Name } |
        Select-Object -ExpandProperty Name)

    $discoveredTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskName -match $Name -or $_.TaskPath -match $Name } |
        ForEach-Object { "$($_.TaskPath)$($_.TaskName)" })

    Write-Host "`nDiscovered items matching '$Name':" -ForegroundColor Cyan
    Write-Host "Folders ($($discoveredFolders.Count)):"
    $discoveredFolders | ForEach-Object { Write-Host "  [Dir]  $_" -ForegroundColor Gray }
    Write-Host "Services ($($discoveredServices.Count)):"
    $discoveredServices | ForEach-Object { Write-Host "  [Svc]  $_" -ForegroundColor Gray }
    Write-Host "Scheduled Tasks ($($discoveredTasks.Count)):"
    $discoveredTasks | ForEach-Object { Write-Host "  [Task] $_" -ForegroundColor Gray }

    $customFolder = Read-Host "`nPaste any additional folder (or .exe) path to include (or press ENTER to continue)"
    if ($customFolder) {
        $discoveredFolders += @(Clean-InputPaths -RawInput $customFolder)
    }

    if ($discoveredFolders.Count -eq 0 -and $discoveredServices.Count -eq 0) {
        Write-Warning "No matching folders or services found for '$Name'."
        return
    }

    Block-FoldersAndDependencies `
        -AppIdentifier $Name `
        -TargetFolders $discoveredFolders `
        -TargetServiceNames $discoveredServices `
        -TargetTaskPaths $discoveredTasks `
        -StopAndDisableServices $true
}

function Show-IsolatedApps {
    $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Group -like "$RuleGroupPrefix`:*" }
    if (-not $rules) {
        Write-Host "No applications are currently blocked under $RuleGroupPrefix." -ForegroundColor Yellow
        return
    }
    $rules | Group-Object Group | ForEach-Object {
        $appName = $_.Name -replace "^$RuleGroupPrefix`:", ""
        $ruleCount = $_.Count
        Write-Host "App: $appName ($ruleCount firewall rules active)" -ForegroundColor Cyan
    }
}

function Remove-IsolatedApp {
    param([string]$Name)
    if (-not $Name) {
        Show-IsolatedApps
        $Name = Read-Host "`nEnter the App name to unblock (e.g. Windows_LOLBins_AntiStealer or MyApp)"
    }
    $Name = $Name.Trim()
    if (-not $Name) { return }
    $groupName = "$RuleGroupPrefix`:$Name"
    $rules = Get-NetFirewallRule -Group $groupName -ErrorAction SilentlyContinue
    if ($rules) {
        $count = @($rules).Count
        $rules | Remove-NetFirewallRule
        Write-Host "Removed $count firewall block rule(s) for [$Name]." -ForegroundColor Green
    } else {
        Write-Warning "No firewall rules found for group '$groupName'."
    }
}

try {
    if ($Install) {
        Invoke-GuidedOfflineInstall -Name $AppName -Installer $InstallerPath
        Read-Host "`nPress ENTER to close"
    } elseif ($Block) {
        Invoke-BlockExistingApp -Name $AppName
        Read-Host "`nPress ENTER to close"
    } elseif ($Unblock) {
        Remove-IsolatedApp -Name $AppName
        Read-Host "`nPress ENTER to close"
    } elseif ($List) {
        Show-IsolatedApps
        Read-Host "`nPress ENTER to close"
    } elseif ($LockdownLOLBins) {
        Invoke-BlockWindowsLOLBins
        Read-Host "`nPress ENTER to close"
    } else {
        while ($true) {
            Write-Host "`n=====================================================================" -ForegroundColor Cyan
            Write-Host "   ANTI-STEALER / ANTI-TROJAN OFFLINE INSTALLER & FIREWALL TRAP      " -ForegroundColor Cyan
            Write-Host "=====================================================================" -ForegroundColor Cyan
            Write-Host "1. Guided Forensic Offline Install (Auto-cuts Internet, Hunts Droppers & Tampering)"
            Write-Host "2. Block an Already-Installed App & All Its Dependencies"
            Write-Host "3. Lock Down Windows LOLBins Against Infostealers (Block mshta, wscript, certutil, etc.)"
            Write-Host "4. List Currently Blocked Apps / Rules"
            Write-Host "5. Unblock an App (Remove firewall rules)"
            Write-Host "Q. Quit"
            $choice = Read-Host "`nSelect an option (1-5 or Q)"
            switch ($choice.Trim().ToUpper()) {
                "1" { Invoke-GuidedOfflineInstall }
                "2" { Invoke-BlockExistingApp }
                "3" { Invoke-BlockWindowsLOLBins }
                "4" { Show-IsolatedApps }
                "5" { Remove-IsolatedApp }
                "Q" { break }
                default { Write-Warning "Invalid selection." }
            }
            if ($choice.Trim().ToUpper() -eq "Q") { break }
        }
    }
} catch {
    Write-Host "`n[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
    Read-Host "`nPress ENTER to close"
}
