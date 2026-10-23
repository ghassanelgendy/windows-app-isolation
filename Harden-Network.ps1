<#
.SYNOPSIS
    Harden-Network.ps1 - Windows Network, Protocol & Firewall Hardening Toolkit.
.DESCRIPTION
    Applies recommended security baselines to prevent lateral movement, credential theft, and unsolicited inbound exposure:
      1. Default Inbound Firewall Lockdown: Sets explicit DefaultInboundAction = Block across Domain, Private, and Public profiles.
      2. LLMNR Mitigation: Disables Link-Local Multicast Name Resolution (UDP 5355) to stop Responder/mitm spoofing attacks.
      3. NetBIOS over TCP/IP Mitigation: Disables NBT-NS across physical network interfaces.
      4. Disables Insecure Inbound Allow Rules: Turns off unsolicited inbound services (Network Discovery broadcasts, DIAL,
         Proximity sharing, Cast to Device, UPnP, WSD, Windows Media Player, Feedback Hub).
      5. Connected Devices Platform Lockdown: Stops CDPSvc and closes unnecessary listening ports (5040/5050).
      6. SMB Protocol Hardening: Enforces SMB signing and completely disables legacy SMBv1.
      7. Dynamic OpenSSH Hardening: If OpenSSH Server (sshd) is installed, automatically provisions administrator authorized keys
         from the current user's profile with strict ACLs and restricts SSH Port 22 to LAN / VPN subnets.
.EXAMPLE
    .\Harden-Network.ps1
    Executes full system network & protocol hardening.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "           WINDOWS NETWORK & PROTOCOL HARDENING TOOLKIT              " -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan

# 1. OpenSSH Server Hardening (if installed or keys present)
$userSshKey = Join-Path $env:USERPROFILE ".ssh\authorized_keys"
$adminSshKey = "$env:ProgramData\ssh\administrators_authorized_keys"
$sshDir = "$env:ProgramData\ssh"

if (Test-Path -LiteralPath $userSshKey) {
    Write-Host "`n=== 1. Hardening OpenSSH Server Authorized Keys ===" -ForegroundColor Cyan
    if (-not (Test-Path -LiteralPath $sshDir)) {
        New-Item -Path $sshDir -ItemType Directory -Force | Out-Null
    }
    Copy-Item -Path $userSshKey -Destination $adminSshKey -Force
    & icacls.exe $adminSshKey /inheritance:r /grant "SYSTEM:(F)" /grant "BUILTIN\Administrators:(F)" | Out-Null
    Write-Host "  [OK] Copied authorized_keys to $adminSshKey with locked ACLs." -ForegroundColor Green
}

if (Get-Service -Name "sshd" -ErrorAction SilentlyContinue) {
    Set-Service -Name "sshd" -StartupType Automatic
    Restart-Service -Name "sshd" -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] OpenSSH Server (sshd) restarted and set to Automatic startup." -ForegroundColor Green

    Remove-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -Name "OpenSSH-Server-Hardened" -ErrorAction SilentlyContinue
    New-NetFirewallRule -Name "OpenSSH-Server-Hardened" `
        -DisplayName "OpenSSH Server (Restricted to LAN & Tailscale - TCP 22)" `
        -Enabled True `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort 22 `
        -RemoteAddress "100.64.0.0/10","fd7a:115c:a1e0::/48","LocalSubnet" `
        -Action Allow `
        -Profile Any | Out-Null
    Write-Host "  [OK] Firewall Rule: SSH Port 22 restricted to Tailscale & LocalSubnet only." -ForegroundColor Green
}

# 2. Enforce Default Inbound Block
Write-Host "`n=== 2. Enforcing Default Inbound Block on All Firewall Profiles ===" -ForegroundColor Cyan
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -AutoSize

# 3. Disable LLMNR (UDP 5355)
Write-Host "=== 3. Disabling LLMNR (Link-Local Multicast Name Resolution Spoofing Protection) ===" -ForegroundColor Cyan
$dnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $dnsClientPath)) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name "DNSClient" -Force | Out-Null
}
Set-ItemProperty -Path $dnsClientPath -Name "EnableMultiCast" -Value 0 -Type DWord
Write-Host "  [OK] LLMNR disabled (EnableMultiCast = 0)." -ForegroundColor Green

# 4. Disable NetBIOS over TCP/IP
Write-Host "`n=== 4. Disabling NetBIOS over TCP/IP (NBT-NS Spoofing Protection) ===" -ForegroundColor Cyan
$adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True"
foreach ($adapter in $adapters) {
    if ($adapter.Description -match "(Tailscale|WireGuard|Virtual|Loopback)") { continue }
    $res = Invoke-CimMethod -InputObject $adapter -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 }
    Write-Host "  [OK] Adapter '$($adapter.Description)': NetBIOS disabled (Result: $($res.ReturnValue))" -ForegroundColor Green
}

# 5. Disable Unnecessary Inbound Rules
Write-Host "`n=== 5. Disabling Unnecessary Inbound Firewall Allow Rules ===" -ForegroundColor Cyan
$rulesToDisable = @(
    "Connected Devices Platform (TCP-In)",
    "Connected Devices Platform (UDP-In)",
    "AllJoyn Router (TCP-In)",
    "AllJoyn Router (UDP-In)",
    "Cast to Device functionality (qWave-TCP-In)",
    "Cast to Device functionality (qWave-UDP-In)",
    "Cast to Device streaming server (HTTP-Streaming-In)",
    "Cast to Device streaming server (RTCP-Streaming-In)",
    "Cast to Device streaming server (RTSP-Streaming-In)",
    "DIAL protocol server (HTTP-In)",
    "Game Bar",
    "Microsoft Media Foundation Network Source IN [TCP 554]",
    "Microsoft Media Foundation Network Source IN [UDP 5004-5009]",
    "Network Discovery (LLMNR-UDP-In)",
    "Network Discovery (NB-Datagram-In)",
    "Network Discovery (NB-Name-In)",
    "Network Discovery (Pub-WSD-In)",
    "Network Discovery (UPnP-In)",
    "Network Discovery (WSD Events-In)",
    "Network Discovery (WSD EventsSecure-In)",
    "Network Discovery (WSD-In)",
    "Proximity sharing over TCP (TCP sharing-In)",
    "Solitaire & Casual Games",
    "Windows Media Player",
    "Wireless Display (TCP-In)",
    "Wireless Display Infrastructure Back Channel (TCP-In)",
    "WFD ASP Coordination Protocol (UDP-In)",
    "WFD Driver-only (TCP-In)",
    "WFD Driver-only (UDP-In)"
)

$disabledCount = 0
foreach ($ruleName in $rulesToDisable) {
    $rules = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq "True" }
    if ($rules) {
        $rules | Disable-NetFirewallRule
        $disabledCount += @($rules).Count
        Write-Host "  [DISABLED INBOUND RULE] $ruleName" -ForegroundColor Yellow
    }
}

$uwpRules = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match "WindowsFeedbackHub|WindowsCamera|Microsoft\.Todos" }
if ($uwpRules) {
    $uwpRules | Disable-NetFirewallRule
    $disabledCount += @($uwpRules).Count
    Write-Host "  [DISABLED INBOUND RULES] Feedback Hub, Camera, To-Do ($(@($uwpRules).Count) rules)" -ForegroundColor Yellow
}
Write-Host "  [OK] Total unnecessary inbound Allow rules disabled: $disabledCount" -ForegroundColor Green

# 6. Stop CDPSvc
Write-Host "`n=== 6. Disabling Connected Devices Platform Service (CDPSvc / Ports 5040, 5050) ===" -ForegroundColor Cyan
Stop-Service -Name "CDPSvc" -Force -ErrorAction SilentlyContinue
Set-Service -Name "CDPSvc" -StartupType Manual -ErrorAction SilentlyContinue
Write-Host "  [OK] CDPSvc stopped and set to Manual." -ForegroundColor Green

# 7. Harden SMB
Write-Host "`n=== 7. Hardening SMB Server Configuration (Require SMB Signing & Disable SMBv1) ===" -ForegroundColor Cyan
Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true -EnableSecuritySignature $true -Force -ErrorAction SilentlyContinue
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature, EnableSecuritySignature | Format-Table -AutoSize

Write-Host "`n==================================================================" -ForegroundColor Cyan
Write-Host "  WINDOWS NETWORK HARDENING COMPLETED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "==================================================================" -ForegroundColor Cyan
Read-Host "`nPress ENTER to close"
