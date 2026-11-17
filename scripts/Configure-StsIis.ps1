<#
.SYNOPSIS
    Prepares the IIS host for the Mini-STS site so that:
      - / and /FederationMetadata can be served WITHOUT a client-cert prompt
      - /wsfed performs per-URL TLS renegotiation to collect the client cert

.DESCRIPTION
    Given ONLY the HTTPS binding (Hostname:port), this script:
      1. Reads the binding from `netsh http show sslcert` to discover the
         certificate hash, application id, and current Negotiate Client
         Certificate state.
      2. Discovers the IIS site bound to that Hostname:port and the
         application pool it uses.
      3. Unlocks system.webServer/security/access at the server level so
         <location path="wsfed"> in web.config is honored instead of 404'd.
      4. (Optional) Forces clientcertnegotiation=disable on the binding by
         deleting and re-adding the sslcert mapping with the discovered
         certhash / appid.
      5. Recycles the discovered application pool so the new web.config takes
         effect.
      6. Prints a final summary and a smoke-test checklist.

    Run elevated:
        powershell -ExecutionPolicy Bypass -File .\Configure-StsIis.ps1
        powershell -ExecutionPolicy Bypass -File .\Configure-StsIis.ps1 -HostnamePort some.host:443
        powershell -ExecutionPolicy Bypass -File .\Configure-StsIis.ps1 -ForceDisableNegotiation

.PARAMETER HostnamePort
    The HTTPS binding to operate on, in 'host:port' form. Defaults to
    federation.lab.navintechnologies.com:443.

.PARAMETER ForceDisableNegotiation
    If set, and the binding currently has 'Negotiate Client Certificate'
    enabled, the script will delete and re-add the sslcert mapping with
    clientcertnegotiation=disable. Otherwise, only a warning is printed.
#>

[CmdletBinding()]
param(
    [string]$HostnamePort = 'federation.lab.navintechnologies.com:443',
    [switch]$ForceDisableNegotiation
)

$ErrorActionPreference = 'Stop'

# ---------- helpers ---------------------------------------------------------

function Assert-Elevated {
    $isAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        throw 'This script must be run from an elevated PowerShell session.'
    }
}

function Write-Step([string]$msg) {
    Write-Host ''
    Write-Host "==> $msg" -ForegroundColor Cyan
}

function Get-Field {
    param(
        [Parameter(Mandatory)] [string] $Text,
        [Parameter(Mandatory)] [string] $Label
    )
    $line = ($Text -split "`r?`n") |
        Where-Object { $_ -match [regex]::Escape($Label) } |
        Select-Object -First 1
    if (-not $line) { return $null }
    return ($line -split ':', 2)[1].Trim()
}

function Get-SslCertBinding {
    param([Parameter(Mandatory)] [string] $HostnamePort)

    # Try hostname:port form first (SNI binding), then fall back to ipport=
    $output = (& netsh http show sslcert hostnameport=$HostnamePort) -join "`n"
    if ($LASTEXITCODE -ne 0 -or ($output -notmatch 'Certificate Hash')) {
        $output = (& netsh http show sslcert ipport=$HostnamePort) -join "`n"
    }
    if ($output -notmatch 'Certificate Hash') {
        throw "No sslcert binding found for '$HostnamePort'. Check 'netsh http show sslcert'."
    }

    [pscustomobject]@{
        Raw                        = $output
        CertificateHash            = Get-Field $output 'Certificate Hash'
        ApplicationId              = Get-Field $output 'Application ID'
        CertificateStoreName       = (Get-Field $output 'Certificate Store Name') -as [string]
        NegotiateClientCertificate = Get-Field $output 'Negotiate Client Certificate'
    }
}

function Find-WebsiteByHostnamePort {
    param([Parameter(Mandatory)] [string] $HostnamePort)

    Import-Module WebAdministration -ErrorAction Stop

    $parts = $HostnamePort -split ':'
    if ($parts.Count -ne 2) {
        throw "HostnamePort '$HostnamePort' must be in 'host:port' form."
    }
    $hostName = $parts[0]
    $port     = $parts[1]

    $sites = Get-ChildItem 'IIS:\Sites'
    foreach ($site in $sites) {
        foreach ($b in $site.Bindings.Collection) {
            # bindingInformation is "ip:port:hostheader" e.g. "*:443:federation.lab..."
            $bi = $b.bindingInformation
            $biParts = $bi -split ':'
            if ($biParts.Count -ge 3) {
                $biPort = $biParts[1]
                $biHost = $biParts[2]
                if ($biPort -eq $port -and
                    ($biHost -ieq $hostName -or [string]::IsNullOrEmpty($biHost))) {
                    return [pscustomobject]@{
                        Site           = $site
                        AppPoolName    = $site.applicationPool
                        PhysicalPath   = $site.physicalPath
                        MatchedBinding = $bi
                        Protocol       = $b.protocol
                    }
                }
            }
        }
    }
    return $null
}

# ---------- main ------------------------------------------------------------

Assert-Elevated

$appcmd = Join-Path $env:windir 'system32\inetsrv\appcmd.exe'
if (-not (Test-Path $appcmd)) {
    throw "appcmd.exe not found at $appcmd. Is IIS installed?"
}

# 1. Discover binding details from netsh
Write-Step "Reading sslcert binding for $HostnamePort"
$binding = Get-SslCertBinding -HostnamePort $HostnamePort
$binding.Raw | Out-Host

if (-not $binding.CertificateHash -or -not $binding.ApplicationId) {
    throw 'Could not parse Certificate Hash / Application ID from netsh output.'
}

# 2. Discover IIS site / app pool serving that binding
Write-Step "Discovering IIS site bound to $HostnamePort"
$siteInfo = Find-WebsiteByHostnamePort -HostnamePort $HostnamePort
if (-not $siteInfo) {
    throw "No IIS site has a binding matching '$HostnamePort'. Check Get-Website | ft Name, Bindings."
}
Write-Host ("  Site         : {0}" -f $siteInfo.Site.Name)
Write-Host ("  App Pool     : {0}" -f $siteInfo.AppPoolName)
Write-Host ("  Physical Path: {0}" -f $siteInfo.PhysicalPath)
Write-Host ("  Binding      : {0} ({1})" -f $siteInfo.MatchedBinding, $siteInfo.Protocol)

# 3. Unlock system.webServer/security/access at the server level
Write-Step 'Unlocking system.webServer/security/access at the server level'
& $appcmd unlock config -section:"system.webServer/security/access" | Out-Host
if ($LASTEXITCODE -ne 0) {
    Write-Host "  (appcmd exit code $LASTEXITCODE - likely already unlocked; continuing.)" -ForegroundColor Yellow
}

Write-Step 'Verifying the section override mode'
& $appcmd list config -section:"system.webServer/security/access" 2>&1 | Out-Host

# 4. Optionally force clientcertnegotiation=disable on the binding
if ($binding.NegotiateClientCertificate -ne 'Disabled') {
    if ($ForceDisableNegotiation) {
        Write-Step "Disabling binding-level client cert negotiation on $HostnamePort"
        $storeName = if ([string]::IsNullOrWhiteSpace($binding.CertificateStoreName)) { 'My' } else { $binding.CertificateStoreName }

        & netsh http delete sslcert hostnameport=$HostnamePort | Out-Host
        if ($LASTEXITCODE -ne 0) {
            & netsh http delete sslcert ipport=$HostnamePort | Out-Host
        }

        & netsh http add sslcert `
            hostnameport=$HostnamePort `
            certhash=$($binding.CertificateHash) `
            appid="$($binding.ApplicationId)" `
            certstorename=$storeName `
            clientcertnegotiation=disable | Out-Host

        # Re-read to confirm
        $binding = Get-SslCertBinding -HostnamePort $HostnamePort
        Write-Host ("  Negotiate Client Certificate is now: {0}" -f $binding.NegotiateClientCertificate) -ForegroundColor Green
    }
    else {
        Write-Host ''
        Write-Warning "Binding currently has 'Negotiate Client Certificate : $($binding.NegotiateClientCertificate)'."
        Write-Warning 'Every URL on this binding will prompt for a cert, including /FederationMetadata.'
        Write-Warning 'Re-run with -ForceDisableNegotiation to fix automatically, or run manually:'
        Write-Warning ("  netsh http delete sslcert hostnameport={0}" -f $HostnamePort)
        Write-Warning ("  netsh http add sslcert hostnameport={0} certhash={1} appid=`"{2}`" certstorename=My clientcertnegotiation=disable" -f `
            $HostnamePort, $binding.CertificateHash, $binding.ApplicationId)
    }
}

# 5. Recycle the discovered application pool
Write-Step "Recycling application pool '$($siteInfo.AppPoolName)'"
if (-not (Test-Path "IIS:\AppPools\$($siteInfo.AppPoolName)")) {
    Write-Host "  App pool '$($siteInfo.AppPoolName)' not found - skipping recycle." -ForegroundColor Yellow
} else {
    Restart-WebAppPool -Name $siteInfo.AppPoolName
    Write-Host "  App pool '$($siteInfo.AppPoolName)' recycled."
}

# 6. Final summary
Write-Step 'Final state'
Write-Host ("  Hostname:port                : {0}" -f $HostnamePort)
Write-Host ("  Certificate Hash             : {0}" -f $binding.CertificateHash)
Write-Host ("  Application ID               : {0}" -f $binding.ApplicationId)
Write-Host ("  Certificate Store Name       : {0}" -f $binding.CertificateStoreName)
Write-Host ("  Negotiate Client Certificate : {0}" -f $binding.NegotiateClientCertificate)
Write-Host ("  IIS Site                     : {0}" -f $siteInfo.Site.Name)
Write-Host ("  IIS App Pool                 : {0}" -f $siteInfo.AppPoolName)
Write-Host ("  Site Physical Path           : {0}" -f $siteInfo.PhysicalPath)

$hostName = ($HostnamePort -split ':')[0]
Write-Host ''
Write-Host 'Done.' -ForegroundColor Green
Write-Host 'Smoke test in this order from a fresh InPrivate/Incognito window:'
Write-Host ("  1. https://{0}/                                                              (no cert prompt)" -f $hostName)
Write-Host ("  2. https://{0}/FederationMetadata/2007-06/FederationMetadata.xml             (no cert prompt)" -f $hostName)
Write-Host ("  3. https://{0}/wsfed?wa=wsignin1.0&wtrealm=...                               (cert prompt)" -f $hostName)
