#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs Pathology as a Windows service.

.DESCRIPTION
    Copies pathology.exe to Program Files, prepares a data directory writable by
    the service account (NT AUTHORITY\LocalService), places the configuration in
    ProgramData, optionally stores secret environment variables for the service,
    and registers the service with "pathology service install".

.PARAMETER Binary
    Path to pathology.exe (defaults to the copy next to this script).

.PARAMETER Config
    TOML configuration to install. Existing configuration is never overwritten.

.PARAMETER EnvFile
    Optional KEY=value file with secrets (bot tokens, routing keys, ...). They
    are stored in the service's registry Environment value, which local
    administrators can read. Keep the host's administrator group small.

.EXAMPLE
    .\install-service.ps1 -Config .\pathology.toml -EnvFile .\pathology.env
#>
[CmdletBinding()]
param(
    [string]$Binary = (Join-Path $PSScriptRoot 'pathology.exe'),
    [Parameter(Mandatory = $true)][string]$Config,
    [string]$EnvFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$serviceName = 'pathology'
$installDir = Join-Path $env:ProgramFiles 'LLCForge\pathology'
$dataDir = Join-Path $env:ProgramData 'LLCForge\pathology'
$configPath = Join-Path $dataDir 'pathology.toml'

if (-not (Test-Path -LiteralPath $Binary)) { throw "Binary not found: $Binary" }
if (-not (Test-Path -LiteralPath $Config)) { throw "Config not found: $Config" }
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    throw "Service '$serviceName' already exists. Run 'pathology service uninstall' first."
}

New-Item -ItemType Directory -Force -Path $installDir, $dataDir | Out-Null
Copy-Item -LiteralPath $Binary -Destination (Join-Path $installDir 'pathology.exe') -Force

if (Test-Path -LiteralPath $configPath) {
    Write-Host "Keeping existing configuration $configPath"
} else {
    Copy-Item -LiteralPath $Config -Destination $configPath
}

# Data dir: LocalService may modify; inherited Users access removed.
& icacls.exe $dataDir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' 'NT AUTHORITY\LocalService:(OI)(CI)M' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls failed with exit code $LASTEXITCODE" }

$exe = Join-Path $installDir 'pathology.exe'
& $exe service install --config $configPath
if ($LASTEXITCODE -ne 0) { throw "'pathology service install' failed with exit code $LASTEXITCODE" }

$envVars = @("STATE_DIRECTORY=$dataDir")
if ($EnvFile) {
    if (-not (Test-Path -LiteralPath $EnvFile)) { throw "EnvFile not found: $EnvFile" }
    foreach ($line in Get-Content -LiteralPath $EnvFile) {
        $t = $line.Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        if ($t -notmatch '^[A-Za-z_][A-Za-z0-9_]*=') { throw "Invalid line in EnvFile (expected KEY=value): $t" }
        $envVars += $t
    }
}
$key = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
New-ItemProperty -Path $key -Name 'Environment' -PropertyType MultiString -Value $envVars -Force | Out-Null

Start-Service -Name $serviceName
Get-Service -Name $serviceName | Format-Table -AutoSize Name, Status, StartType
Write-Host "To debug: Stop-Service $serviceName, then run '$exe run --config $configPath' in a console."
