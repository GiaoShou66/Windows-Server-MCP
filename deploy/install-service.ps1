#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
  Installs the MCP broker as a Windows service running under a gMSA.
.DESCRIPTION
  Operator-run on the domain-joined Windows Server 2025 host. Does NOT run from the
  broker process itself (endpoint/service registration needs local admin; the broker
  never holds that privilege). Review every value before running.
.PARAMETER PublishDir
  Folder containing the published Broker.Host.exe (dotnet publish output).
.PARAMETER GmsaAccount
  Group Managed Service Account, e.g. 'CONTOSO\McpBrokerSvc$'.
.PARAMETER AllowedClientSid
  SID of the single client identity permitted to connect to the pipe.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $PublishDir,
    [Parameter(Mandatory = $true)] [string] $GmsaAccount,
    [Parameter(Mandatory = $true)] [string] $AllowedClientSid,
    [string] $ServiceName = 'McpBroker',
    [string] $TranscriptDir = 'C:\McpBroker\Transcripts'
)

$ErrorActionPreference = 'Stop'

$exe = Join-Path $PublishDir 'Broker.Host.exe'
if (-not (Test-Path $exe)) { throw "Broker.Host.exe not found in $PublishDir" }

function Assert-ProtectedDeploymentPath {
    param([Parameter(Mandatory = $true)] [string] $Path)

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $acl = Get-Acl -LiteralPath $resolved
    $broadPrincipals = @(
        'Everyone',
        'NT AUTHORITY\Authenticated Users',
        'BUILTIN\Users'
    )
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -eq 'Allow' -and
            ($broadPrincipals -contains $rule.IdentityReference.Value) -and
            (($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write) -ne 0 -or
             ($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Modify) -ne 0 -or
             ($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -ne 0)) {
            throw "Refusing deployment path '$resolved': a broad principal can modify it."
        }
    }
}

Assert-ProtectedDeploymentPath -Path $PublishDir
$signature = Get-AuthenticodeSignature -LiteralPath $exe
if ($signature.Status -ne 'Valid') {
    throw "Broker.Host.exe is not validly Authenticode-signed (status: $($signature.Status))."
}

# Transcript directory, writable by the gMSA only.
if (-not (Test-Path $TranscriptDir)) {
    New-Item -ItemType Directory -Path $TranscriptDir -Force | Out-Null
}
$acl = Get-Acl $TranscriptDir
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $GmsaAccount, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.SetAccessRule($rule)
Set-Acl -Path $TranscriptDir -AclObject $acl

# Verify the gMSA is installed and usable on this host before wiring the service.
Import-Module ActiveDirectory
if (-not (Test-ADServiceAccount -Identity ($GmsaAccount -replace '^.*\\','' -replace '\$$',''))) {
    throw "gMSA $GmsaAccount is not installed/usable on this host. Run Install-ADServiceAccount first."
}

# Register the service to run as the gMSA (no password; AD-managed).
$binPath = "`"$exe`""
sc.exe create $ServiceName binPath= $binPath start= auto obj= $GmsaAccount
sc.exe description $ServiceName "MCP broker: centralized, JEA-boundaried MCP tool execution."

# 'Log on as a service' for a gMSA is handled by SCM at service creation.
Write-Host "Service '$ServiceName' created."
Write-Host "Set Pipe:AllowedSids to include '$AllowedClientSid' in appsettings.json before starting."
Write-Host "Start with: Start-Service $ServiceName"
