#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
  Registers the generated JEA endpoints (.pssc) on this host.
.DESCRIPTION
  Operator-run after the broker's JeaConfigGenerator has produced .psrc/.pssc into the
  generated directory, and after the wrapper .psm1 modules are placed on a path the
  .psrc ModulesToImport can resolve. Copies role capabilities into a module layout and
  calls Register-PSSessionConfiguration per endpoint.
.PARAMETER GeneratedDir
  Directory containing the generated *.psrc and *.pssc files.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $GeneratedDir,
    [string] $ModulesSourceDir = (Join-Path $PSScriptRoot '..\jea\modules'),
    [string] $ModuleRoot = 'C:\Program Files\WindowsPowerShell\Modules\McpBrokerRoles',
    [string] $SystemModulesRoot = 'C:\Program Files\WindowsPowerShell\Modules'
)

$ErrorActionPreference = 'Stop'

# Role capabilities must live under <Module>\RoleCapabilities\*.psrc to be resolvable.
$rcDir = Join-Path $ModuleRoot 'RoleCapabilities'
New-Item -ItemType Directory -Path $rcDir -Force | Out-Null
Copy-Item -Path (Join-Path $GeneratedDir '*.psrc') -Destination $rcDir -Force

# A module manifest so PowerShell treats McpBrokerRoles as a module.
$psd1 = Join-Path $ModuleRoot 'McpBrokerRoles.psd1'
if (-not (Test-Path $psd1)) {
    New-ModuleManifest -Path $psd1 -ModuleVersion '1.0.0' -Description 'MCP broker JEA role capabilities'
}

# Install each wrapper module so the .psrc ModulesToImport can resolve the cmdlet.
# These .psm1 files MUST be Authenticode-signed (WDAC + the broker's own check require it).
if (Test-Path $ModulesSourceDir) {
    Get-ChildItem -Path $ModulesSourceDir -Filter '*.psm1' | ForEach-Object {
        $moduleName = $_.BaseName
        $dest = Join-Path $SystemModulesRoot $moduleName
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        Copy-Item -Path $_.FullName -Destination (Join-Path $dest "$moduleName.psm1") -Force
        $sig = Get-AuthenticodeSignature -FilePath $_.FullName
        if ($sig.Status -ne 'Valid') {
            Write-Warning "Module $moduleName is not validly signed (status: $($sig.Status)). The broker will refuse it at call time."
        }
        Write-Host "Installed wrapper module: $moduleName"
    }
}
else {
    Write-Warning "ModulesSourceDir '$ModulesSourceDir' not found; wrapper modules not installed."
}

Get-ChildItem -Path $GeneratedDir -Filter '*.pssc' | ForEach-Object {
    $name = [System.IO.Path]::GetFileNameWithoutExtension($_.Name)

    if (Get-PSSessionConfiguration -Name $name -ErrorAction SilentlyContinue) {
        Write-Host "Re-registering $name"
        Unregister-PSSessionConfiguration -Name $name -Force -ErrorAction SilentlyContinue
    }

    Register-PSSessionConfiguration -Name $name -Path $_.FullName -Force
    Write-Host "Registered JEA endpoint: $name"
}

Write-Host "Done. Verify with: Get-PSSessionConfiguration | Where-Object Name -like 'McpBroker.*'"
