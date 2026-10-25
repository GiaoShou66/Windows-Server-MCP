#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
  Builds and deploys a WDAC code-integrity policy that permits only signed MCP servers,
  scoped to the expected install path.
.DESCRIPTION
  Durable kill switch (slower than manifest revocation). The path scope matters: a
  revoked-but-not-yet-WDAC-refreshed binary moved elsewhere still cannot execute.
  Start in Audit mode; promote to Enforced only after reviewing CodeIntegrity logs.
.PARAMETER ServerPath
  Directory where signed MCP server binaries/modules live, e.g. 'C:\McpBroker\jea'.
.PARAMETER Mode
  'Audit' (default) or 'Enforced'.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $ServerPath,
    [ValidateSet('Audit', 'Enforced')] [string] $Mode = 'Audit',
    [string] $PolicyDir = 'C:\McpBroker\wdac'
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $PolicyDir -Force | Out-Null

$xml = Join-Path $PolicyDir 'mcp-broker-policy.xml'
$bin = Join-Path $PolicyDir 'mcp-broker-policy.cip'

# Scan the signer+path scope. PcaCertificate level keys on the signing CA; combined
# with FilePath rules this restricts execution to signed binaries in the expected dir.
New-CIPolicy -FilePath $xml -ScanPath $ServerPath -Level PcaCertificate `
    -FilePathRules -UserPEs -Fallback Hash -ErrorAction Stop

# Default to audit so you can observe before enforcing.
Set-RuleOption -FilePath $xml -Option 3   # Audit Mode

if ($Mode -eq 'Enforced') {
    Set-RuleOption -FilePath $xml -Option 3 -Delete   # remove Audit Mode -> Enforced
}

ConvertFrom-CIPolicy -XmlFilePath $xml -BinaryFilePath $bin

Write-Host "WDAC policy built ($Mode): $bin"
Write-Host "Deploy with CiTool: citool --update-policy `"$bin`""
Write-Host "Review audit hits in Event Viewer: Microsoft-Windows-CodeIntegrity/Operational"
