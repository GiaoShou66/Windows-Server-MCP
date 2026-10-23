#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: list files and folders under an absolute path. Metadata only.
.NOTES
  Path is ValidatePattern-constrained in the generated .psrc: the negative lookahead
  blocks any ".." substring (directory traversal), and the pattern requires a
  drive-letter-absolute path. Bounded to 500 entries. File CONTENT is never read —
  only name/size/timestamp metadata, which is why this tool is still read tier.

  The regex only rejects traversal syntax — it does not scope WHERE a caller can browse,
  so a syntactically valid absolute path could still point at a security-sensitive
  location (SAM/SYSTEM hive backups, DPAPI master keys, machine key material, other
  users' profiles). That is a real exposure a pattern match can't express semantically,
  so this function adds an explicit denylist of sensitive path prefixes as defense in
  depth beyond the JEA/broker-level allowlist.
#>
function Get-BrokerListDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^(?!.*\.\.)[A-Za-z]:\\.*$')]
        [ValidateLength(1, 260)]
        [string] $Path
    )

    $deniedPrefixes = @(
        "$env:SystemRoot\System32\config",
        "$env:SystemRoot\System32\drivers",
        "$env:ProgramData\Microsoft\Crypto",
        "$env:SystemDrive\Users"
    )

    $normalized = $Path.TrimEnd('\')
    foreach ($prefix in $deniedPrefixes) {
        $prefixNormalized = $prefix.TrimEnd('\')
        if ($normalized -eq $prefixNormalized -or $normalized.StartsWith("$prefixNormalized\", [StringComparison]::OrdinalIgnoreCase)) {
            throw "Access to '$Path' is denied by policy (sensitive system location)."
        }
    }

    Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop | Select-Object -First 500 | ForEach-Object {
        [pscustomobject]@{
            Name          = $_.Name
            FullName      = $_.FullName
            IsDirectory   = $_.PSIsContainer
            LengthBytes   = if ($_.PSIsContainer) { $null } else { $_.Length }
            LastWriteTime = $_.LastWriteTime
        }
    }
}

Export-ModuleMember -Function Get-BrokerListDirectory
