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

    # Allowlist of permitted root prefixes. In NoLanguage mode, reading arbitrary external files
    # at runtime is blocked, so permitted roots are defined statically in the wrapper.
    # An environment variable BROKER_ALLOWED_ROOTS can supply additional/override roots
    # (semicolon-separated) for environment-specific deployment or testing without file reads.
    # Reject any resolved path not under an allowed root, using canonicalized, case-insensitive
    # prefix matching.
    $allowedRoots = if ($env:BROKER_ALLOWED_ROOTS) {
        $env:BROKER_ALLOWED_ROOTS -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    } else {
        @(
            'C:\Shares',
            'C:\Data',
            'D:\Shares',
            'D:\Data'
        )
    }

    # Canonicalize Path (without trailing slash for uniform prefix comparison).
    $canonicalPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')

    $isAllowed = $false
    foreach ($root in $allowedRoots) {
        $canonicalRoot = [System.IO.Path]::GetFullPath($root).TrimEnd('\')
        if ($canonicalPath -eq $canonicalRoot -or $canonicalPath.StartsWith("$canonicalRoot\", [StringComparison]::OrdinalIgnoreCase)) {
            $isAllowed = $true
            break
        }
    }

    if (-not $isAllowed) {
        throw "Access to '$Path' is denied by policy (path is not under an allowed root)."
    }

    # Do not follow a junction, symlink, mount point, or other reparse point supplied
    # as the requested path. This is defense in depth; the service account ACL remains
    # the authoritative filesystem boundary.
    $current = [System.IO.Path]::GetPathRoot($Path).TrimEnd('\')
    foreach ($part in $Path.Substring($current.Length).Trim('\').Split('\')) {
        if ([string]::IsNullOrEmpty($part)) { continue }
        $current = Join-Path $current $part
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Access to '$Path' is denied by policy (reparse point)."
            }
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
