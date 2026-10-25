#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: summarize JEA transcript activity over a bounded window.
.NOTES
  Exposed through the McpBroker.ReadLocal JEA endpoint. DaysBack is ValidateRange(1,30)
  in the generated .psrc, bounding how much historical log a single call can pull.
#>
function Get-BrokerTranscriptSummary {
    [CmdletBinding()]
    param(
        [ValidateRange(1, 30)]
        [int] $DaysBack = 7
    )

    $dir = 'C:\McpBroker\Transcripts'
    if (-not (Test-Path $dir)) { return @() }

    $since = (Get-Date).AddDays(-$DaysBack)

    Get-ChildItem -Path $dir -Filter 'PowerShell_transcript*.txt' -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $since } |
        Group-Object { $_.LastWriteTime.Date } |
        ForEach-Object {
            [pscustomobject]@{
                Date            = $_.Name
                TranscriptCount = $_.Count
            }
        }
}

Export-ModuleMember -Function Get-BrokerTranscriptSummary
