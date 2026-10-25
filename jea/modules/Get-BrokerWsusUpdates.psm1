#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate updates awaiting approval on this WSUS server.
.NOTES
  Bounded to unapproved updates only, first 200 — avoids returning the entire catalog.
#>
function Get-BrokerWsusUpdates {
    [CmdletBinding()]
    param()

    Import-Module UpdateServices -ErrorAction Stop

    $wsus = Get-WsusServer -ErrorAction Stop
    $scope = New-Object Microsoft.UpdateServices.Administration.UpdateScope
    $scope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::NotApproved

    $wsus.GetUpdates($scope) | Select-Object -First 200 | ForEach-Object {
        [pscustomobject]@{
            Title                 = $_.Title
            Classification        = $_.UpdateClassificationTitle
            KnowledgeBaseArticles = ($_.KnowledgeBaseArticles -join ',')
            IsDeclined            = $_.IsDeclined
        }
    }
}

Export-ModuleMember -Function Get-BrokerWsusUpdates
