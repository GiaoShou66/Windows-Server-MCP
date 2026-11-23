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

    $count = 0
    foreach ($update in @($wsus.GetUpdates($scope))) {
        if ($null -eq $update) { continue }
        if ($count -ge 200) { break }
        $count++
        [pscustomobject]@{
            Title                 = $update.Title
            Classification        = $update.UpdateClassificationTitle
            KnowledgeBaseArticles = ($update.KnowledgeBaseArticles -join ',')
            IsDeclined            = $update.IsDeclined
        }
    }
}

Export-ModuleMember -Function Get-BrokerWsusUpdates
