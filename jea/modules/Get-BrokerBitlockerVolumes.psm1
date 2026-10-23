#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate volumes and their BitLocker protection status on this host.
.NOTES
  Key material (recovery passwords, key protector IDs) is never included in the output —
  the manifest's maskedFields entry is defense in depth, not the only control.
#>
function Get-BrokerBitlockerVolumes {
    [CmdletBinding()]
    param()

    Import-Module BitLocker -ErrorAction Stop

    Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            MountPoint           = $_.MountPoint
            VolumeStatus         = $_.VolumeStatus.ToString()
            ProtectionStatus     = $_.ProtectionStatus.ToString()
            EncryptionPercentage = $_.EncryptionPercentage
        }
    }
}

Export-ModuleMember -Function Get-BrokerBitlockerVolumes
