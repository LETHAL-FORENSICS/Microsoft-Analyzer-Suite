Function Get-FileSize() {

<#
.SYNOPSIS
  Get-FileSize - Get file sizes in Bytes/KB/MB/GB/TB

.DESCRIPTION
  The Get-FileSize cmdlet returns the size of a file in human readable format.

.EXAMPLE
  Get-FileSize((Get-Item "$LogFile").Length)

.EXAMPLE
  Get-FileSize((Get-Item "$OUTPUT_FOLDER\OAuthPermissions\OAuthPermissions.xlsx").Length)

.NOTES
  Author - Martin Willing

.LINK
  https://lethal-forensics.com/
#>

Param ([long]$Length)
If ($Length -gt 1TB) {[string]::Format("{0:0.00} TB", $Length / 1TB)}
ElseIf ($Length -gt 1GB) {[string]::Format("{0:0.00} GB", $Length / 1GB)}
ElseIf ($Length -gt 1MB) {[string]::Format("{0:0.00} MB", $Length / 1MB)}
ElseIf ($Length -gt 1KB) {[string]::Format("{0:0.00} KB", $Length / 1KB)}
ElseIf ($Length -gt 0) {[string]::Format("{0:0.00} Bytes", $Length)}
Else {""}

}