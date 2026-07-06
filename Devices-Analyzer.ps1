# Devices-Analyzer
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2026 Martin Willing. All rights reserved. Licensed under the MIT license.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2026-07-06
#
#
# ██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
# ██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
# ██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
# ██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
# ███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
# ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
#
#
# Dependencies:
#
# ImportExcel v7.8.10 (2024-10-21)
# https://github.com/dfinke/ImportExcel
#
#
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.6456) and PowerShell 5.1 (5.1.19041.6456)
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.6456) and PowerShell 7.6.3
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  Devices-Analyzer - Automated Processing of Microsoft Entra ID Device Information for DFIR

.DESCRIPTION
  Devices-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of Microsoft Entra ID Device Information extracted via "Microsoft-Extractor-Suite" by Invictus Incident Response.

  https://github.com/invictus-ir/Microsoft-Extractor-Suite (Microsoft-Extractor-Suite v4.1.0)

  https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/Azure/Devices.html

.PARAMETER OutputDir
  Specifies the output directory. Default is "$env:USERPROFILE\Desktop\Devices-Analyzer".

  Note: The subdirectory 'Devices-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the CSV-based input file (*-Devices.csv).

.EXAMPLE
  PS> .\Devices-Analyzer.ps1

.EXAMPLE
  PS> .\Devices-Analyzer.ps1 -Path "$env:USERPROFILE\Desktop\*-Devices.csv"

.EXAMPLE
  PS> .\Devices-Analyzer.ps1 -Path "H:\Microsoft-Extractor-Suite\*-Devices.csv" -OutputDir "H:\Microsoft-Analyzer-Suite"

.NOTES
  Author - Martin Willing

.LINK
  https://lethal-forensics.com/
#>

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region CmdletBinding

[CmdletBinding()]
Param(
    [String]$Path,
    [String]$OutputDir
)

#endregion CmdletBinding

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Declarations

# Declarations

# Script Root
if ($PSVersionTable.PSVersion.Major -gt 2)
{
    # PowerShell 3+
    $SCRIPT_DIR = $PSScriptRoot
}
else
{
    # PowerShell 2
    $SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

# Output Directory
if (!($OutputDir))
{
    $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\Devices-Analyzer" # Default
}
else
{
    if ($OutputDir -cnotmatch '.+(?=\\)') 
    {
        Write-Host "[Error] You must provide a valid directory path." -ForegroundColor Red
        Exit
    }
    else
    {
        $script:OUTPUT_FOLDER = "$OutputDir\Devices-Analyzer" # Custom
    }
}

# Colors
Add-Type -AssemblyName System.Drawing
$script:Green  = [System.Drawing.Color]::FromArgb(0,176,80) # Green
$script:Orange = [System.Drawing.Color]::FromArgb(255,192,0) # Orange

# Configuration File (JSON)
if(!(Test-Path "$PSScriptRoot\Config.json"))
{
    Write-Host "[Error] Config.json NOT found." -ForegroundColor Red
    Exit
}
else
{
    $Config = Get-Content "$PSScriptRoot\Config.json" | ConvertFrom-Json

    # BackgroundColor
    if ($Config.ImportExcel.BackgroundColor)
    {
        if ($Config.ImportExcel.BackgroundColor -cnotmatch '^(([0-1]?[0-9]?[0-9])|([2][0-4][0-9])|(25[0-5])),(([0-1]?[0-9]?[0-9])|([2][0-4][0-9])|(25[0-5])),(([0-1]?[0-9]?[0-9])|([2][0-4][0-9])|(25[0-5]))$') # <0-255>,<0-255>,<0-255>
        {
            Write-Host "[Error] You must provide a valid RGB Color Code." -ForegroundColor Red
            Return
        }
    }

    # Excel - Color Scheme
    $script:BackgroundColor = [System.Drawing.Color]$Config.ImportExcel.BackgroundColor
    $script:FontColor       = $Config.ImportExcel.FontColor
}

#endregion Declarations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Header

# Check if the PowerShell script is being run with admin rights
if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "[Error] This PowerShell script must be run with admin rights." -ForegroundColor Red
    Exit
}

# Check if PowerShell module 'ImportExcel' is installed
if (!(Get-Module -ListAvailable -Name ImportExcel))
{
    Write-Host "[Error] Please install 'ImportExcel' PowerShell module." -ForegroundColor Red
    Write-Host "[Info]  Check out: https://github.com/evild3ad/Microsoft-Analyzer-Suite/wiki#setup"
    Exit
}

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "Devices-Analyzer - Automated Processing of Microsoft Entra ID Device Information for DFIR"

# Flush Output Directory
if (Test-Path "$OUTPUT_FOLDER")
{
    Get-ChildItem -Path "$OUTPUT_FOLDER" -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse
    New-Item "$OUTPUT_FOLDER" -ItemType Directory -Force | Out-Null
}
else 
{
    New-Item "$OUTPUT_FOLDER" -ItemType Directory -Force | Out-Null
}

# Import Functions
$FilePath = "$SCRIPT_DIR\Functions"
if (Test-Path "$FilePath")
{
    if (Test-Path "$FilePath\*.ps1") 
    {
        Get-ChildItem -Path "$FilePath" -Filter *.ps1 | ForEach-Object { . $_.FullName }
    }
}

# Select Log File
if(!($Path))
{
    Function Get-LogFile($InitialDirectory)
    { 
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
        $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $OpenFileDialog.InitialDirectory = $InitialDirectory
        $OpenFileDialog.Filter = "Devices|*-Devices.csv|All Files (*.*)|*.*"
        $OpenFileDialog.ShowDialog()
        $OpenFileDialog.Filename
        $OpenFileDialog.ShowHelp = $true
        $OpenFileDialog.Multiselect = $false
    }

    $Result = Get-LogFile

    if($Result -eq "OK")
    {
        $script:LogFile = $Result[1]
    }
    else
    {
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }
}
else
{
    $script:LogFile = $Path
}

# Create a record of your PowerShell session to a text file
Start-Transcript -Path "$OUTPUT_FOLDER\Transcript.txt"

# Get Start Time
$startTime = (Get-Date)

# Logo
$Logo = @"
██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
"@

Write-Output ""
Write-Output "$Logo"
Write-Output ""

# Header
Write-Output "Devices-Analyzer - Automated Processing of Microsoft Entra ID Device Information for DFIR"
Write-Output "(c) 2026 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
Write-Output ""

# Analysis date (ISO 8601)
$AnalysisDateTime = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "Analysis date: $AnalysisDateTime UTC"
Write-Output ""

#endregion Header

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Analysis

# Device Information
# https://learn.microsoft.com/en-us/graph/api/resources/device?view=graph-rest-1.0

# Input-Check
if (!(Test-Path "$LogFile"))
{
    Write-Host "[Error] $LogFile does not exist." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Check File Extension
$Extension = [IO.Path]::GetExtension($LogFile)
if (!($Extension -eq ".csv" ))
{
    Write-Host "[Error] No CSV File provided." -ForegroundColor Red
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Input Size
$InputSize = Get-FileSize((Get-Item "$LogFile").Length)
Write-Output "[Info]  Total Input Size: $InputSize"

# Count rows of CSV (w/ thousands separators)
$Count = 0
switch -File "$LogFile" { default { ++$Count } }
$Rows = '{0:N0}' -f $Count
Write-Output "[Info]  Total Lines: $Rows"

# Processing Device Information
Write-Output "[Info]  Processing Device Information ..."

# XLSX
$Devices = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Sort-Object { $_.CreatedDateTime -as [datetime] } -Descending
[datetime]$LastSignInDateTime = ($Devices | Select-Object LastSignInDateTime | Sort-Object { $_.LastSignInDateTime -as [datetime] } -Descending | Select-Object -First 1).LastSignInDateTime
$LastDay = ($LastSignInDateTime).AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ssZ")
$Devices | Export-Excel -Path "$OUTPUT_FOLDER\Devices.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Devices" -CellStyleSB {
param($WorkSheet)
# BackgroundColor and FontColor for specific cells of TopRow
Set-Format -Address $WorkSheet.Cells["A1:X1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
# HorizontalAlignment "Center" of columns A-X
$WorkSheet.Cells["A:X"].Style.HorizontalAlignment="Center"
# ConditionalFormatting - CreatedDateTime
$LastRow = $WorkSheet.Dimension.End.Row
Add-ConditionalFormatting -Address $WorkSheet.Cells["A2:A$LastRow"] -WorkSheet $WorkSheet -RuleType GreaterThanOrEqual -ConditionValue "$LastDay" -BackgroundColor Yellow # New Registered Devices (Last 7 days)
}

# File Size (XLSX)
if (Test-Path "$OUTPUT_FOLDER\Devices.xlsx")
{
    $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\Devices.xlsx").Length)
    Write-Output "[Info]  File Size (XLSX): $Size"
}

# Total Number of Devices
$Total = ($Devices | Measure-Object).Count
Write-Output "[Info]  Total Number of Devices: $Total"

# LastWriteTime
$LastWriteTime = (Get-Item -Path "$LogFile" | Select-Object -ExpandProperty LastWriteTimeUtc).ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "[Info]  LastWriteTime: $LastWriteTime UTC"

# LastSignInDateTime
# Note: Device Information may be processed days after acquisition date. LastSignInDateTime seems to be the most accurate datetime.
[datetime]$LastSignInDateTime = ($Devices | Select-Object LastSignInDateTime | Sort-Object { $_.LastSignInDateTime -as [datetime] } -Descending | Select-Object -First 1).LastSignInDateTime
$DateTime = $LastSignInDateTime.ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "[Info]  LastSignInDateTime: $DateTime UTC"

# TimeSpan
$TimeSpan = New-TimeSpan -Start $LastSignInDateTime -End $AnalysisDateTime
$Days = $TimeSpan.Days

# Active Devices (Last 30 days)
if ($Days -ge "2")
{
    $LastDay = ($LastSignInDateTime).AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $ActiveDevices = ($Devices | Where-Object { $_.LastSignInDateTime -ge $LastDay } | Measure-Object).Count
    Write-Output "[Info]  Active Devices (Last 30 Days): $ActiveDevices"
}
else
{
    $LastDay = (Get-Date).ToUniversalTime().AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $ActiveDevices = ($Devices | Where-Object { $_.LastSignInDateTime -ge $LastDay } | Measure-Object).Count
    Write-Output "[Info]  Active Devices (Last 30 Days): $ActiveDevices"
}

# Inactive Devices (Last 90 days)
if ($Days -ge "2")
{
    $LastDay = ($LastSignInDateTime).AddDays(-90).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $InactiveDevices = ($Devices | Where-Object { $_.LastSignInDateTime -lt $LastDay } | Measure-Object).Count
    Write-Output "[Info]  Inactive Devices (Last 90 Days): $InactiveDevices"
}
else
{
    $LastDay = (Get-Date).ToUniversalTime().AddDays(-90).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $InactiveDevices = ($Devices | Where-Object { $_.LastSignInDateTime -lt $LastDay } | Measure-Object).Count
    Write-Output "[Info]  Inactive Devices (Last 90 Days): $InactiveDevices"
}

# New Registered Devices (Last 7 days)
if ($Days -ge "2")
{
    $LastDay = ($LastSignInDateTime).AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $NewDevices = $Devices | Where-Object { $_.CreatedDateTime -ge $LastDay } 
    $Count = ($NewDevices| Measure-Object).Count
    if ($Count -ge "1")
    {
        Write-Host "[Info]  New Registered Devices (Last 7 Days): $Count" -ForegroundColor Yellow
    }
    else
    {
        Write-Host "[Info]  New Registered Devices (Last 7 Days): 0"
    }
}
else
{
    $LastDay = ($LastSignInDateTime).AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $NewDevices = $Devices | Where-Object { $_.CreatedDateTime -ge $LastDay } 
    $Count = ($NewDevices| Measure-Object).Count
    if ($Count -ge "1")
    {
        Write-Host "[Info]  New Registered Devices (Last 7 Days): $Count" -ForegroundColor Yellow
    }
    else
    {
        Write-Host "[Info]  New Registered Devices (Last 7 Days): 0"
    }
}

#############################################################################################################################################################################################

# Stats
New-Item "$OUTPUT_FOLDER\Stats" -ItemType Directory -Force | Out-Null

# DeviceOwnership (Stats)
$Import = $Devices | Select-Object DeviceOwnership
$Total = ($Import | Measure-Object).Count

if ($Total -ge "1")
{
    $Stats = $Import | Group-Object DeviceOwnership | Select-Object @{Name='DeviceOwnership'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending

    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\DeviceOwnership.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DeviceOwnership" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of column B-C
        $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
        }
    }
}

# EnrollmentType (Stats)
$Import = $Devices | Select-Object EnrollmentType
$Total = ($Import | Measure-Object).Count

if ($Total -ge "1")
{
    $Stats = $Import | Group-Object EnrollmentType | Select-Object @{Name='EnrollmentType'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending

    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\EnrollmentType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "EnrollmentType" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of column B-C
        $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
        }
    }
}

# OperatingSystem (Stats)
$Import = $Devices | Select-Object OperatingSystem
$Total = ($Import | Measure-Object).Count

if ($Total -ge "1")
{
    $Stats = $Import | Group-Object OperatingSystem | Select-Object @{Name='OperatingSystem'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending

    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\OperatingSystem.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "OperatingSystem" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of column B-C
        $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
        }
    }
}

# OperatingSystem / Version (Stats)
$Import = $Devices | Select-Object OperatingSystem,OperatingSystemVersion
$Total = ($Import | Measure-Object).Count

if ($Total -ge "1")
{
    $Stats = $Import | Group-Object OperatingSystem,OperatingSystemVersion | Select-Object @{Name='OperatingSystem'; Expression={ $_.Values[0] }},@{Name='Version'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending

    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\OperatingSystem-Version.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "OperatingSystem" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of column A-D
        $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
        }
    }
}

# Model (Stats)
$Import = $Devices | Select-Object Model
$Total = ($Import | Measure-Object).Count

if ($Total -ge "1")
{
    $Stats = $Import | Group-Object Model | Select-Object @{Name='Model'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending

    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\Model.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Model" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of column B-C
        $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
        }
    }
}

# ProfileType (Stats)
$Import = $Devices | Select-Object ProfileType
$Total = ($Import | Measure-Object).Count

if ($Total -ge "1")
{
    $Stats = $Import | Group-Object ProfileType | Select-Object @{Name='ProfileType'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending

    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\ProfileType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ProfileType" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of column B-C
        $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
        }
    }
}

# TrustType (Stats)
$Import = $Devices | Select-Object TrustType
$Total = ($Import | Measure-Object).Count

if ($Total -ge "1")
{
    $Stats = $Import | Group-Object TrustType | Select-Object @{Name='TrustType'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending

    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\TrustType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "TrustType" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of column B-C
        $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
        }
    }
}

#endregion Analysis

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Footer

# Get End Time
$endTime = (Get-Date)

# Echo Time elapsed
Write-Output ""
Write-Output "FINISHED!"

$Time = ($endTime-$startTime)
$ElapsedTime = ('Overall analysis duration: {0} h {1} min {2} sec' -f $Time.Hours, $Time.Minutes, $Time.Seconds)
Write-Output "$ElapsedTime"

# Stop logging
Write-Host ""
Stop-Transcript
Start-Sleep 0.5

# Reset Windows Title
$Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"

#endregion Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# SIG # Begin signature block
# MIIs3gYJKoZIhvcNAQcCoIIszzCCLMsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUZpyxfivUy1wc8M6Xr4RXUS5w
# fDKggiYXMIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
# AQwFADB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVy
# MRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEh
# MB8GA1UEAwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTIxMDUyNTAwMDAw
# MFoXDTI4MTIzMTIzNTk1OVowVjELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3Rp
# Z28gTGltaXRlZDEtMCsGA1UEAxMkU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5n
# IFJvb3QgUjQ2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjeeUEiIE
# JHQu/xYjApKKtq42haxH1CORKz7cfeIxoFFvrISR41KKteKW3tCHYySJiv/vEpM7
# fbu2ir29BX8nm2tl06UMabG8STma8W1uquSggyfamg0rUOlLW7O4ZDakfko9qXGr
# YbNzszwLDO/bM1flvjQ345cbXf0fEj2CA3bm+z9m0pQxafptszSswXp43JJQ8mTH
# qi0Eq8Nq6uAvp6fcbtfo/9ohq0C/ue4NnsbZnpnvxt4fqQx2sycgoda6/YDnAdLv
# 64IplXCN/7sVz/7RDzaiLk8ykHRGa0c1E3cFM09jLrgt4b9lpwRrGNhx+swI8m2J
# mRCxrds+LOSqGLDGBwF1Z95t6WNjHjZ/aYm+qkU+blpfj6Fby50whjDoA7NAxg0P
# OM1nqFOI+rgwZfpvx+cdsYN0aT6sxGg7seZnM5q2COCABUhA7vaCZEao9XOwBpXy
# bGWfv1VbHJxXGsd4RnxwqpQbghesh+m2yQ6BHEDWFhcp/FycGCvqRfXvvdVnTyhe
# Be6QTHrnxvTQ/PrNPjJGEyA2igTqt6oHRpwNkzoJZplYXCmjuQymMDg80EY2NXyc
# uu7D1fkKdvp+BRtAypI16dV60bV/AK6pkKrFfwGcELEW/MxuGNxvYv6mUKe4e7id
# FT/+IAx1yCJaE5UZkADpGtXChvHjjuxf9OUCAwEAAaOCARIwggEOMB8GA1UdIwQY
# MBaAFKARCiM+lvEH7OKvKe+CpX/QMKS0MB0GA1UdDgQWBBQy65Ka/zWWSC8oQEJw
# IDaRXBeF5jAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUE
# DDAKBggrBgEFBQcDAzAbBgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEMGA1Ud
# HwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FBQUNlcnRpZmlj
# YXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBDAUAA4IBAQASv6Hvi3Sa
# mES4aUa1qyQKDKSKZ7g6gb9Fin1SB6iNH04hhTmja14tIIa/ELiueTtTzbT72ES+
# BtlcY2fUQBaHRIZyKtYyFfUSg8L54V0RQGf2QidyxSPiAjgaTCDi2wH3zUZPJqJ8
# ZsBRNraJAlTH/Fj7bADu/pimLpWhDFMpH2/YGaZPnvesCepdgsaLr4CnvYFIUoQx
# 2jLsFeSmTD1sOXPUC4U5IOCFGmjhp0g4qdE2JXfBjRkWxYhMZn0vY86Y6GnfrDyo
# XZ3JHFuu2PMvdM+4fvbXg50RlmKarkUT2n/cR/vfw1Kf5gZV6Z2M8jpiUbzsJA8p
# 1FiAhORFe1rYMIIGGjCCBAKgAwIBAgIQYh1tDFIBnjuQeRUgiSEcCjANBgkqhkiG
# 9w0BAQwFADBWMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MS0wKwYDVQQDEyRTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYw
# HhcNMjEwMzIyMDAwMDAwWhcNMzYwMzIxMjM1OTU5WjBUMQswCQYDVQQGEwJHQjEY
# MBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSswKQYDVQQDEyJTZWN0aWdvIFB1Ymxp
# YyBDb2RlIFNpZ25pbmcgQ0EgUjM2MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIB
# igKCAYEAmyudU/o1P45gBkNqwM/1f/bIU1MYyM7TbH78WAeVF3llMwsRHgBGRmxD
# eEDIArCS2VCoVk4Y/8j6stIkmYV5Gej4NgNjVQ4BYoDjGMwdjioXan1hlaGFt4Wk
# 9vT0k2oWJMJjL9G//N523hAm4jF4UjrW2pvv9+hdPX8tbbAfI3v0VdJiJPFy/7Xw
# iunD7mBxNtecM6ytIdUlh08T2z7mJEXZD9OWcJkZk5wDuf2q52PN43jc4T9OkoXZ
# 0arWZVeffvMr/iiIROSCzKoDmWABDRzV/UiQ5vqsaeFaqQdzFf4ed8peNWh1OaZX
# nYvZQgWx/SXiJDRSAolRzZEZquE6cbcH747FHncs/Kzcn0Ccv2jrOW+LPmnOyB+t
# AfiWu01TPhCr9VrkxsHC5qFNxaThTG5j4/Kc+ODD2dX/fmBECELcvzUHf9shoFvr
# n35XGf2RPaNTO2uSZ6n9otv7jElspkfK9qEATHZcodp+R4q2OIypxR//YEb3fkDn
# 3UayWW9bAgMBAAGjggFkMIIBYDAfBgNVHSMEGDAWgBQy65Ka/zWWSC8oQEJwIDaR
# XBeF5jAdBgNVHQ4EFgQUDyrLIIcouOxvSK4rVKYpqhekzQwwDgYDVR0PAQH/BAQD
# AgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwGwYD
# VR0gBBQwEjAGBgRVHSAAMAgGBmeBDAEEATBLBgNVHR8ERDBCMECgPqA8hjpodHRw
# Oi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmluZ1Jvb3RS
# NDYuY3JsMHsGCCsGAQUFBwEBBG8wbTBGBggrBgEFBQcwAoY6aHR0cDovL2NydC5z
# ZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljQ29kZVNpZ25pbmdSb290UjQ2LnA3YzAj
# BggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJKoZIhvcNAQEM
# BQADggIBAAb/guF3YzZue6EVIJsT/wT+mHVEYcNWlXHRkT+FoetAQLHI1uBy/YXK
# ZDk8+Y1LoNqHrp22AKMGxQtgCivnDHFyAQ9GXTmlk7MjcgQbDCx6mn7yIawsppWk
# vfPkKaAQsiqaT9DnMWBHVNIabGqgQSGTrQWo43MOfsPynhbz2Hyxf5XWKZpRvr3d
# MapandPfYgoZ8iDL2OR3sYztgJrbG6VZ9DoTXFm1g0Rf97Aaen1l4c+w3DC+IkwF
# kvjFV3jS49ZSc4lShKK6BrPTJYs4NG1DGzmpToTnwoqZ8fAmi2XlZnuchC4NPSZa
# PATHvNIzt+z1PHo35D/f7j2pO1S8BCysQDHCbM5Mnomnq5aYcKCsdbh0czchOm8b
# kinLrYrKpii+Tk7pwL7TjRKLXkomm5D1Umds++pip8wH2cQpf93at3VDcOK4N7Ew
# oIJB0kak6pSzEu4I64U6gZs7tS/dGNSljf2OSSnRr7KWzq03zl8l75jy+hOds9TW
# SenLbjBQUGR96cFr6lEUfAIEHVC1L68Y1GGxx4/eRI82ut83axHMViw1+sVpbPxg
# 51Tbnio1lB93079WPFnYaOvfGAA0e0zcfF/M9gXr+korwQTh2Prqooq2bYNMvUoU
# KD85gnJ+t0smrWrb8dee2CvYZXD5laGtaAxOfy/VKNmwuWuAh9kcMIIGazCCBNOg
# AwIBAgIRAIxBnpO/K86siAYoO3YZvTwwDQYJKoZIhvcNAQEMBQAwVDELMAkGA1UE
# BhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDErMCkGA1UEAxMiU2VjdGln
# byBQdWJsaWMgQ29kZSBTaWduaW5nIENBIFIzNjAeFw0yNDExMTQwMDAwMDBaFw0y
# NzExMTQyMzU5NTlaMFcxCzAJBgNVBAYTAkRFMRYwFAYDVQQIDA1OaWVkZXJzYWNo
# c2VuMRcwFQYDVQQKDA5NYXJ0aW4gV2lsbGluZzEXMBUGA1UEAwwOTWFydGluIFdp
# bGxpbmcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDRn27mnIzB6dsJ
# FLMexQQNRd8aMv73DTla68G6Q8u+V2TY1JQ/Z4j2oCI9ATW3K3P7NAPdlE0Qmtdj
# C0F/74jsfil/i8LwxuyT034wabViZKUcodmKsEFhM9am8W5kUgLuC5FIK4wNOq5T
# fzYdHTyJu1eR2XuSDoMp0wg45mOuFNBbYB8DVBtHxobvWq4eCs3lUxX07wR3Qr2U
# tb92w8eU2vKr2Ss9xIh/YvM4UxgBpO1I6O+W2tAB5mmynIgoCfX7mu6iD3A+AhpQ
# 9Gv209G83y8FPrFJIWU77TTehErbPjZ074xXwrlEkhnGUCk1w+KiNtZHaSn0X+vn
# hqJ7otBxQZQAESlhWXpDKCunnnVnVgwvVWtccAhxZO95eif6Vss/UhCaBZ26szln
# eGtFeTClI4+k3mqfWuodtXjHc8ohAclWp7XVywliwhCFEsAcFkpkCyivey0sqEfr
# wiMnRy1elH1S37XcQaav5+bt4KxtIXuOVEx3vM9MHdlraW0y1on5E8i4tagdI45T
# H0LU080ubc2MKqq6ZXtplTu1wdF2Cgy3hfSSLkJscRWApvpvOO6Vtc4jTG/AO6iq
# N5M6Swd+g40XtsxBD/gSk9kMqkgJ1pD1Gp5gkHnP1veut+YgJ9xWcRDJI7vcis9q
# sXwtVybeOCh56rTQvC/Tf6BJtiieEQIDAQABo4IBszCCAa8wHwYDVR0jBBgwFoAU
# DyrLIIcouOxvSK4rVKYpqhekzQwwHQYDVR0OBBYEFIxyZAmEHl7uAfEwbB4nzI8M
# CCLbMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsG
# AQUFBwMDMEoGA1UdIARDMEEwNQYMKwYBBAGyMQECAQMCMCUwIwYIKwYBBQUHAgEW
# F2h0dHBzOi8vc2VjdGlnby5jb20vQ1BTMAgGBmeBDAEEATBJBgNVHR8EQjBAMD6g
# PKA6hjhodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2ln
# bmluZ0NBUjM2LmNybDB5BggrBgEFBQcBAQRtMGswRAYIKwYBBQUHMAKGOGh0dHA6
# Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY0NvZGVTaWduaW5nQ0FSMzYu
# Y3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTAoBgNVHREE
# ITAfgR1td2lsbGluZ0BsZXRoYWwtZm9yZW5zaWNzLmNvbTANBgkqhkiG9w0BAQwF
# AAOCAYEAZ0dBMMwluWGb+MD1rGWaPtaXrNZnlZqOZxgbdrMLBKAQr0QGcILCVIZ4
# SZYaevT5yMR6jFGSAjgaFtnk8ZpbtGwig/ed/C/D1Ne8SZyffdtALns/5CHxMnU8
# ks7ut7dsR6zFD4/bmljuoUoi55W6/XU/1pr+tqRaZGJvjSKJQCN9MhFAvXSpPPqR
# sj27ze1+KYIBF1/L0BW0HS0d9ZhGSUoEwqMDLpQf2eqJFyyyzWt21VVhLF6mgZ1d
# E5tCLZY7ERzx6/h5N7F0w361oigizMbCMdST29XOc5mB8q6Cye7OmEfM2jByRWa+
# cd4RycsN2p2wHRukpq48iX+tPVKmHwNKf+upuKPDQAeV4J7gUCtevIsOtoyiC2+a
# mimu81o424Dl+NsAyCLz0SXvNAhVvtU73H61gtoPa/SWouem2S+bzp7oGvGPop/9
# mh4CXki6LVeDH3hDM8hZsJg/EToIWiDozTc2yWqwV4Ozyd4x5Ix8lckXMgWuyWcx
# mLK1RmKpMIIGgjCCBGqgAwIBAgIQNsKwvXwbOuejs902y8l1aDANBgkqhkiG9w0B
# AQwFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNV
# BAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsx
# LjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkw
# HhcNMjEwMzIyMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjBXMQswCQYDVQQGEwJHQjEY
# MBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYDVQQDEyVTZWN0aWdvIFB1Ymxp
# YyBUaW1lIFN0YW1waW5nIFJvb3QgUjQ2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAiJ3YuUVnnR3d6LkmgZpUVMB8SQWbzFoVD9mUEES0QUCBdxSZqdTk
# dizICFNeINCSJS+lV1ipnW5ihkQyC0cRLWXUJzodqpnMRs46npiJPHrfLBOifjfh
# pdXJ2aHHsPHggGsCi7uE0awqKggE/LkYw3sqaBia67h/3awoqNvGqiFRJ+OTWYmU
# CO2GAXsePHi+/JUNAax3kpqstbl3vcTdOGhtKShvZIvjwulRH87rbukNyHGWX5tN
# K/WABKf+Gnoi4cmisS7oSimgHUI0Wn/4elNd40BFdSZ1EwpuddZ+Wr7+Dfo0lcHf
# lm/FDDrOJ3rWqauUP8hsokDoI7D/yUVI9DAE/WK3Jl3C4LKwIpn1mNzMyptRwsXK
# rop06m7NUNHdlTDEMovXAIDGAvYynPt5lutv8lZeI5w3MOlCybAZDpK3Dy1MKo+6
# aEtE9vtiTMzz/o2dYfdP0KWZwZIXbYsTIlg1YIetCpi5s14qiXOpRsKqFKqav9R1
# R5vj3NgevsAsvxsAnI8Oa5s2oy25qhsoBIGo/zi6GpxFj+mOdh35Xn91y72J4RGO
# JEoqzEIbW3q0b2iPuWLA911cRxgY5SJYubvjay3nSMbBPPFsyl6mY4/WYucmyS9l
# o3l7jk27MAe145GWxK4O3m3gEFEIkv7kRmefDR7Oe2T1HxAnICQvr9sCAwEAAaOC
# ARYwggESMB8GA1UdIwQYMBaAFFN5v1qqK0rPVIDh2JvAnfKyA2bLMB0GA1UdDgQW
# BBT2d2rdP/0BE/8WoWyCAi/QCj0UJTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/
# BAUwAwEB/zATBgNVHSUEDDAKBggrBgEFBQcDCDARBgNVHSAECjAIMAYGBFUdIAAw
# UAYDVR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC51c2VydHJ1c3QuY29tL1VTRVJU
# cnVzdFJTQUNlcnRpZmljYXRpb25BdXRob3JpdHkuY3JsMDUGCCsGAQUFBwEBBCkw
# JzAlBggrBgEFBQcwAYYZaHR0cDovL29jc3AudXNlcnRydXN0LmNvbTANBgkqhkiG
# 9w0BAQwFAAOCAgEADr5lQe1oRLjlocXUEYfktzsljOt+2sgXke3Y8UPEooU5y39r
# AARaAdAxUeiX1ktLJ3+lgxtoLQhn5cFb3GF2SSZRX8ptQ6IvuD3wz/LNHKpQ5nX8
# hjsDLRhsyeIiJsms9yAWnvdYOdEMq1W61KE9JlBkB20XBee6JaXx4UBErc+YuoSb
# 1SxVf7nkNtUjPfcxuFtrQdRMRi/fInV/AobE8Gw/8yBMQKKaHt5eia8ybT8Y/Ffa
# 6HAJyz9gvEOcF1VWXG8OMeM7Vy7Bs6mSIkYeYtddU1ux1dQLbEGur18ut97wgGwD
# iGinCwKPyFO7ApcmVJOtlw9FVJxw/mL1TbyBns4zOgkaXFnnfzg4qbSvnrwyj1Ni
# urMp4pmAWjR+Pb/SIduPnmFzbSN/G8reZCL4fvGlvPFk4Uab/JVCSmj59+/mB2Gn
# 6G/UYOy8k60mKcmaAZsEVkhOFuoj4we8CYyaR9vd9PGZKSinaZIkvVjbH/3nlLb0
# a7SBIkiRzfPfS9T+JesylbHa1LtRV9U/7m0q7Ma2CQ/t392ioOssXW7oKLdOmMBl
# 14suVFBmbzrt5V5cQPnwtd3UOTpS9oCG+ZZheiIvPgkDmA8FzPsnfXW5qHELB43E
# T7HHFHeRPRYrMBKjkb8/IN7Po0d0hQoF4TeMM+zYAJzoKQnVKOLg8pZVPT8wggan
# MIIEj6ADAgECAhEAkKwIciD9xafEa1zHDfc9BjANBgkqhkiG9w0BAQwFADBXMQsw
# CQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYDVQQDEyVT
# ZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFJvb3QgUjQ2MB4XDTI2MDMyNTAw
# MDAwMFoXDTQxMDMyNDIzNTk1OVowVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1Nl
# Y3RpZ28gTGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFt
# cGluZyBDQSBSNDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCu5Eqi
# Aa2CHGL5Zi1bmgPM8NUXwYZJ+BtQqHps43GLTC+sjVLypsBh+8uv+TLkgtVGD//v
# SmA0qrzELf9YRCh2MTAA/aGaQZKGg0BRCmziR3pbCnvgWjtGXBDUyn3j3K2lZAO8
# KxgFtlxwOYEAkL+CCqK4v9zzTl8ZwzDpPMiDIFa5THk8an1ieF5I09cXNrPQw+1E
# R1liThaG0z6FrOpqwxZWmPRZQBw2E32878UB1bL0Zp91vuWZgsMpNNiPCoBj0/1F
# +LE8+NRokfqacFI0F2tftrRB2W7HQClLR9zjxFbWb5be2rceIfNyHUUfKGIvMI2N
# zoxSlxXnFqUG887D8W1Cj8DFok688JKxWvHR/9aQykSbd+9Vutj36ij2sgq/125w
# TpUZ/AgC0ph50bRs7gFrUyaXE9wSsOqMvCCC+sEm7vd/BemSG0TSHNXSmyCba+FC
# zekeWX03TRIcF3Laqd0Rw24OH7jpei4zaGhcI7nfdhBA4c8RScxNY6jeHLHHmSMM
# Tk9Wqn7H4dLhUBP5YEwbgbN4uv1i9ltTnHli8t1xHV0StX9BFgrnmunTX19kUXY1
# H5ORJbRZyZDdvm1oZyteDj0SnMozr+YSmdIleDUTXdfoY7b2taz8s2+QbOxLxcah
# EIYGWzqu6h955tKwcANHcZ4gTmAhT3btuOiQsQIDAQABo4IBbjCCAWowHwYDVR0j
# BBgwFoAU9ndq3T/9ARP/FqFsggIv0Ao9FCUwHQYDVR0OBBYEFDp0pQxnxkJQwv21
# /Me7KTSC9Hq5MA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMBMG
# A1UdJQQMMAoGCCsGAQUFBwMIMCMGA1UdIAQcMBowCAYGZ4EMAQQCMA4GDCsGAQQB
# sjEBAgEDCDBMBgNVHR8ERTBDMEGgP6A9hjtodHRwOi8vY3JsLnNlY3RpZ28uY29t
# L1NlY3RpZ29QdWJsaWNUaW1lU3RhbXBpbmdSb290UjQ2LmNybDB8BggrBgEFBQcB
# AQRwMG4wRwYIKwYBBQUHMAKGO2h0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGln
# b1B1YmxpY1RpbWVTdGFtcGluZ1Jvb3RSNDYucDdjMCMGCCsGAQUFBzABhhdodHRw
# Oi8vb2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOCAgEAMt5SR2bxngNm
# +N8oc6Gq76Gx1c235fkX7jw8Ho9MAkJGADerHE7dhsBXttqmzgr/7ZZahZSykGRP
# hPY1crj028kB8KzO0dKC2qQBAwtfgqMLKkkX/6bYq2uT33eD6ByAp2/XKD0LcmZh
# 0kKecvSBr6ln9ajX6u1dnx2fA7xEKy1M3qBhfQSUWLtjs2nFt0ELVLptzTlX9ID0
# cL+iOPfdboZ3CelT+JXKVKR2Sge0d4YiFAtPZkfSo8z1Z1x7y/Z9mwMIlBAnyuWX
# s4YsNuxdrYIt/QxE31PDOJ9DesS4Bc7H9OTORlEV/AvfiF/VepKZpira1MzLYuCw
# +uoLZn/pkpvd+CvNTS+mEHjBJNa6WK1j8qXFu+jIq+sG9QILHiyB6p/xpHrkJu8z
# kw393+VqF9eKlTY2VjRxdycZLrVemZ4Yp3wi33b+W58CllH3HqjmowlZ7SOrgmx8
# YwYOkgrHsXOQHyBp6O4FRb8In0+FzjT7ElGie9V7CfhL3IlVFZ4zjuKsZtH1iU3f
# Gu4z/JnOGT6sCb0BbTqe/uhvpFCQBdH5xPGIA/LrbQUXjU2tWJgHhTIqnN/HvHyO
# Hi5tM4zP3nhgh2rJ6Kqq2xsHBeNYs/R18xQ8DeIg+c90Eoaeh0YlN1KU8AyYol3K
# 9M+qY5ez8syd/7ZlrRnoVewgH3P1pcswggbiMIIEyqADAgECAhEA507yVbBQT/rb
# pt/3/IujFTANBgkqhkiG9w0BAQwFADBVMQswCQYDVQQGEwJHQjEYMBYGA1UEChMP
# U2VjdGlnbyBMaW1pdGVkMSwwKgYDVQQDEyNTZWN0aWdvIFB1YmxpYyBUaW1lIFN0
# YW1waW5nIENBIFI0MTAeFw0yNjAzMjUwMDAwMDBaFw0zNzA2MjQyMzU5NTlaMHIx
# CzAJBgNVBAYTAkdCMRcwFQYDVQQIEw5HcmVhdGVyIExvbmRvbjEYMBYGA1UEChMP
# U2VjdGlnbyBMaW1pdGVkMTAwLgYDVQQDEydTZWN0aWdvIFB1YmxpYyBUaW1lIFN0
# YW1waW5nIFNpZ25lciBSMzcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQCy/8NtS9xQ2UUtBRF32bj7VK3n4m50Uqjk/zTciSziYV40H1LKah0/oEklYG42
# E4VCP3DvsBUB6DmpCkDZ0jCnZBPIEevaH15ZJOQwFWP2ZXr5YjlJpb68Nlbs+ElN
# vKx32/1YHde3qqUSLybjulxPLz6T85+HOIqK7M1Bep8LspyhEP/q6nw5kGxTSrGv
# ufmeH+JF8CnVBcVMFA40FlIYh0cDJVFhhfTfdWgLy/vWuLMQoKkf3s/FvByf16r0
# rtbyHm/iemwxSioJL9zyZDDKUNAbHXl0dhXo2VxUV2NcPXWXuoKsjL+6cfk6Vm2D
# HnxAlFdFsaBDIF1JOkSnC6PeLlBznZn2buF3vIIYJcq6N/zeFRCk4/HXDz7zgRsR
# RMdUB+rhyk5FoZaBjw0nLq3GZ3fClLUx5es5pUAxzNODMBn7JkFYip2BAGBPER5e
# V0ROhk6tGTG+fUiMiV+vgjg1YnP5FvnYWyEtWeQD/B2hp3vz0RvtdkM0p3igyadz
# rfpOBq5ppVk/YsuhTQkP99ivneHAGfi5e7lmxJ+meoBPrRLuzMmb81rzzbESjJHM
# sn5RVtc6Ucs7rcMqQC13PUIO7BbGBETV2ufCmV6lPTp3P7XJOvmnUCRTPbVvMTpx
# P/z+SOHg4/OCBhiqs4FA9+4oQvlkk9w32NGASli9GWrm5wIDAQABo4IBjjCCAYow
# HwYDVR0jBBgwFoAUOnSlDGfGQlDC/bX8x7spNIL0erkwHQYDVR0OBBYEFGEQ6XoS
# r1HEhdTyz6R0D1DNIK/4MA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMBYG
# A1UdJQEB/wQMMAoGCCsGAQUFBwMIMEoGA1UdIARDMEEwCAYGZ4EMAQQCMDUGDCsG
# AQQBsjEBAgEDCDAlMCMGCCsGAQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQ
# UzBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3Rp
# Z29QdWJsaWNUaW1lU3RhbXBpbmdDQVI0MS5jcmwwegYIKwYBBQUHAQEEbjBsMEUG
# CCsGAQUFBzAChjlodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNU
# aW1lU3RhbXBpbmdDQVI0MS5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNl
# Y3RpZ28uY29tMA0GCSqGSIb3DQEBDAUAA4ICAQAD6j2N0azN+hl6k6bKB5/U6VuS
# Os93ZBb3Pczy9VtBIKu4947Z5GwL0aFngIxl+GSuLFrJgPruBCRvKJEJsm7kv+LQ
# 1COVCEG9tZ+IRtr4ocUoa53lgdFaENlS0N4wgkZkbQEPv+x+1lSjYh+T4JeL9mUz
# nT7Erc6Sp5dWLka5sMP/m3GZi6oJPdPcsCKWagH7m2H2xDGIyHJC5PdH9phvi/Km
# hkktiSVTNNqVeV5bWdX2zhRE6UTfz0IcMoCL996lFIydXxOCE4MNDHDM0as4lnTi
# T/KHMccO6l8c9TnUVgmpci9ar1IABZ2U1XUkYjGGSn9MC3EHDP9V39VuBVvZ33/B
# EV/EWSRrf07T7jFplKX+gQr/UOqPGMlE7ZJ72UaUkNJy7bVl3bcLKzdpjIHzLkf/
# 4MVa1V7w8wqCv5W4gOnRGTlud5UMARbRM8BPxR/CXYXoMmIOD8pmTk2axgRL4LG8
# XtuchISdCHRmtacAmLGq5XSYSVTHTXADlO48iDKh3HM2r98LSF6f0sG12d8V9Jn7
# C3wDUieOxuKj4MdWrW+hiJU2kF87v6eH00HgCFFc2V0+CvfOCMn7juzS41jLaINc
# BlKWQ/fKb/uDLfWOW73z1I2lFY7Xj8tQ1XYtK5eREjWItM8jpl1cbQOc88btR+0X
# S2TmboE/141+va2PWzGCBjEwggYtAgEBMGkwVDELMAkGA1UEBhMCR0IxGDAWBgNV
# BAoTD1NlY3RpZ28gTGltaXRlZDErMCkGA1UEAxMiU2VjdGlnbyBQdWJsaWMgQ29k
# ZSBTaWduaW5nIENBIFIzNgIRAIxBnpO/K86siAYoO3YZvTwwCQYFKw4DAhoFAKB4
# MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQB
# gjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkE
# MRYEFBdXKN1SE/zLL3ivY7lY7MX4BkaeMA0GCSqGSIb3DQEBAQUABIICAAZKRkiv
# eQYV+h/+nIZ3HGKxnutBa0Pg3d5wJrCbZb0O1yLfZ6ii7tZvyPyeHyVNKf68aIEO
# t7TXAWbzpMqVFn9xF8nL6A/pHalcNQs7d0kl5NGG3NGtwuw7IGhHuyXM72IDC1e7
# yxTzMt5u7yKgNVEweGKWGlvyy8AbEjUjGI0910S8Mb6WODLi/Ci4hM0w9z4rwIpM
# egH8lazyv0bhMlxSe7GLLeiAQIs47kLgF0o9MpOhxJj9nL8seailiO+HN8/bvv+t
# xCPoGet3Tfn3vykmYTlY0KQo0t3Gxc/SvVcEPXC34AvbD3qoWFSPOqZAncm7f1Po
# tCFDzB5dKZTuUQc5Xev4VVT6FPRN7UJt8y3Juj3I1TujWdjJfd4qSYXTtwbeGLpi
# PeTEja+m8aVbzC2eew7jdr3Gt5PPGQzZOc3OBA6Wr+FfECr88V6X/6txClCCEHp8
# jWPG+k/qfMGm5bsVe7qqvEFPhirdfd/A3zLLhq1OQPMqpDOEsnp/5u41Nirud3OG
# gWekdGzZxnRgyKKMrDNozV+v3YEKZUrCQOmAg4c6H6VPllAWmxbUTrlJArGUikBQ
# O70xMqvWSrYfUyTf8aAThWRlPpL7KNHltFnhrjnM/FOmHHfEva80eqn0zvgRlYC+
# W0UiRr8SEh1MUmKdHZjbTqJN1EovWsubhNohoYIDIzCCAx8GCSqGSIb3DQEJBjGC
# AxAwggMMAgEBMGowVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGlt
# aXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBDQSBS
# NDECEQDnTvJVsFBP+tum3/f8i6MVMA0GCWCGSAFlAwQCAgUAoHkwGAYJKoZIhvcN
# AQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYwNzA2MTEzMDQ1WjA/
# BgkqhkiG9w0BCQQxMgQwpqwa/wZg0rY1XhTncPYEpYlK3K2jICv7FDya170wRVkI
# akgpBK1C2kFRBiAKK4a+MA0GCSqGSIb3DQEBAQUABIICAIJF0WHZRa7khl6wbipH
# C0b7oGbSqSKl7u69cJnrz9UZ0xWBq4jy0mvb6c3w/woWMnSEdLj5+20TMbGmRj2J
# gxqVfbiJty6am2YqdUn3aaDclTFt0OdnM8DaqRXija1arTPD8rxdUR0aZgQPeZSX
# aEKHserPzC95O/C+WI50EgPVx/IbTmPEENRmSY0bKBDQsqWEdKGQcZVTBkCNGHWW
# LtcrMx6xFD7ZN+dXjgj9WOo9esfeQPCTEeohCgudG4p+hMLtuW/ZTjwf8G79S7rB
# RN0XdM8vZ7KqW/bM9nOFdOlmg6ZDIASg3kToiuu9Y+Inj0ku5MRlI1gR9b1T75mT
# Nru/U9874S1ZwzW+EOR7ebbRCDnEG52tWjucmYT3P/119XRT9Rcsoj/WTLXfqRiH
# mRYTI2HyTLIVlIOxzrundwz8Hh8+KCT69LBQN1hrwOIpOoepiKqP387Y59V1fXGr
# K1zz9dM7UZPbVK2grD7MHzWO5KZsyusdGwig1lg5PRrI15AcBhS0VkWEnfz1nijN
# sk0ShASEVKTxpyIEvK5szDEevtYfMi87hmia6Lq2wOAZ9mVqlYc71mY0+XVHYJrH
# ZkXNlswmkYFKr1YELy4mVD5x/N4GbNpMhNpxA1oveqNE2a4XhqmcP9RIPOO8Vi6s
# KjWun72s9p7C44QITjKK+IqL
# SIG # End signature block
