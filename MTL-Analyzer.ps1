# MTL-Analyzer
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
# IPinfo CLI 3.3.2 (2026-04-28)
# https://ipinfo.io/signup?ref=cli --> Sign up for free
# https://github.com/ipinfo/cli
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
  MTL-Analyzer - Automated Processing of M365 Message Trace Logs for DFIR

.DESCRIPTION
  MTL-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of M365 Message Trace Logs extracted via "Microsoft Extractor Suite" by Invictus Incident Response.

  https://github.com/invictus-ir/Microsoft-Extractor-Suite (Microsoft-Extractor-Suite v4.1.0)

  https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/M365/MessageTraceLog.html

  Single User Audit

.PARAMETER OutputDir
  Specifies the output directory. Default is "$env:USERPROFILE\Desktop\MTL-Analyzer".

  Note: The subdirectory 'MTL-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the CSV-based input file (<UPN>-MTL.csv).

.EXAMPLE
  PS> .\MTL-Analyzer.ps1

.EXAMPLE
  PS> .\MTL-Analyzer.ps1 -Path "$env:USERPROFILE\Desktop\<UPN>-MTL.csv"

.EXAMPLE
  PS> .\MTL-Analyzer.ps1 -Path "H:\Microsoft-Extractor-Suite\<UPN>-MTL.csv" -OutputDir "H:\Microsoft-Analyzer-Suite"

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

#region Initialisations

# Set Progress Preference to Silently Continue
$OriginalProgressPreference = $Global:ProgressPreference
$Global:ProgressPreference = 'SilentlyContinue'

#endregion Initialisations

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

# Colors
Add-Type -AssemblyName System.Drawing
$script:Green  = [System.Drawing.Color]::FromArgb(0,176,80) # Green
$script:Orange = [System.Drawing.Color]::FromArgb(255,192,0) # Orange

# Output Directory
if (!($OutputDir))
{
    $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\MTL-Analyzer" # Default
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
        $script:OUTPUT_FOLDER = "$OutputDir\MTL-Analyzer" # Custom
    }
}

# Tools

# IPinfo CLI
$script:IPinfo = "$SCRIPT_DIR\Tools\IPinfo\ipinfo.exe"

# Import Functions
$FilePath = "$SCRIPT_DIR\Functions"
if (Test-Path "$FilePath")
{
    if (Test-Path "$FilePath\*.ps1") 
    {
        Get-ChildItem -Path "$FilePath" -Filter *.ps1 | ForEach-Object { . $_.FullName }
    }
}

# Configuration File (JSON)
if(!(Test-Path "$PSScriptRoot\Config.json"))
{
    Write-Host "[Error] Config.json NOT found." -ForegroundColor Red
    Exit
}
else
{
    $Config = Get-Content "$PSScriptRoot\Config.json" | ConvertFrom-Json

    # IPinfo CLI - Access Token
    $script:Token = $Config.IPinfo.AccessToken

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
    Write-Host "[Info]  Check out: https://github.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/wiki#setup"
    Exit
}

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "MTL-Analyzer - Automated Processing of M365 Message Trace Logs for DFIR"

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

# Add the required MessageBox class (Windows PowerShell)
Add-Type -AssemblyName System.Windows.Forms

# Select Log File
if(!($Path))
{
    Function Get-LogFile($InitialDirectory)
    { 
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
        $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $OpenFileDialog.InitialDirectory = $InitialDirectory
        $OpenFileDialog.Filter = "Message Trace Log Files (*-MTL.csv)|*-MTL.csv|All Files (*.*)|*.*"
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
Write-Output "MTL-Analyzer - Automated Processing of M365 Message Trace Logs for DFIR"
Write-Output "(c) 2026 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
Write-Output ""

# Analysis date (ISO 8601)
$script:AnalysisDate = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "Analysis date: $AnalysisDate UTC"
Write-Output ""

# Create HashTable and import 'ASN-Whitelist.csv'
$script:AsnWhitelist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Whitelists\ASN-Whitelist.csv")
{
    if(Test-Csv -Path "$SCRIPT_DIR\Whitelists\ASN-Whitelist.csv" -MaxLines 2)
    {
        Import-Csv "$SCRIPT_DIR\Whitelists\ASN-Whitelist.csv" -Delimiter "," | ForEach-Object { $AsnWhitelist_HashTable[$_.ASN] = $_.OrgName,$_.Info }
    }
}

# Create HashTable and import 'ASN-Blacklist.csv'
$script:AsnBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\ASN-Blacklist.csv")
{
    if(Test-Csv -Path "$SCRIPT_DIR\Blacklists\ASN-Blacklist.csv" -MaxLines 2)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\ASN-Blacklist.csv" -Delimiter "," | ForEach-Object { $AsnBlacklist_HashTable[$_.ASN] = $_.OrgName,$_.Info }
    }
}

# Create HashTable and import 'Country-Blacklist.csv'
$script:CountryBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\Country-Blacklist.csv")
{
    if(Test-Csv -Path "$SCRIPT_DIR\Blacklists\Country-Blacklist.csv" -MaxLines 2)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\Country-Blacklist.csv" -Delimiter "," | ForEach-Object { $CountryBlacklist_HashTable[$_."Country Name"] = $_.Country }
    }
}

#endregion Header

#############################################################################################################################################################################################

#region Analysis

# Message Trace Logs

Function Start-Processing {

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

# Check IPinfo CLI Access Token 
if ("$Token" -eq "access_token")
{
    Write-Host "[Error] No IPinfo CLI Access Token provided. Please add your personal access token to 'Config.json'" -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# UserId
$script:UserId = Import-Csv -Path "$LogFile" -Delimiter "," | Group-Object SenderAddress | Sort-Object Count -Descending | Select-Object Name,Count -First 1 | Select-Object -ExpandProperty Name

# Domain
$Domain = $UserId | ForEach-Object{($_ -split ".*@")[1]}

# Input Size
$InputSize = Get-FileSize((Get-Item "$LogFile").Length)
Write-Output "[Info]  Total Input Size: $InputSize"

# Count rows of CSV (w/ thousands separators)
[int]$TotalLines = 0
$Reader = New-Object IO.StreamReader "$LogFile"
while($Reader.ReadLine() -ne $null){ $TotalLines++ }
($Reader.Dispose())
$Rows = '{0:N0}' -f $TotalLines | ForEach-Object {$_ -replace ' ','.'} # Replace Space with a dot (e.g. de-AT)
Write-Output "[Info]  Total Lines: $Rows"

# Processing M365 Message Trace Logs
Write-Output "[Info]  Processing M365 Message Trace Logs ($UserId) ..."
New-Item "$OUTPUT_FOLDER\MessageTraceLogs\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\MessageTraceLogs\XLSX" -ItemType Directory -Force | Out-Null

# Import CSV
$Data = Import-Csv -Path "$LogFile" -Delimiter "," | Sort-Object { $_.Received -as [datetime] } -Descending

# Time Frame
$Last  = ($Data | Select-Object -Last 1).Received
$First = ($Data | Select-Object -First 1).Received
$StartDate = (Get-Date $Last).ToString("yyyy-MM-dd HH:mm:ss")
$EndDate = (Get-Date $First).ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "[Info]  Log data from $StartDate UTC until $EndDate UTC"

# XLSX

# Untouched
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$LogFile")
    {
        if(Test-Csv -Path "$LogFile" -MaxLines 2)
        {
            $IMPORT = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\XLSX\Untouched.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MTL-Untouched" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-G and I-J
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:G"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["I:J"].Style.HorizontalAlignment="Center"
            }
        }
    }
}

# File Size (XLSX)
if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\XLSX\Untouched.xlsx")
{
    $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\MessageTraceLogs\XLSX\Untouched.xlsx").Length)
    Write-Output "[Info]  File Size (XLSX) : $Size"
}

#############################################################################################################################################################################################

# Stats
New-Item "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Inbound" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Outbound" -ItemType Directory -Force | Out-Null

# Total Messages
[int]$TotalMessages = (Import-Csv -Path "$LogFile" -Delimiter "," | Measure-Object).Count
$TotalMessagesCount = '{0:N0}' -f $TotalMessages
Write-Output "[Info]  Total Messages: $TotalMessagesCount"

# Incoming Messages (RecipientAddress)
[int]$IncomingMessages = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.RecipientAddress -eq "$UserId" } | Measure-Object).Count
$IncomingMessagesCount = '{0:N0}' -f $IncomingMessages

# Incoming Messages (RecipientAddress) --> Internal
[int]$IncomingMessagesFromInternal = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.RecipientAddress -eq "$UserId"} | Where-Object {$_.SenderAddress -like "*$Domain"} | Measure-Object).Count
$IncomingMessagesFromInternalCount = '{0:N0}' -f $IncomingMessagesFromInternal

# Incoming Messages (RecipientAddress) --> External
[int]$IncomingMessagesFromExternal = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.RecipientAddress -eq "$UserId"} | Where-Object {$_.SenderAddress -notlike "*$Domain"} | Measure-Object).Count
$IncomingMessagesFromExternalCount = '{0:N0}' -f $IncomingMessagesFromExternal

Write-Output "[Info]  Incoming Messages: $IncomingMessagesCount (Internal: $IncomingMessagesFromInternalCount, External: $IncomingMessagesFromExternalCount)"

# Outgoing Messages (SenderAddress)
[int]$OutgoingMessages = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.SenderAddress -eq "$UserId" } | Measure-Object).Count
$OutgoingMessagesCount = '{0:N0}' -f $OutgoingMessages

# Outgoing Messages (SenderAddress) --> Internal
[int]$OutgoingMessagesToInternal = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.SenderAddress -eq "$UserId" } | Where-Object {$_.RecipientAddress -like "*$Domain" } | Measure-Object).Count
$OutgoingMessagesToInternalCount = '{0:N0}' -f $OutgoingMessagesToInternal

# Outgoing Messages (SenderAddress) --> External
[int]$OutgoingMessagesToExternal = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.SenderAddress -eq "$UserId" } | Where-Object {$_.RecipientAddress -notlike "*$Domain" } | Measure-Object).Count
$OutgoingMessagesToExternalCount = '{0:N0}' -f $OutgoingMessagesToExternal

Write-Output "[Info]  Outgoing Messages: $OutgoingMessagesCount (Internal: $OutgoingMessagesToInternalCount, External: $OutgoingMessagesToExternalCount)"

# Subject (Inbound)

# CSV (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.RecipientAddress -eq "$UserId" } | Select-Object Subject | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" } | Group-Object Subject | Sort-Object Count -Descending | Select-Object @{Name='Subject'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\Subject.csv" -NoTypeInformation -Encoding UTF8
[int]$Count = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" } | Select-Object Subject | Sort-Object Subject -Unique | Measure-Object).Count
$SubjectCount = '{0:N0}' -f $Count
Write-Output "[Info]  Subjects (Inbound): $SubjectCount"

# XLSX (Stats)
if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\Subject.csv")
{
    if(Test-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\Subject.csv" -MaxLines 2)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\Subject.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Inbound\Subject.xlsx" -NoHyperLinkConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Subject (Inbound)" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns B-C
        $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
        }
    }
}

# Subject / Status (Inbound)

# CSV (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.RecipientAddress -eq "$UserId" } | Select-Object Subject | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" } | Group-Object Subject,Status | Select-Object @{Name='Subject'; Expression={ $_.Values[0] }},@{Name='Status'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\Subject-Status.csv" -NoTypeInformation -Encoding UTF8

# XLSX (Stats)
if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\Subject-Status.csv")
{
    if(Test-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\Subject-Status.csv" -MaxLines 2)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\Subject-Status.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Inbound\Subject-Status.xlsx" -NoHyperLinkConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Subject (Inbound)" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns B-D
        $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
        }
    }
}

# Subject (Outbound)

# CSV (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.SenderAddress -eq "$UserId" } | Select-Object Subject | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" } | Group-Object Subject | Sort-Object Count -Descending | Select-Object @{Name='Subject'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\Subject.csv" -NoTypeInformation -Encoding UTF8

$SubjectCount = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" } | Select-Object Subject | Sort-Object Subject -Unique | Measure-Object).Count
Write-Output "[Info]  Subjects (Outbound): $SubjectCount"

# XLSX (Stats)
if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\Subject.csv")
{
    if(Test-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\Subject.csv" -MaxLines 2)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\Subject.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Outbound\Subject.xlsx" -NoHyperLinkConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Subject (Outbound)" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns B-C
        $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
        # ConditionalFormatting - Count
        $LastRow = $WorkSheet.Dimension.End.Row
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A2:C$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$B2>=75' -BackgroundColor "Red" # 75x outgoing messages with the same 'Subject'
        }
    }
}

# Subject / Status (Outbound)

# CSV (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.SenderAddress -eq "$UserId" } | Select-Object Subject | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" } | Group-Object Subject,Status | Select-Object @{Name='Subject'; Expression={ $_.Values[0] }},@{Name='Status'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\Subject-Status.csv" -NoTypeInformation -Encoding UTF8

# XLSX (Stats)
if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\Subject-Status.csv")
{
    if(Test-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\Subject-Status.csv" -MaxLines 2)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\Subject-Status.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Outbound\Subject-Status.xlsx" -NoHyperLinkConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Subject (Outbound)" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns B-D
        $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
        # ConditionalFormatting - Count
        $LastRow = $WorkSheet.Dimension.End.Row
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A2:D$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$C2>=75' -BackgroundColor "Red" # 75x outgoing messages with the same 'Subject'
        }
    }
}

# MessageId (Inbound)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.RecipientAddress -eq "$UserId" } | Select-Object MessageId | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" } | Group-Object MessageId | Sort-Object Count -Descending | Select-Object @{Name='MessageId'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\MessageIds.csv" -NoTypeInformation -Encoding UTF8

$MessageIdCount = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" } | Select-Object MessageId | Sort-Object MessageId -Unique | Measure-Object).Count
Write-Output "[Info]  MessageIds (Inbound): $MessageIdCount"

# XLSX (Stats)
if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\MessageIds.csv")
{
    if(Test-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\MessageIds.csv" -MaxLines 2)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\MessageIds.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Inbound\MessageIds.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MessageId (Outbound)" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        }
    }
}

# MessageId (Outbound)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.SenderAddress -eq "$UserId" } | Select-Object MessageId | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" } | Group-Object MessageId | Sort-Object Count -Descending | Select-Object @{Name='MessageId'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\MessageIds.csv" -NoTypeInformation -Encoding UTF8

$MessageIdCount = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" } | Select-Object MessageId | Sort-Object MessageId -Unique | Measure-Object).Count
Write-Output "[Info]  MessageIds (Outbound): $MessageIdCount"

# XLSX (Stats)
if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\MessageIds.csv")
{
    if(Test-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\MessageIds.csv" -MaxLines 2)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\MessageIds.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Outbound\MessageIds.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MessageId (Outbound)" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        }
    }
}

# MessageTraceId (Inbound)

# CSV (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.RecipientAddress -eq "$UserId" } | Select-Object MessageTraceId | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" } | Group-Object MessageTraceId | Sort-Object Count -Descending | Select-Object @{Name='MessageTraceId'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\MessageTraceIds.csv" -NoTypeInformation -Encoding UTF8

$MessageTraceIdCount = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" } | Select-Object MessageTraceId | Sort-Object MessageTraceId -Unique | Measure-Object).Count
Write-Output "[Info]  MessageTraceIds (Inbound): $MessageTraceIdCount"

# XLSX (Stats)
if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\MessageTraceIds.csv")
{
    if(Test-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\MessageTraceIds.csv" -MaxLines 2)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\MessageTraceIds.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Inbound\MessageTraceIds.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MessageTraceId (Inbound)" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        }
    }
}

# MessageTraceId (Outbound)

# CSV (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.SenderAddress -eq "$UserId" } | Select-Object MessageTraceId | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" } | Group-Object MessageTraceId | Sort-Object Count -Descending | Select-Object @{Name='MessageTraceId'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\MessageTraceIds.csv" -NoTypeInformation -Encoding UTF8

$MessageTraceIdCount = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" } | Select-Object MessageTraceId | Sort-Object MessageTraceId -Unique | Measure-Object).Count
Write-Output "[Info]  MessageTraceIds (Outbound): $MessageTraceIdCount"

# XLSX (Stats)
if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\MessageTraceIds.csv")
{
    if(Test-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\MessageTraceIds.csv" -MaxLines 2)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\MessageTraceIds.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Outbound\MessageTraceIds.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MessageTraceId (Outbound)" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        }
    }
}

# Status (Inbound)
Write-Output "[Info]  Tracking the Delivery Status of all Inbound Messages ..."

# CSV (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.RecipientAddress -eq "$UserId" } | Select-Object Status | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" } | Group-Object Status | Sort-Object Count -Descending | Select-Object @{Name='Status'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\Status.csv" -NoTypeInformation -Encoding UTF8
[int]$Failed = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" } | Where-Object {$_.Status -eq 'Failed' } | Measure-Object).Count
[int]$Delivered = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" } | Where-Object {$_.Status -eq 'Delivered' } | Measure-Object).Count
[int]$FilteredAsSpam = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" } | Where-Object {$_.Status -eq 'FilteredAsSpam' } | Measure-Object).Count
[int]$Quarantined = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" } | Where-Object {$_.Status -eq 'Quarantined' } | Measure-Object).Count
$FailedCount = '{0:N0}' -f $Failed
$DeliveredCount = '{0:N0}' -f $Delivered
$FilteredAsSpamCount = '{0:N0}' -f $FilteredAsSpam
$QuarantinedCount = '{0:N0}' -f $Quarantined
Write-Output "[Info]  Delivered (Inbound): $DeliveredCount"
Write-Output "[Info]  Failed (Inbound): $FailedCount"
Write-Output "[Info]  FilteredAsSpam (Inbound): $FilteredAsSpamCount"
Write-Output "[Info]  Quarantined (Inbound): $QuarantinedCount"

# XLSX (Stats)
if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\Status.csv")
{
    if(Test-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\Status.csv" -MaxLines 2)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\Status.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Inbound\Status.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Status (Inbound)" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        }
    }
}

# Add Worksheet w/ Pie Chart (Inbound)
$ExcelChart = New-ExcelChartDefinition -XRange Status -YRange Count -ChartType Pie -ShowPercent -Title "Delivery Status (Inbound)" -LegendPosition Bottom
$IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Inbound\Status.xlsx" -Append -WorksheetName "Pie Chart" -ExcelChartDefinition $ExcelChart -AutoNameRange

# Status (Outbound)
Write-Output "[Info]  Tracking the Delivery Status of all Outbound Messages ..."

# CSV (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.SenderAddress -eq "$UserId" } | Select-Object Status | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" } | Group-Object Status | Sort-Object Count -Descending | Select-Object @{Name='Status'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\Status.csv" -NoTypeInformation -Encoding UTF8
[int]$Failed = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" } | Where-Object {$_.Status -eq 'Failed' } | Measure-Object).Count
[int]$Delivered = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" } | Where-Object {$_.Status -eq 'Delivered' } | Measure-Object).Count
[int]$FilteredAsSpam = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" } | Where-Object {$_.Status -eq 'FilteredAsSpam' } | Measure-Object).Count
[int]$Quarantined = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" } | Where-Object {$_.Status -eq 'Quarantined' } | Measure-Object).Count
$FailedCount = '{0:N0}' -f $Failed
$DeliveredCount = '{0:N0}' -f $Delivered
$FilteredAsSpamCount = '{0:N0}' -f $FilteredAsSpam
$QuarantinedCount = '{0:N0}' -f $Quarantined
Write-Output "[Info]  Delivered (Outbound): $DeliveredCount"
Write-Output "[Info]  Failed (Outbound): $FailedCount"
Write-Output "[Info]  FilteredAsSpam (Outbound): $FilteredAsSpamCount"
Write-Output "[Info]  Quarantined (Outbound): $QuarantinedCount"

# XLSX (Stats)
if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\Status.csv")
{
    if(Test-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\Status.csv" -MaxLines 2)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\Status.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Outbound\Status.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Status (Outbound)" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        }
    }
}

# Add Worksheet w/ Pie Chart (Outbound)
$ExcelChart = New-ExcelChartDefinition -XRange Status -YRange Count -ChartType Pie -ShowPercent -Title "Delivery Status (Outbound)" -LegendPosition Bottom
$IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Outbound\Status.xlsx" -Append -WorksheetName "Pie Chart" -ExcelChartDefinition $ExcelChart -AutoNameRange

# Delivery Status
#
# https://learn.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/message-trace-modern-eac#delivery-status
#
# Delivered      - The message was successfully delivered to the intended destination.
# Expanded       - A distribution group recipient was expanded before delivery to the individual members of the group.
# Failed         - The message wasn't delivered.
# FilteredAsSpam - The message was identified as spam, and was rejected or blocked (not quarantined).
# Pending        - Delivery of the message is being attempted or reattempted.
# Quarantined    - The message was quarantined (as spam, bulk mail, or phishing).
# Resolved       - The message was redirected to a new recipient address based on an Active Directory look up. When this event happens, the original recipient address is listed in a separate row in the message trace along with the final delivery status for the message.

}

Start-Processing

#############################################################################################################################################################################################

Function Get-IPLocation {

# Count IP addresses
Write-Output "[Info]  Parsing Message Trace Logs for FromIP Property ..."
New-Item "$OUTPUT_FOLDER\FromIP" -ItemType Directory -Force | Out-Null
$Data = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Select-Object -ExpandProperty FromIP | Where-Object { $_.Trim() -ne "" }

$Unique = $Data | Sort-Object -Unique
$Unique | Out-File "$OUTPUT_FOLDER\FromIP\IP-All.txt"

$Count = ($Unique | Measure-Object).Count
$Total = ($Data | Measure-Object).Count
Write-Output "[Info]  $Count IP addresses found ($Total)"

# IPv4
# https://ipinfo.io/bogon
$IPv4 = "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
$Private = "^(192\.168|10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.)"
$Special = "^(0\.0\.0\.0|127\.0\.0\.1|169\.254\.|224\.0\.0)"
Get-Content "$OUTPUT_FOLDER\FromIP\IP-All.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Out-File "$OUTPUT_FOLDER\FromIP\IPv4-All.txt"
Get-Content "$OUTPUT_FOLDER\FromIP\IP-All.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Where-Object {$_ -notmatch $Private} | Where-Object {$_ -notmatch $Special} | Out-File "$OUTPUT_FOLDER\FromIP\IPv4.txt"

# Count
$Total = (Get-Content "$OUTPUT_FOLDER\FromIP\IPv4-All.txt" | Measure-Object).Count # Public (Unique) + Private (Unique) --> Note: Extracts IPv4 addresses of IPv4-compatible IPv6 addresses.
$Public = (Get-Content "$OUTPUT_FOLDER\FromIP\IPv4.txt" | Measure-Object).Count # Public (Unique)
Write-Output "[Info]  $Public Public IPv4 addresses found ($Total)"

# IPv6
# https://ipinfo.io/bogon
$IPv6 = ":(?::[a-f\d]{1,4}){0,5}(?:(?::[a-f\d]{1,4}){1,2}|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}|:)|(?::(?:[a-f\d]{1,4})?|(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[a-f\d]{1,4}(?::[a-f\d]{1,4})?|))|(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[a-f\d]{1,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){0,2})|:))|(?:(?::[a-f\d]{1,4}){0,2}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,3}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))"
$Bogon = "^(::1|::ffff:|100::|2001:10::|2001:db8::|fc00::|fe80::|fec0::|ff00::)"
Get-Content "$OUTPUT_FOLDER\FromIP\IP-All.txt" | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Out-File "$OUTPUT_FOLDER\FromIP\IPv6-All.txt"
#Get-Content "$OUTPUT_FOLDER\FromIP\IP-All.txt" | ForEach-Object{($_ -split "\s+")[5]} | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Where-Object {$_ -notmatch $Bogon} | Out-File "$OUTPUT_FOLDER\FromIP\IPv6.txt"
Get-Content -Path "$OUTPUT_FOLDER\FromIP\IPv6-All.txt" | & $IPinfo grepip -o | Out-File "$OUTPUT_FOLDER\FromIP\IPv6.txt" -Encoding UTF8

# Count
$Total = (Get-Content "$OUTPUT_FOLDER\FromIP\IPv6-All.txt" | Measure-Object).Count # including Bogus IPv6 addresses (e.g. IPv4-compatible IPv6 addresses)
$Public = (Get-Content "$OUTPUT_FOLDER\FromIP\IPv6.txt" | Measure-Object).Count
Write-Output "[Info]  $Public Public IPv6 addresses found ($Total)"

# IP.txt
Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\FromIP\IP.txt" # Header

# IPv4.txt
if (Test-Path "$OUTPUT_FOLDER\FromIP\IPv4.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\FromIP\IPv4.txt").Length -gt 0kb)
    {
        Get-Content -Path "$OUTPUT_FOLDER\FromIP\IPv4.txt" | Out-File "$OUTPUT_FOLDER\FromIP\IP.txt" -Append
    }
}

# IPv6.txt
if (Test-Path "$OUTPUT_FOLDER\FromIP\IPv6.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\FromIP\IPv6.txt").Length -gt 0kb)
    {
        Get-Content -Path "$OUTPUT_FOLDER\FromIP\IPv6.txt" | Out-File "$OUTPUT_FOLDER\FromIP\IP.txt" -Append
    }
}

# IP (Inbound)
New-Item "$OUTPUT_FOLDER\FromIP\Inbound" -ItemType Directory -Force | Out-Null
$Data = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" }  | Select-Object -ExpandProperty FromIP | Where-Object { $_.Trim() -ne "" }
$Unique = $Data | Sort-Object -Unique
$Unique | Out-File "$OUTPUT_FOLDER\FromIP\Inbound\IP-All.txt"

# IPv4 (Inbound)
Get-Content "$OUTPUT_FOLDER\FromIP\Inbound\IP-All.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Out-File "$OUTPUT_FOLDER\FromIP\Inbound\IPv4-All.txt"
Get-Content "$OUTPUT_FOLDER\FromIP\Inbound\IP-All.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Where-Object {$_ -notmatch $Private} | Where-Object {$_ -notmatch $Special} | Out-File "$OUTPUT_FOLDER\FromIP\Inbound\IPv4.txt"

# IPv6 (Inbound)
Get-Content "$OUTPUT_FOLDER\FromIP\Inbound\IP-All.txt" | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Out-File "$OUTPUT_FOLDER\FromIP\Inbound\IPv6-All.txt"
Get-Content "$OUTPUT_FOLDER\FromIP\Inbound\IP-All.txt" | ForEach-Object{($_ -split "\s+")[5]} | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Where-Object {$_ -notmatch $Bogon} | Out-File "$OUTPUT_FOLDER\FromIP\Inbound\IPv6.txt"

# IP-Inbound.txt
Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\FromIP\Inbound\IP.txt" # Header

# IPv4.txt
if (Test-Path "$OUTPUT_FOLDER\FromIP\Inbound\IPv4.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\FromIP\Inbound\IPv4.txt").Length -gt 0kb)
    {
        Get-Content -Path "$OUTPUT_FOLDER\FromIP\Inbound\IPv4.txt" | Out-File "$OUTPUT_FOLDER\FromIP\Inbound\IP.txt" -Append
    }
}

# IPv6.txt
if (Test-Path "$OUTPUT_FOLDER\FromIP\Inbound\IPv6.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\FromIP\Inbound\IPv6.txt").Length -gt 0kb)
    {
        Get-Content -Path "$OUTPUT_FOLDER\FromIP\Inbound\IPv6.txt" | Out-File "$OUTPUT_FOLDER\FromIP\Inbound\IP.txt" -Append
    }
}

# IP (Outbound)
New-Item "$OUTPUT_FOLDER\FromIP\Outbound" -ItemType Directory -Force | Out-Null
$Data = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" }  | Select-Object -ExpandProperty FromIP | Where-Object { $_.Trim() -ne "" }
$Unique = $Data | Sort-Object -Unique
$Unique | Out-File "$OUTPUT_FOLDER\FromIP\Outbound\IP-All.txt"

# IPv4 (Outbound)
Get-Content "$OUTPUT_FOLDER\FromIP\Outbound\IP-All.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Out-File "$OUTPUT_FOLDER\FromIP\Outbound\IPv4-All.txt"
Get-Content "$OUTPUT_FOLDER\FromIP\Outbound\IP-All.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Where-Object {$_ -notmatch $Private} | Where-Object {$_ -notmatch $Special} | Out-File "$OUTPUT_FOLDER\FromIP\Outbound\IPv4.txt"

# IPv6 (Outbound)
Get-Content "$OUTPUT_FOLDER\FromIP\Outbound\IP-All.txt" | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Out-File "$OUTPUT_FOLDER\FromIP\Outbound\IPv6-All.txt"
Get-Content "$OUTPUT_FOLDER\FromIP\Outbound\IP-All.txt" | ForEach-Object{($_ -split "\s+")[5]} | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Where-Object {$_ -notmatch $Bogon} | Out-File "$OUTPUT_FOLDER\FromIP\Outbound\IPv6.txt"

# IP-Outbound.txt
Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\FromIP\Outbound\IP.txt" # Header

# IPv4.txt
if (Test-Path "$OUTPUT_FOLDER\FromIP\Outbound\IPv4.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\FromIP\Outbound\IPv4.txt").Length -gt 0kb)
    {
        Get-Content -Path "$OUTPUT_FOLDER\FromIP\Outbound\IPv4.txt" | Out-File "$OUTPUT_FOLDER\FromIP\Outbound\IP.txt" -Append
    }
}

# IPv6.txt
if (Test-Path "$OUTPUT_FOLDER\FromIP\Outbound\IPv6.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\FromIP\Outbound\IPv6.txt").Length -gt 0kb)
    {
        Get-Content -Path "$OUTPUT_FOLDER\FromIP\Outbound\IPv6.txt" | Out-File "$OUTPUT_FOLDER\FromIP\Outbound\IP.txt" -Append
    }
}

# Check IPinfo Subscription Plan (https://ipinfo.io/pricing)
if (Test-Path "$($IPinfo)")
{
    $Quota = & $IPinfo quota 2>&1
    if ($Quota -eq "err: please login first to check quota")
    {
        # Login
        & $IPinfo init "$Token" > $null
        $Quota = & $IPinfo quota 2>&1
    }

    Write-Output "[Info]  Checking IPinfo Subscription Plan ..."
    [int]$TotalRequests = $Quota | Select-String -Pattern "Total Requests" | ForEach-Object{($_ -split "\s+")[-1]}
    [int]$RemainingRequests = $Quota | Select-String -Pattern "Remaining Requests" | ForEach-Object{($_ -split "\s+")[-1]}
    $TotalMonth = '{0:N0}' -f $TotalRequests | ForEach-Object {$_ -replace ' ','.'}
    $RemainingMonth = '{0:N0}' -f $RemainingRequests | ForEach-Object {$_ -replace ' ','.'}
    $script:PrivacyDetection = & $IPinfo myip --token "$Token" -f privacy.vpn | Select-String -Pattern "false|true" -Quiet

    if ($PrivacyDetection -eq "True")
    {
        Write-output "[Info]  IPinfo Subscription Plan w/ Privacy Detection found"
        Write-Output "[Info]  $RemainingMonth Requests left this month"
    }
    else
    {
        Write-output "[Info]  IPinfo Subscription: Free ($TotalMonth Requests/Month)"
        Write-Output "[Info]  $RemainingMonth Requests left this month"
    }
}

# IPinfo CLI
if (Test-Path "$($IPinfo)")
{
    if (Test-Path "$OUTPUT_FOLDER\FromIP\IP.txt")
    {
        if ((Get-Item "$OUTPUT_FOLDER\FromIP\IP.txt").Length -gt 0kb)
        {
            # Internet Connectivity Check (Vista+)
            $NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]‘{DCB00C01-570F-4A9B-8D69-199FDBA5723B}’)).IsConnectedToInternet

            if (!($NetworkListManager -eq "True"))
            {
                Write-Host "[Error] Your computer is NOT connected to the Internet. IP addresses cannot be checked via IPinfo API." -ForegroundColor Red
            }
            else
            {
                # Check if IPinfo.io is reachable
                if (!(Test-NetConnection -ComputerName ipinfo.io -Port 443).TcpTestSucceeded)
                {
                    Write-Host "[Error] ipinfo.io is NOT reachable. IP addresses cannot be checked via IPinfo API." -ForegroundColor Red
                }
                else
                {
                    # Map IPs
                    # https://ipinfo.io/map
                    New-Item "$OUTPUT_FOLDER\FromIP\IPinfo" -ItemType Directory -Force | Out-Null

                    # All
                    Get-Content "$OUTPUT_FOLDER\FromIP\IP.txt" | & $IPinfo map | Out-File "$OUTPUT_FOLDER\FromIP\IPinfo\Map-All.txt"

                    # Inbound
                    Get-Content "$OUTPUT_FOLDER\FromIP\Inbound\IP.txt" | & $IPinfo map | Out-File "$OUTPUT_FOLDER\FromIP\IPinfo\Map-Inbound.txt"

                    # Outbound
                    Get-Content "$OUTPUT_FOLDER\FromIP\Outbound\IP.txt" | & $IPinfo map | Out-File "$OUTPUT_FOLDER\FromIP\IPinfo\Map-Outbound.txt"

                    # Access Token
                    # https://ipinfo.io/signup?ref=cli
                    if (!("$Token" -eq "access_token"))
                    {
                        # Summarize IPs
                        # https://ipinfo.io/summarize-ips

                        # TXT (lists VPNs)
                        Get-Content -Path "$OUTPUT_FOLDER\FromIP\IP.txt" | & $IPinfo summarize -t $Token | Out-File "$OUTPUT_FOLDER\FromIP\IPinfo\Summary.txt"

                        # CSV --> No Privacy Detection --> Standard ($249/month w/ 250k lookups)
                        Get-Content -Path "$OUTPUT_FOLDER\FromIP\IP.txt" | & $IPinfo --csv -t $Token | Out-File "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo.csv"

                        # Custom CSV (Free)
                        if (Test-Path "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo.csv")
                        {
                            if(Test-Csv -Path "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo.csv" -MaxLines 2)
                            {
                                $Import = Import-Csv "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo.csv" -Delimiter ","

                                $Import | Foreach-Object {

                                    New-Object -TypeName PSObject -Property @{
                                        "IP"           = $_ | Select-Object -ExpandProperty ip
                                        "City"         = $_ | Select-Object -ExpandProperty city
                                        "Region"       = $_ | Select-Object -ExpandProperty region
                                        "Country"      = $_ | Select-Object -ExpandProperty country
                                        "Country Name" = $_ | Select-Object -ExpandProperty country_name
                                        "EU"           = $_ | Select-Object -ExpandProperty isEU
                                        "Location"     = $_ | Select-Object -ExpandProperty loc
                                        "ASN"          = $_ | Select-Object -ExpandProperty org | ForEach-Object{($_ -split "\s+")[0]}
                                        "OrgName"      = $_ | Select-Object -ExpandProperty org | ForEach-Object { $_ -replace "^AS[0-9]+ " } # OrgName
                                        "Postal Code"  = $_ | Select-Object -ExpandProperty postal
                                        "Timezone"     = $_ | Select-Object -ExpandProperty timezone
                                        }
                                } | Select-Object "IP","City","Region","Country","Country Name","EU","Location","ASN","OrgName","Postal Code","Timezone" | Sort-Object {$_.ip -as [Version]} | ConvertTo-Csv -NoTypeInformation -Delimiter "," | Out-File "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo-Custom.csv"
                            }
                        }

                        # Custom XLSX (Free)
                        if (Test-Path "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo-Custom.csv")
                        {
                            if(Test-Csv -Path "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo-Custom.csv" -MaxLines 2)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo-Custom.csv" -Delimiter "," | Sort-Object {$_.ip -as [Version]}
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo-Custom.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -PivotRows "Country Name" -PivotData @{"IP"="Count"} -WorkSheetname "IPinfo (Free)" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
                                # HorizontalAlignment "Center" of columns A-K
                                $WorkSheet.Cells["A:K"].Style.HorizontalAlignment="Center"
                                }
                            }
                        }

                        # Count
                        if (Test-Path "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo-Custom.csv")
                        {
                            if(Test-Csv -Path "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo-Custom.csv" -MaxLines 2)
                            {
                                # Suspicious ASN (Autonomous System Number)
                                $Data = Import-Csv -Path "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo-Custom.csv" -Delimiter ","
                                $Total = ($Data | Select-Object ASN | Measure-Object).Count
                                $Count = ($Data | Select-Object ASN -Unique | Measure-Object).Count
                                $ASN = $AsnBlacklist_HashTable.Count
                                Write-Output "[Info]  $Count ASN found ($Total)"
                                Write-Output "[Info]  Initializing ASN Blacklist ($ASN) ..."

                                # Iterating over the HashTable
                                foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                {
                                    $Import = $Data | Where-Object { $_.ASN -eq "AS$ASN" }
                                    $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
                                    if ($Count -gt 0)
                                    {
                                        $OrgName = $AsnBlacklist_HashTable["$ASN"][0]
                                        Write-Host "[Alert] Suspicious ASN detected: AS$ASN - $OrgName ($Count)" -ForegroundColor Red
                                    }
                                }

                                # Suspicious Countries
                                $Data = Import-Csv -Path "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo-Custom.csv" -Delimiter ","
                                $Total = ($Data | Select-Object Country | Measure-Object).Count
                                $Count = ($Data | Select-Object Country -Unique | Measure-Object).Count
                                $Countries = $CountryBlacklist_HashTable.Count
                                Write-Output "[Info]  $Count Countries found ($Total)"
                                Write-Output "[Info]  Initializing Country Blacklist ($Countries) ..."

                                # Iterating over the HashTable
                                foreach ($CountryName in $CountryBlacklist_HashTable.Keys) 
                                {
                                    $Import = $Data | Where-Object { $_."Country Name" -eq "$CountryName" }
                                    $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
                                    if ($Count -gt 0)
                                    {
                                        Write-Host "[Alert] Suspicious Country detected: $CountryName ($Count)" -ForegroundColor Red
                                    }
                                }
                            }
                        }

                        # XLSX (Free)
                        if (Test-Path "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo.csv")
                        {
                            if(Test-Csv -Path "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo.csv" -MaxLines 2)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo.csv" -Delimiter "," | Select-Object ip,city,region,country,country_name,isEU,loc,org,postal,timezone | Sort-Object {$_.ip -as [Version]}
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "IPinfo (Free)" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
                                # HorizontalAlignment "Center" of columns A-J
                                $WorkSheet.Cells["A:J"].Style.HorizontalAlignment="Center"
                                }
                            }
                        }

                        # Create HashTable and import 'IPinfo-Custom.csv'
                        $script:IPinfo_HashTable = @{}
                        if (Test-Path "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo-Custom.csv")
                        {
                            if(Test-Csv -Path "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo-Custom.csv" -MaxLines 2)
                            {
                                Import-Csv -Path "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo-Custom.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $IPinfo_HashTable[$_.IP] = $_.City,$_.Country,$_."Country Name",$_.ASN,$_.OrgName }

                                # Count Ingested Properties
                                $Count = $IPinfo_HashTable.Count
                                Write-Output "[Info]  Initializing 'IPinfo-Custom.csv' Lookup Table ($Count) ..."
                            }
                        }

                        # Hunt
                        Write-Output "[Info]  Creating Enhanced Message Trace Report (Hunt View) ..."
                        $Records = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8

                        # CSV
                        $Results = [Collections.Generic.List[PSObject]]::new()
                        ForEach($Record in $Records)
                        {
                            # FromIP
                            $IP = $Record.FromIP 
                            #| & $IPinfo grepip -o
                            #$IP = $Record.FromIP | ForEach-Object {$_ -replace "^::ffff:"} # Remove Prefix of IPv4-mapped IPv6 address

                            # Check if HashTable contains IP
                            if($IPinfo_HashTable.ContainsKey("$IP"))
                            {
                                $City        = $IPinfo_HashTable["$IP"][0]
                                $Country     = $IPinfo_HashTable["$IP"][1]
                                $CountryName = $IPinfo_HashTable["$IP"][2]
                                $ASN         = $IPinfo_HashTable["$IP"][3]
                                $OrgName     = $IPinfo_HashTable["$IP"][4]
                            }
                            else
                            {
                                $City        = ""
                                $Country     = ""
                                $CountryName = ""
                                $ASN         = ""
                                $OrgName     = ""
                            }

                            # Direction
                            if($Record.RecipientAddress -eq "$UserId")
                            {
                                $Direction = "Inbound" # Messages sent to recipients in your organization.
                            }
                            else
                            {
                                $Direction = "Outbound" # Messages sent from users in your organization.
                            }

                            $Line = [PSCustomObject]@{
                                "Received"         = (Get-Date $Record.Received).ToString("yyyy-MM-dd HH:mm:ss") # UTC
                                "SenderAddress"    = $Record.SenderAddress
                                "RecipientAddress" = $Record.RecipientAddress
                                "Subject"          = $Record.Subject
                                "Direction"        = $Direction
                                "Status"           = $Record.Status
                                "MessageId"        = $Record.MessageId
                                "MessageTraceId"   = $Record.MessageTraceId
                                "Size"             = $Record.Size
                                "ToIP"             = $Record.ToIP
                                "FromIP"           = $IP
                                "City"             = $City
                                "Country"          = $Country
                                "Country Name"     = $CountryName
                                "ASN"              = $ASN
                                "OrgName"          = $OrgName
                            }

                            $Results.Add($Line)
                        }

                        $Results | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -NoTypeInformation -Encoding UTF8

                        # XLSX
                        if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv")
                        {
                            if(Test-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -MaxLines 2)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -Delimiter "," | Sort-Object { $_.Received -as [datetime] } -Descending
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\XLSX\Hunt.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezePane 2,7 -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -WorkSheetname "Hunt" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
                                # HorizontalAlignment "Center" of columns A-P
                                $WorkSheet.Cells["A:P"].Style.HorizontalAlignment="Center"

                                # Iterating over the ASN-Whitelist HashTable
                                foreach ($ASN in $AsnWhitelist_HashTable.Keys) 
                                {
                                    $ConditionValue = 'NOT(ISERROR(FIND("{0}",$O1)))' -f $ASN
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["O:O"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Green
                                }
                                    
                                # Iterating over the ASN-Blacklist HashTable
                                foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                {
                                    $ConditionValue = 'NOT(ISERROR(FIND("{0}",$O1)))' -f $ASN
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["O:O"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                }

                                # Iterating over the Country-Blacklist HashTable
                                foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                                {
                                    $ConditionValue = 'NOT(ISERROR(FIND("{0}",$N1)))' -f $Country
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["N:N"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                }

                                # ConditionalFormatting - Status
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Quarantined",$F1)))' -BackgroundColor Red
                                
                                # ConditionalFormatting - MessageId
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("<em",$G1)))' -BackgroundColor Red # Messages sent by eM Client (Inbound and Outbound)

                                }
                            }
                        }

                        # ASN 
                        
                        # CSV (Stats)
                        if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv")
                        {
                            if(Test-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -MaxLines 2)
                            {
                                $Total = (Import-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object ASN | Where-Object {$_.ASN -ne '' } | Measure-Object).Count
                                Import-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object ASN,OrgName | Where-Object {$_.ASN -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object ASN,OrgName | Select-Object Count,@{Name='ASN'; Expression={ $_.Values[0] }},@{Name='OrgName'; Expression={ $_.Values[1] }},@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\ASN.csv" -NoTypeInformation -Encoding UTF8
                            }
                        }

                        # XLSX (Stats)
                        if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\ASN.csv")
                        {
                            if(Test-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\ASN.csv" -MaxLines 2)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\ASN.csv" -Delimiter ","
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\ASN.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ASN" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
                                # HorizontalAlignment "Center" of columns A-D
                                $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"

                                # Iterating over the ASN-Whitelist HashTable
                                foreach ($ASN in $AsnWhitelist_HashTable.Keys) 
                                {
                                    $ConditionValue = 'NOT(ISERROR(FIND("{0}",$B1)))' -f $ASN
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Green
                                }

                                # Iterating over the ASN-Blacklist HashTable
                                foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                {
                                    $ConditionValue = 'NOT(ISERROR(FIND("{0}",$B1)))' -f $ASN
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                }
                                    
                                }
                            }
                        }

                        # Country / Country Name

                        # CSV (Stats)
                        if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv")
                        {
                            if(Test-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -MaxLines 2)
                            {
                                $Total = (Import-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object Country | Where-Object {$_.Country -ne '' } | Measure-Object).Count
                                Import-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object Country,"Country Name" | Where-Object {$_.Country -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object Country,"Country Name" | Select-Object Count,@{Name='Country'; Expression={ $_.Values[0] }},@{Name='Country Name'; Expression={ $_.Values[1] }},@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Country.csv" -NoTypeInformation -Encoding UTF8

                                # Countries
                                $Countries = (Import-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object Country -Unique | Where-Object { $_.Country -ne '' } | Measure-Object).Count

                                # Cities
                                $Cities = (Import-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object City -Unique | Where-Object { $_.City -ne '' } | Measure-Object).Count

                                Write-Output "[Info]  $Countries Countries and $Cities Cities found"
                            }
                        }

                        # XLSX (Stats)
                        if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Country.csv")
                        {
                            if(Test-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Country.csv" -MaxLines 2)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Country.csv" -Delimiter ","
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Country.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Countries" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
                                # HorizontalAlignment "Center" of columns A-D
                                $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"

                                # Iterating over the Country-Blacklist HashTable
                                foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                                {
                                    $ConditionValue = 'NOT(ISERROR(FIND("{0}",$C1)))' -f $Country
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                }
                                    
                                }
                            }
                        }

                        # FromIP / Country Name

                        # CSV (Stats)
                        if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv")
                        {
                            if(Test-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -MaxLines 2)
                            {
                                $Total = (Import-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object FromIP | Where-Object {$_.FromIP -ne '' } | Measure-Object).Count
                                Import-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Select-Object FromIP,Country,"Country Name",ASN,OrgName | Where-Object {$_.FromIP -ne '' } | Where-Object {$_."Country Name" -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object FromIP,Country,"Country Name",ASN,OrgName | Select-Object Count,@{Name='FromIP'; Expression={ $_.Values[0] }},@{Name='Country'; Expression={ $_.Values[1] }},@{Name='Country Name'; Expression={ $_.Values[2] }},@{Name='ASN'; Expression={ $_.Values[3] }},@{Name='OrgName'; Expression={ $_.Values[4] }},@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\FromIP.csv" -NoTypeInformation -Encoding UTF8
                            }
                        }

                        # XLSX (Stats)
                        if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\FromIP.csv")
                        {
                            if(Test-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\FromIP.csv" -MaxLines 2)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\FromIP.csv" -Delimiter ","
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\FromIP.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "FromIP" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
                                # HorizontalAlignment "Center" of columns A-G
                                $WorkSheet.Cells["A:G"].Style.HorizontalAlignment="Center"

                                # Iterating over the ASN-Whitelist HashTable
                                foreach ($ASN in $AsnWhitelist_HashTable.Keys) 
                                {
                                    $ConditionValue = 'NOT(ISERROR(FIND("{0}",$E1)))' -f $ASN
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["E:F"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Green
                                }

                                # Iterating over the ASN-Blacklist HashTable
                                foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                {
                                    $ConditionValue = 'NOT(ISERROR(FIND("{0}",$E1)))' -f $ASN
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["E:F"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                }

                                # Iterating over the Country-Blacklist HashTable
                                foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                                {
                                    $ConditionValue = 'NOT(ISERROR(FIND("{0}",$D1)))' -f $Country
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                }

                                }
                            }
                        }

                        # Line Charts
                        New-Item "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\LineCharts" -ItemType Directory -Force | Out-Null

                        # Inbound
                        $Import = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.Direction -eq "Inbound" } | Select-Object Received,Direction | Group-Object{($_.Received -split "\s+")[0]} | Select-Object Count,@{Name='Received'; Expression={ $_.Values[0] }} | Sort-Object { $_.Received -as [datetime] }
                        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
                        if ($Count -gt 0)
                        {
                            $ChartDefinition = New-ExcelChartDefinition -XRange Received -YRange Count -Title "Inbound Messages" -ChartType Line -NoLegend -Width 1200
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\LineCharts\Inbound.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
                        }

                        # Outbound
                        $Import = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.Direction -eq "Outbound" } | Select-Object Received,Direction | Group-Object{($_.Received -split "\s+")[0]} | Select-Object Count,@{Name='Received'; Expression={ $_.Values[0] }} | Sort-Object { $_.Received -as [datetime] }
                        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
                        if ($Count -gt 0)
                        {
                            $ChartDefinition = New-ExcelChartDefinition -XRange Received -YRange Count -Title "Outbound Messages" -ChartType Line -NoLegend -Width 1200
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\LineCharts\Outbound.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
                        }
                    }
                }
            }
        }
    }
}
else
{
    Write-Output "[Info]  ipinfo.exe NOT found."
}

}

Get-IPLocation

#############################################################################################################################################################################################

Function Get-Analytics {

# Import Hunt Data
if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv")
{
    $Data = Import-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8
}

# SharePoint Email Notifications (SharePoint Files shared)
$Import = $Data | Where-Object {$_.MessageId -like "<Share-*" }
[int]$Count = ($Import | Measure-Object).Count
if ($Count -gt 0)
{
    [int]$Inbound = ($Data | Where-Object {$_.MessageId -like "<Share-*"} | Where-Object {$_.Direction -like "Inbound"} | Measure-Object).Count
    [int]$Outbound = ($Data | Where-Object {$_.MessageId -like "<Share-*"} | Where-Object {$_.Direction -like "Outbound"} | Measure-Object).Count
    Write-Host "[Alert] $Count Shared File Email Notification(s) from OneDrive/SharePoint found (ODSP Notify) (Inbound: $Inbound, Outbound: $Outbound)" -ForegroundColor Yellow
    New-Item "$OUTPUT_FOLDER\MessageTraceLogs\Analytics\ODSP-Notify" -ItemType Directory -Force | Out-Null
    
    # XLSX
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Analytics\ODSP-Notify\Share.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SharePoint Sharing Operation" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-C and E-P
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    $WorkSheet.Cells["E:P"].Style.HorizontalAlignment="Center"
    }
}

# OneTimePasscode Email Notifications (OneTimePasscode received) --> SendEmail@odspnotify --> ODSP = OneDrive/SharePoint
$Import = $Data | Where-Object {$_.MessageId -like "<OneTimePasscode-*" }
[int]$Count = ($Import | Measure-Object).Count
if ($Count -gt 0)
{
    [int]$Inbound = ($Data | Where-Object {$_.MessageId -like "<OneTimePasscode-*"} | Where-Object {$_.Direction -eq "Inbound"} | Measure-Object).Count
    [int]$Outbound = ($Data | Where-Object {$_.MessageId -like "<OneTimePasscode-*"} | Where-Object {$_.Direction -eq "Outbound"} | Measure-Object).Count
    Write-Host "[Alert] $OTP OneTimePasscode Email Notification(s) from OneDrive/SharePoint found (ODSP Notify) (Inbound: $Inbound, Outbound: $Outbound)" -ForegroundColor Yellow
    New-Item "$OUTPUT_FOLDER\MessageTraceLogs\Analytics\ODSP-Notify" -ItemType Directory -Force | Out-Null

    # XLSX
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Analytics\ODSP-Notify\OneTimePasscode.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "OneTimePasscode received" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-C and E-P
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    $WorkSheet.Cells["E:P"].Style.HorizontalAlignment="Center"
    }
}

# Suspicious Inbound Email Messages sent by 'eM Client' found
$Import = $Data | Where-Object {$_.Direction -eq "Inbound"} | Where-Object {$_.MessageId -like "<em*"}
[int]$Count = ($Import | Measure-Object).Count
if ($Count -gt 0)
{
    Write-Host "[Alert] Suspicious Inbound Email Messages sent by 'eM Client' found ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\MessageTraceLogs\Analytics" -ItemType Directory -Force | Out-Null

    # XLSX
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Analytics\eM-Client_Inbound.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Inbound - eM Client" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-C and E-P
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    $WorkSheet.Cells["E:P"].Style.HorizontalAlignment="Center"
    # ConditionalFormatting - MessageId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("<em",$G1)))' -BackgroundColor Red
    }
}

# Suspicious Outbound Email Messages sent by 'eM Client' found
$Import = $Data | Where-Object {$_.Direction -eq "Outbound"} | Where-Object {$_.MessageId -like "<em*"}
[int]$Count = ($Import | Measure-Object).Count
if ($Count -gt 0)
{
    Write-Host "[Alert] Suspicious Outbound Email Messages sent by 'eM Client' found ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\MessageTraceLogs\Analytics" -ItemType Directory -Force | Out-Null

    # XLSX
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Analytics\eM-Client_Outbound.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Outbound - eM Client" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-C and E-P
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    $WorkSheet.Cells["E:P"].Style.HorizontalAlignment="Center"
    # ConditionalFormatting - MessageId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("<em",$G1)))' -BackgroundColor Red
    }
}

# 50+ Outbound Email Messages with the same 'Subject' (Outbound Spam)
[int]$Count = ($Data | Where-Object {$_.Direction -eq "Outbound"} | Group-Object Subject | Where-Object Count -ge 50  | Measure-Object).Count
if ($Count -gt 0)
{
    Write-Host "[Alert] 50+ Outbound Email Message(s) with the same 'Subject' found ($Count)" -ForegroundColor Red
}

# 50+ Outbound Shared File Email Notification(s) from OneDrive/SharePoint with the same 'Subject' (Spreader)
[int]$Count = ($Data | Where-Object {$_.MessageId -like "<Share-*" } | Where-Object {$_.Direction -eq "Outbound"} | Group-Object Subject | Where-Object Count -ge 50  | Measure-Object).Count
if ($Count -gt 0)
{
    Write-Host "[Alert] 50+ Outbound Shared File Email Notification(s) from OneDrive/SharePoint with the same 'Subject' found ($Count)" -ForegroundColor Red
}

}

Get-Analytics

#endregion Analysis

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

# MessageBox UI
$MessageBody = "Status: Message Trace Log Analysis completed."
$MessageTitle = "MTL-Analyzer.ps1 (https://lethal-forensics.com/)"
$ButtonType = "OK"
$MessageIcon = "Information"
$Result = [System.Windows.Forms.MessageBox]::Show($MessageBody, $MessageTitle, $ButtonType, $MessageIcon)

if ($Result -eq "OK" ) 
{
    # Reset Progress Preference
    $Global:ProgressPreference = $OriginalProgressPreference

    # Reset Windows Title
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

#endregion Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# SIG # Begin signature block
# MIIs3gYJKoZIhvcNAQcCoIIszzCCLMsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUi8WhCNporvoMkhhNv+sewJyk
# S7GggiYXMIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
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
# MRYEFIVyFwDkApYDrNhdSmkBRAz40e2NMA0GCSqGSIb3DQEBAQUABIICAFfeyDBX
# GZ6U+RDcTo1AEwU86wiFnIGcSfqUl6s3O2tP00BKFmGPcROk7b6RBrZw/FTuD4JG
# ySax7TDSarZOU2b8q9+WPDkVv4JRyhXH/f2q+o6mUgUuDKP/mFHQ7+gNYy9hrYrh
# BS8cmSOViovLVf5Vr764b2tkMDVfy15Cn5F5yS4t8DMbTaRI+E6a3fJOLIPhpZkX
# cf+SptXlOeN09kWwyo4C4DJJqzC/LKl6XttnNR54PkPNxB7swpxDye74rxMekQIE
# yrASgCsY7vN42RpOudYlsJ9tDZifKSbLIdJ1ZYiRpiluFvPAVSMQ4vk4VVpAeCbj
# b1Eo1Ekl8ASnZJ126GSsm2NTMmTXb0QJawoTezBna33/K45wB9Thy88h2JhKCDgI
# eFsaCk2an6EF9mAG29aXj8qMKv+kaag1FDvYgC2nKZFPc5eTgrJQUifD9XFfyxyX
# gnL4FxETgJD6b+rRCuaf/D/5UQSayldcktY8IoB7uFO8vKNn6a6bmceAxrTDUipf
# Y1mAayOJQbpu3xplvCJ9GW2u1GFf1vdzPVfOSScPh2/+FFChB9igsZhXNeHehW3B
# DR4/2AviAbPw2yuNocQEjDM4jprE8k8aDaKSakbe0miupISsOguk+TPYIqI6dPke
# 9venSwHYQOBQ/K2Z5ecb++6Aw4aqHIRY/N8uoYIDIzCCAx8GCSqGSIb3DQEJBjGC
# AxAwggMMAgEBMGowVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGlt
# aXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBDQSBS
# NDECEQDnTvJVsFBP+tum3/f8i6MVMA0GCWCGSAFlAwQCAgUAoHkwGAYJKoZIhvcN
# AQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYwNzA2MTEzMTA0WjA/
# BgkqhkiG9w0BCQQxMgQwjShscOwEYOatZ9az8ENoLExfTQaZBf2k6LBY+Qo0vuBg
# rUFXwZ/AsRADZzjs/2QZMA0GCSqGSIb3DQEBAQUABIICAAqPtdD2vWstWQtLZmB+
# 5aOVrWm3zUzemAMmlpI45DWS0dknXZGhcriMbFWka5tHZwijVIz5L4ZA0c68hgsL
# zwyjJ0PrG+6XueDgqXOJfbYJ7j8ohLVChuPab1022UmVI1P+7rFtBQwlAo9BNPrI
# LWIcxLXRI20m6Y05pFyCskJoJsAGG8vRbH+Od0uhS4+E/jvKrc3yFY1q2w1ZsRZD
# eL4YpH9zrcWvKQhxVv8Ht8D3l+6KI5EumE1IrOQf1Qb4wzJ82AiqTeX6KecDFSPi
# ouObTdUalbT6Y9bkXemMjmq0RP9QoyErp0R8ltTtubq4cKJLEi7j17COMh+K6Vs+
# 8sIrdHiyFS6rG1gdmfHOgfCrGg+OYmMQ24HQzqhYeVjkLOXz3TRfVOv1H2ifnMMQ
# XFIANbEr6d2ypb+WV37Gt31XTZdwg8ub5THYKbKOaqm0d18opXbk+5ZsOUWx2xwE
# QWHct5bTaw6woUBEIO5zd2O3UBTgTrXoX8ZmPF6umDZhcJ/c4vf0c81LpVvuoPg7
# f9MbYc+bH0XjwYc0dS6YU9GYun+kPDlkNHRwXmmdsOuhjNSRbb8ivV/RucLwFDWX
# b4x2zNETr/ODPBmNkWK2yG6NahlnXyHZE3NFRyR7DbsFQs+oqa2xEk63AE9pz8L9
# amQT73gJj2pgJv/pW1ZAF6C+
# SIG # End signature block
