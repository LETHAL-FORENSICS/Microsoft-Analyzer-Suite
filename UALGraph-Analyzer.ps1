# UALGraph-Analyzer
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2026 Martin Willing. All rights reserved. Licensed under the MIT license.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2026-06-01
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
# DuckDB CLI v1.5.3 (2026-05-19)
# https://duckdb.org/install/?platform=windows&environment=cli
#
# ImportExcel v7.8.10 (2024-10-21)
# https://github.com/dfinke/ImportExcel
# Install-Module ImportExcel
#
# IPinfo CLI 3.3.2 (2026-04-28)
# https://ipinfo.io/signup?ref=cli --> Sign up for free
# https://github.com/ipinfo/cli
#
#
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.6456) and PowerShell 5.1 (5.1.19041.6456)
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.6456) and PowerShell 7.6.2
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################
<#
.SYNOPSIS
  UALGraph-Analyzer - Automated Processing of M365 Unified Audit Logs for DFIR

.DESCRIPTION
  UALGraph-GraphAnalyzer.ps1 is a PowerShell script utilized to simplify the analysis of M365 Unified Audit Logs extracted via "Microsoft Extractor Suite" by Invictus Incident Response.

  https://github.com/invictus-ir/Microsoft-Extractor-Suite (Microsoft-Extractor-Suite v4.1.0)

  https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/M365/UnifiedAuditLogGraph.html

  Single User Audit

.PARAMETER OutputDir
  Specifies the output directory. Default is "$env:USERPROFILE\Desktop\UALGraph-Analyzer".

  Note: The subdirectory 'UALGraph-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the JSON-based input file (<date>-<search_name>-UnifiedAuditLog.json).

.EXAMPLE
  PS> .\UALGraph-Analyzer.ps1

.EXAMPLE
  PS> .\UALGraph-Analyzer.ps1 -Path "$env:USERPROFILE\Desktop\<date>-<search_name>-UnifiedAuditLog.json"

.EXAMPLE
  PS> .\UALGraph-Analyzer.ps1 -Path "H:\Microsoft-Extractor-Suite\<date>-<search_name>-UnifiedAuditLog.json" -OutputDir "H:\Microsoft-Analyzer-Suite"

.NOTES
  Author - Martin Willing

.LINK
  https://lethal-forensics.com/
#>

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# Notes

# Audit (Standard)
# The default retention period for Audit (Standard) has changed from 90 days to 180 days. 
# Audit (Standard) logs generated before October 17, 2023 are retained for 90 days. Audit (Standard) logs generated on or after October 17, 2023 follow the new default retention of 180 days.

# Audit (Premium)
# To retain an audit log for longer than 180 days (and up to 1 year), the user who generates the audit log (by performing an audited activity) must be assigned an Office 365 E5 or Microsoft 365 E5 license or have a Microsoft 365 E5 Compliance or E5 eDiscovery and Audit add-on license. 
# To retain audit logs for 10 years, the user who generates the audit log must also be assigned a 10-year audit log retention add-on license in addition to an E5 license.

# https://learn.microsoft.com/en-us/purview/audit-log-retention-policies#default-audit-log-retention-policy

##############################################################################################################################
# Audit (Standard) # Audit (Premium)                                                                                         #
##############################################################################################################################
# 180 days         # 180 days --> 365 days         # 10 years                                                                #
##############################################################################################################################
#                  # Office 365 E5                 # 10-year audit log retention add-on license in addition to an E5 license #
#                  # Microsoft 365 E5              #                                                                         #
#                  # Microsoft 365 E5 Compliance   #                                                                         #
#                  # E5 eDiscovery                 #                                                                         #
#                  # Audit add-on license          #                                                                         #
##############################################################################################################################

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
    $script:SCRIPT_DIR = $PSScriptRoot
}
else
{
    # PowerShell 2
    $script:SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

# Colors
Add-Type -AssemblyName System.Drawing
$script:Green  = [System.Drawing.Color]::FromArgb(0,176,80) # Green
$script:Orange = [System.Drawing.Color]::FromArgb(255,192,0) # Orange

# Output Directory
if (!($OutputDir))
{
    $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\UALGraph-Analyzer" # Default
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
        $script:OUTPUT_FOLDER = "$OutputDir\UALGraph-Analyzer" # Custom
    }
}

# Tools

# cURL
$script:curl = "$env:SystemRoot\System32\curl.exe"

# DuckDB CLI
$script:DuckDB = "$SCRIPT_DIR\Tools\DuckDB\duckdb.exe"

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
#############################################################################################################################################################################################

#region Header

Function Invoke-Header {

# Check if the PowerShell script is being run with admin rights
if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "[Error] This PowerShell script must be run with admin rights." -ForegroundColor Red
    Write-Host ""
    Exit
}

# Check if PowerShell module 'ImportExcel' is installed
if (!(Get-Module -ListAvailable -Name ImportExcel))
{
    Write-Host "[Error] Please install 'ImportExcel' PowerShell module." -ForegroundColor Red
    Write-Host "[Info]  Check out: https://github.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/wiki#setup"
    Write-Host ""
    Exit
}

# Check if ipinfo.exe exists
if (!(Test-Path "$($IPinfo)"))
{
    Write-Host "[Error] ipinfo.exe NOT found." -ForegroundColor Red
    Write-Host ""
    Exit
}

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "UAL-Analyzer - Automated Processing of M365 Unified Audit Logs for DFIR"

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
        $OpenFileDialog.Filter = "UAL|*-UnifiedAuditLog.json|All Files (*.*)|*.*"
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
$script:StartTime = (Get-Date)

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
Write-Output "UALGraph-Analyzer - Automated Processing of M365 Unified Audit Logs for DFIR"
Write-Output "(c) 2026 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
Write-Output ""

# Analysis date (ISO 8601)
$script:AnalysisDate = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "Analysis date: $AnalysisDate UTC"
Write-Output ""

# Blacklists

# Create HashTable and import 'Application-Blacklist.csv'
$script:ApplicationBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\Application-Blacklist.csv")
{
    if ((Get-Content "$SCRIPT_DIR\Blacklists\Application-Blacklist.csv" -TotalCount 2).Count -gt 1)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\Application-Blacklist.csv" -Delimiter "," | ForEach-Object { $ApplicationBlacklist_HashTable[$_.AppId] = $_.AppDisplayName,$_.Severity }

        # Count Ingested Properties
        $Count = $ApplicationBlacklist_HashTable.Count
        Write-Output "[Info]  Initializing 'Application-Blacklist.csv' Lookup Table ($Count) ..."
    }
}

# Create HashTable and import 'ASN-Blacklist.csv'
$script:AsnBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\ASN-Blacklist.csv")
{
    if ((Get-Content "$SCRIPT_DIR\Blacklists\ASN-Blacklist.csv" -TotalCount 2).Count -gt 1)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\ASN-Blacklist.csv" -Delimiter "," | ForEach-Object { $AsnBlacklist_HashTable[$_.ASN] = $_.OrgName,$_.Info }

        # Count Ingested Properties
        $Count = $AsnBlacklist_HashTable.Count
        Write-Output "[Info]  Initializing 'ASN-Blacklist.csv' Lookup Table ($Count) ..."
    }
}

# Create HashTable and import 'Country-Blacklist.csv'
$script:CountryBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\Country-Blacklist.csv")
{
    if ((Get-Content "$SCRIPT_DIR\Blacklists\Country-Blacklist.csv" -TotalCount 2).Count -gt 1)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\Country-Blacklist.csv" -Delimiter "," | ForEach-Object { $CountryBlacklist_HashTable[$_."Country Name"] = $_.Country }

        # Count Ingested Properties
        $Count = $CountryBlacklist_HashTable.Count
        Write-Output "[Info]  Initializing 'Country-Blacklist.csv' Lookup Table ($Count) ..."
    }
}

# Create HashTable and import 'MoveToFolder-Blacklist.csv'
$script:MoveToFolderBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\MoveToFolder-Blacklist.csv")
{
    if ((Get-Content "$SCRIPT_DIR\Blacklists\MoveToFolder-Blacklist.csv" -TotalCount 2).Count -gt 1)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\MoveToFolder-Blacklist.csv" -Delimiter "," | ForEach-Object { $MoveToFolderBlacklist_HashTable[$_.Name] = $_.Language }

        # Count Ingested Properties
        $Count = $MoveToFolderBlacklist_HashTable.Count
        Write-Output "[Info]  Initializing 'MoveToFolder-Blacklist.csv' Lookup Table ($Count) ..."
    }
}

# Create HashTable and import 'Operation-Blacklist.csv'
$script:OperationBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\Operation-Blacklist.csv")
{
    if ((Get-Content "$SCRIPT_DIR\Blacklists\Operation-Blacklist.csv" -TotalCount 2).Count -gt 1)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\Operation-Blacklist.csv" -Delimiter "," | ForEach-Object { $OperationBlacklist_HashTable[$_.Operation] = $_.Severity }

        # Count Ingested Properties
        $Count = $OperationBlacklist_HashTable.Count
        Write-Output "[Info]  Initializing 'Operation-Blacklist.csv' Lookup Table ($Count) ..."
    }
}

# Create HashTable and import 'UserAgent-Blacklist.csv'
$script:UserAgentBlacklist_HashTable = New-Object System.Collections.Hashtable
if (Test-Path "$SCRIPT_DIR\Blacklists\UserAgent-Blacklist.csv")
{
    if ((Get-Content "$SCRIPT_DIR\Blacklists\UserAgent-Blacklist.csv" -TotalCount 2).Count -gt 1)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\UserAgent-Blacklist.csv" -Delimiter "," | ForEach-Object { $UserAgentBlacklist_HashTable[$_.UserAgent] = $_.Category,$_.Severity }

        # Count Ingested Properties
        $Count = $UserAgentBlacklist_HashTable.Count
        Write-Output "[Info]  Initializing 'UserAgent-Blacklist.csv' Lookup Table ($Count) ..."
    }
}

}

#endregion Header

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Analysis

# Unified Audit Log

Function Invoke-InitialProcessing {

$StartTime_Processing = (Get-Date)

# Input-Check
if (!(Test-Path "$LogFile" -PathType Leaf))
{
    Write-Host "[Error] $LogFile does not exist." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Check File Extension
$Extension = [IO.Path]::GetExtension($LogFile)
if (!($Extension -eq ".json" ))
{
    Write-Host "[Error] No JSON File provided." -ForegroundColor Red
    Write-Host ""
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

# Internet Connectivity Check
$NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]'{DCB00C01-570F-4A9B-8D69-199FDBA5723B}')).IsConnectedToInternet

if (!($NetworkListManager -eq "True"))
{
    Write-Host "[Error] Your computer is NOT connected to the Internet." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Check IPinfo Subscription Plan (https://ipinfo.io/pricing)
if (Test-Path "$($IPinfo)")
{
    $Quota = & $IPinfo quota 2>&1
    if ($Quota -match "err: please login first to check quota")
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

    if (& $IPinfo myip --token "$Token" | Select-String -Pattern "Privacy" -Quiet)
    {
        $script:PrivacyDetection = "True"
        Write-output "[Info]  IPinfo Subscription Plan w/ Privacy Detection found"
        Write-Output "[Info]  $RemainingMonth Requests left this month"
    }
    else
    {
        $script:PrivacyDetection = "False"
        Write-output "[Info]  IPinfo Subscription: Lite ($TotalMonth Requests/Month)"
        Write-Output "[Info]  $RemainingMonth Requests left this month"
    }
}

# Import JSON
$Data = Get-Content -Path "$LogFile" -Raw | ConvertFrom-Json | Sort-Object { $_.createdDateTime -as [datetime] } -Descending

# UserPrincipalName
$UPN = $Data | Select-Object userPrincipalName | Sort-Object -Unique
[int]$Count = ($UPN | Measure-Object).Count
if ($Count -gt 1)
{
    Write-Host "[Error] Single User Audit ONLY." -ForegroundColor Red
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}
else
{
    $UserPrincipalName = ($UPN).userPrincipalName
}

# Input Size
$InputSize = Get-FileSize((Get-Item "$LogFile").Length)
Write-Output "[Info]  Total Input Size: $InputSize"

# Count rows of JSON (w/ thousands separators)
$Count = 0
switch -File "$LogFile" { default { ++$Count } }
$Rows = '{0:N0}' -f $Count
Write-Output "[Info]  Total Lines: $Rows"

# Count Records (w/ thousands separators)
[int]$Count = ($Data | Measure-Object).Count
$Records = '{0:N0}' -f $Count
Write-Output "[Info]  Records: $Records"

# Processing M365 Unified Audit Logs
Write-Output "[Info]  Processing M365 Unified Audit Logs ($UserPrincipalName) ..."
New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\XLSX" -ItemType Directory -Force | Out-Null

$EndTime_Processing = (Get-Date)
$Time_Processing = ($EndTime_Processing-$StartTime_Processing)
('Initial Processing duration:           {0} h {1} min {2} sec' -f $Time_Processing.Hours, $Time_Processing.Minutes, $Time_Processing.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#############################################################################################################################################################################################
#############################################################################################################################################################################################

Function Invoke-DuckDB {

$StartTime_DuckDB = (Get-Date)

# Data Import
Write-Output "[Info]  Importing Data into DuckDB ..."
New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\DuckDB\Database" -ItemType Directory -Force | Out-Null
$script:Database = "$OUTPUT_FOLDER\UnifiedAuditLog\DuckDB\Database\UnifiedAuditLog.duckdb"
& $DuckDB $Database -c "CREATE OR REPLACE TABLE UAL AS SELECT * FROM read_json('$LogFile', ignore_errors=true), ORDER BY createdDateTime DESC;"

# Time Frame
$StartTime = & $DuckDB $Database -noheader -csv -c "SELECT MIN(createdDateTime) FROM 'UAL';"
$EndTime = & $DuckDB $Database -noheader -csv -c "SELECT MAX(createdDateTime) FROM 'UAL';"
Write-Output "[Info]  Log data from $StartTime UTC until $EndTime UTC"

# Import Blacklists from GitHub
Write-Output "[Info]  Importing Blacklists from GitHub Repository ..."
& $DuckDB $Database -c "CREATE TABLE 'ASN-Blacklist' AS SELECT * FROM read_csv_auto('https://raw.githubusercontent.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/refs/heads/main/Blacklists/ASN-Blacklist.csv');"
& $DuckDB $Database -c "CREATE TABLE 'Application-Blacklist' AS SELECT * FROM read_csv_auto('https://raw.githubusercontent.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/refs/heads/main/Blacklists/Application-Blacklist.csv');"
& $DuckDB $Database -c "CREATE TABLE 'Country-Blacklist' AS SELECT * FROM read_csv_auto('https://raw.githubusercontent.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/refs/heads/main/Blacklists/Country-Blacklist.csv');"
& $DuckDB $Database -c "CREATE TABLE 'MoveToFolder-Blacklist' AS SELECT * FROM read_csv_auto('https://raw.githubusercontent.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/refs/heads/main/Blacklists/MoveToFolder-Blacklist.csv');"
& $DuckDB $Database -c "CREATE TABLE 'Operation-Blacklist' AS SELECT * FROM read_csv_auto('https://raw.githubusercontent.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/refs/heads/main/Blacklists/Operation-Blacklist.csv');"
& $DuckDB $Database -c "CREATE TABLE 'UserAgent-Blacklist' AS SELECT * FROM read_csv_auto('https://raw.githubusercontent.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/refs/heads/main/Blacklists/UserAgent-Blacklist.csv');"

# Import 'MicrosoftApps.csv' from GitHub
# https://github.com/merill/microsoft-info
& $DuckDB $Database -c "CREATE OR REPLACE TABLE 'MicrosoftApps' AS SELECT * FROM read_csv_auto('https://raw.githubusercontent.com/merill/microsoft-info/refs/heads/main/_info/MicrosoftApps.csv');"

# Import 'RecordType.csv' from GitHub
& $DuckDB $Database -c "CREATE OR REPLACE TABLE 'RecordType' AS SELECT * FROM read_csv_auto('https://raw.githubusercontent.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/refs/heads/main/Config/RecordType.csv');"

# Import 'Status.csv' from GitHub
& $DuckDB $Database -c "CREATE OR REPLACE TABLE 'Status' AS SELECT * FROM read_csv_auto('https://raw.githubusercontent.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/refs/heads/main/Config/Status.csv');"

# Import 'TrustType.csv' from GitHub
& $DuckDB $Database -c "CREATE OR REPLACE TABLE 'TrustType' AS SELECT * FROM read_csv_auto('https://raw.githubusercontent.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/refs/heads/main/Config/TrustType.csv');"

# Download IPinfo Lite Parquet Database
$ParquetDatabase = "$SCRIPT_DIR\Tools\IPinfo\ipinfo_lite.parquet"
if (Test-Path "$ParquetDatabase")
{
    # Update Parquet Database
    if (Test-Path "$ParquetDatabase" -OlderThan (Get-Date).AddHours(-24) )
    {
        Write-Output "[Info]  Updating IPinfo Lite Database ..."
        Remove-Item "$ParquetDatabase" -Force
        & $curl --silent -L "https://ipinfo.io/data/ipinfo_lite.parquet?token=$Token" --output "$ParquetDatabase"

        # File Size (ipinfo_lite.parquet)
        if (Test-Path "$ParquetDatabase")
        {
            $Size = Get-FileSize((Get-Item "$ParquetDatabase").Length)
            Write-Output "[Info]  File Size (ipinfo_lite.parquet): $Size"
        }
    }
    else
    {
        Write-Output "[Info]  Your existing IPinfo Lite Database is NOT older than 24 hours."
    }
}
else
{
    # Download Parquet Database
    if (Test-Path "$($curl)")
    {
        Write-Output "[Info]  Downloading IPinfo Lite Database ..."
        & $curl --silent -L "https://ipinfo.io/data/ipinfo_lite.parquet?token=$Token" --output "$ParquetDatabase"

        # File Size (ipinfo_lite.parquet)
        if (Test-Path "$ParquetDatabase")
        {
            $Size = Get-FileSize((Get-Item "$ParquetDatabase").Length)
            Write-Output "[Info]  File Size (ipinfo_lite.parquet): $Size"
        }
    }
}

# Import IPinfo Lite Parquet Database
if (Test-Path "$ParquetDatabase")
{
    Write-Output "[Info]  Importing IPinfo Lite Database ..."
    & $DuckDB $Database -c "CREATE OR REPLACE TABLE 'IPinfo_Lite' AS SELECT network::INET AS cidr, country_code, country, asn, as_name FROM read_parquet('$ParquetDatabase');"
}

# Hunt
if (Test-Path "$SCRIPT_DIR\Queries\Hunt.sql")
{
    Write-Output "[Info]  Creating Hunt View ..."
    $ResultSet = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Hunt.sql"
    $ResultSet | Out-File -FilePath "$OUTPUT_FOLDER\UnifiedAuditLog\CSV\Hunt.csv" -Encoding UTF8
    $script:Hunt = $ResultSet | ConvertFrom-Csv | Select-Object * -ExcludeProperty "DecimalValue"
    $Hunt | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\XLSX\Hunt.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezePane 2,7 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Hunt" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:AG1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-G, I-O and S-AG
    $WorkSheet.Cells["A:G"].Style.HorizontalAlignment="Center"
    $WorkSheet.Cells["I:O"].Style.HorizontalAlignment="Center"
    $WorkSheet.Cells["S:AG"].Style.HorizontalAlignment="Center"

    # Iterating over the Operation-Blacklist HashTable
    foreach ($Operation in $OperationBlacklist_HashTable.Keys) 
    {
        $Severity = $OperationBlacklist_HashTable["$Operation"]
        $ConditionValue = 'EXACT("{0}",$F1)' -f $Operation
        Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
    }

    # Iterating over the Application-Blacklist HashTable - ObjectId
    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
    {
        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$H1)))' -f $AppId
        Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
    }

    # Iterating over the Application-Blacklist HashTable - AppId
    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
    {
        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$I1)))' -f $AppId
        Add-ConditionalFormatting -Address $WorkSheet.Cells["I:J"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
    }

    # Iterating over the ASN-Blacklist HashTable
    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("AS{0}",$N1)))' -f $ASN
        Add-ConditionalFormatting -Address $WorkSheet.Cells["N:O"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red

        $ConditionValue = '=AND(NOT(ISERROR(FIND("AS{0}",$N1))),$V1<>"")' -f $ASN
        Add-ConditionalFormatting -Address $WorkSheet.Cells["V:V"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # Colorize also the corresponding SessionId
    }

    # Iterating over the Country-Blacklist HashTable
    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$M1)))' -f $Country
        Add-ConditionalFormatting -Address $WorkSheet.Cells["L:M"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    # ConditionalFormatting - ClientInfoString
    $Cells = "Q:Q"
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=WebServices;eM Client/",$Q1)))' -BackgroundColor Red # eM Client (Traitorware)
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=WebServices;eMClient/",$Q1)))' -BackgroundColor Red # eM Client (Traitorware)

    # ConditionalFormatting - ActorInfoString
    $Cells = "R:R"
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=WebServices;eM Client/",$R1)))' -BackgroundColor Red # eM Client (Traitorware)
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=WebServices;eMClient/",$R1)))' -BackgroundColor Red # eM Client (Traitorware)

    # Iterating over the UserAgent-Blacklist HashTable
    foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
    {
        $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$P1)))' -f $UserAgent
        Add-ConditionalFormatting -Address $WorkSheet.Cells["P:P"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
    }

    # ConditionalFormatting - BrowserType
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AA:AA"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Other",$AA1)))' -BackgroundColor Red

    }
}

# Create 'Hunt' Table
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLog\CSV\Hunt.csv")
{
    & $DuckDB $Database -c "CREATE OR REPLACE TABLE 'Hunt' AS SELECT * FROM read_csv('$OUTPUT_FOLDER\UnifiedAuditLog\CSV\Hunt.csv', nullstr=' ');"
}

# UserLoggedIn (Interactive Sign-Ins)
if (Test-Path "$SCRIPT_DIR\Queries\UserLoggedIn.sql")
{
    Write-Output "[Info]  Creating UserLoggedIn View ..."
    $UserLoggedIn = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\UserLoggedIn.sql"
    $UserLoggedIn | Out-File -FilePath "$OUTPUT_FOLDER\UnifiedAuditLog\CSV\UserLoggedIn.csv" -Encoding UTF8
    $UserLoggedIn | ConvertFrom-Csv | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\XLSX\UserLoggedIn.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserLoggedIn" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:AF1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-AF
    $WorkSheet.Cells["A:AF"].Style.HorizontalAlignment="Center"

    # Iterating over the Application-Blacklist HashTable - ObjectId
    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
    {
        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$G1)))' -f $AppId
        Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
    }

    # Iterating over the Application-Blacklist HashTable - AppId
    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
    {
        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$H1)))' -f $AppId
        Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
    }

    # Iterating over the ASN-Blacklist HashTable
    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("AS{0}",$M1)))' -f $ASN
        Add-ConditionalFormatting -Address $WorkSheet.Cells["M:N"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red

        $ConditionValue = '=AND(NOT(ISERROR(FIND("AS{0}",$M1))),$S1<>"")' -f $ASN
        Add-ConditionalFormatting -Address $WorkSheet.Cells["S:S"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # Colorize also the corresponding SessionId
    }

    # Iterating over the Country-Blacklist HashTable
    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$L1)))' -f $Country
        Add-ConditionalFormatting -Address $WorkSheet.Cells["K:L"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    # ConditionalFormatting - ObjectId
    $Cells = "G:G"
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("4765445b-32c6-49b0-83e6-1d93765276ca",$G1)))' -BackgroundColor Yellow # OfficeHome (AiTM)
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("00000002-0000-0ff1-ce00-000000000000",$G1)))' -BackgroundColor Yellow # Office 365 Exchange Online (AiTM)
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("72782ba9-4490-4f03-8d82-562370ea3566",$G1)))' -BackgroundColor Yellow # Office 365 (AiTM)

    # Iterating over the UserAgent-Blacklist HashTable
    foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
    {
        $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$O1)))' -f $UserAgent
        Add-ConditionalFormatting -Address $WorkSheet.Cells["O:O"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
    }

    # ConditionalFormatting - RequestType
    Add-ConditionalFormatting -Address $WorkSheet.Cells["P:P"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Consent:Set",$P1)))' -BackgroundColor Yellow # User Application Consent (Consent Permissions Grant)

    # ConditionalFormatting - BrowserType
    Add-ConditionalFormatting -Address $WorkSheet.Cells["Z:Z"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Other",$Z1)))' -BackgroundColor Red

    }
}

# UserLoginFailed (Interactive Sign-Ins)
if (Test-Path "$SCRIPT_DIR\Queries\UserLoginFailed.sql")
{
    Write-Output "[Info]  Creating UserLoginFailed View ..."
    $UserLoginFailed = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\UserLoginFailed.sql"
    $UserLoginFailed | Out-File -FilePath "$OUTPUT_FOLDER\UnifiedAuditLog\CSV\UserLoginFailed.csv" -Encoding UTF8
    $UserLoginFailed | ConvertFrom-Csv | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\XLSX\UserLoginFailed.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserLoginFailed" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:AF1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-AF
    $WorkSheet.Cells["A:AF"].Style.HorizontalAlignment="Center"

    # Iterating over the Application-Blacklist HashTable - ObjectId
    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
    {
        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$G1)))' -f $AppId
        Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
    }

    # Iterating over the Application-Blacklist HashTable - AppId
    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
    {
        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$H1)))' -f $AppId
        Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
    }

    # Iterating over the ASN-Blacklist HashTable
    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("AS{0}",$M1)))' -f $ASN
        Add-ConditionalFormatting -Address $WorkSheet.Cells["M:N"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red

        $ConditionValue = '=AND(NOT(ISERROR(FIND("AS{0}",$M1))),$S1<>"")' -f $ASN
        Add-ConditionalFormatting -Address $WorkSheet.Cells["S:S"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # Colorize also the corresponding SessionId
    }

    # Iterating over the Country-Blacklist HashTable
    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$L1)))' -f $Country
        Add-ConditionalFormatting -Address $WorkSheet.Cells["K:L"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    # ConditionalFormatting - ObjectId
    $Cells = "G:G"
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("4765445b-32c6-49b0-83e6-1d93765276ca",$G1)))' -BackgroundColor Yellow # OfficeHome (AiTM)
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("00000002-0000-0ff1-ce00-000000000000",$G1)))' -BackgroundColor Yellow # Office 365 Exchange Online (AiTM)
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("72782ba9-4490-4f03-8d82-562370ea3566",$G1)))' -BackgroundColor Yellow # Office 365 (AiTM)

    # Iterating over the UserAgent-Blacklist HashTable
    foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
    {
        $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$O1)))' -f $UserAgent
        Add-ConditionalFormatting -Address $WorkSheet.Cells["O:O"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
    }

    # ConditionalFormatting - RequestType
    Add-ConditionalFormatting -Address $WorkSheet.Cells["P:P"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Consent:Set",$P1)))' -BackgroundColor Yellow # User Application Consent (Consent Permissions Grant)

    # ConditionalFormatting - BrowserType
    Add-ConditionalFormatting -Address $WorkSheet.Cells["Z:Z"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Other",$Z1)))' -BackgroundColor Red

    }
}

# LETHAL-0xx: 10+ UserLoginFailed operations per user on a single day
$Import = $UserLoginFailed | ConvertFrom-Csv
$Count = ($Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 10 | Measure-Object).Count
if ($Count -ge 1)
{
    Write-Host "[Alert] Suspicious Operation(s) detected: 10+ UserLoginFailed operations per user on a single day ($Count)" -ForegroundColor Yellow
}

$EndTime_DuckDB = (Get-Date)
$Time_DuckDB = ($EndTime_DuckDB-$StartTime_DuckDB)
('DuckDB Ingestion duration:             {0} h {1} min {2} sec' -f $Time_DuckDB.Hours, $Time_DuckDB.Minutes, $Time_DuckDB.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#############################################################################################################################################################################################
#############################################################################################################################################################################################

Function Invoke-BlacklistDetections {

# Blacklists
$StartTime_Blacklists = (Get-Date)

# Application Blacklist - ObjectId
foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
{
    $Filter = $Hunt | Where-Object { $_.ObjectId -eq "$AppId" }
    $Count = ($Filter | Measure-Object).Count
    if ($Count -gt 0)
    {
        $AppDisplayName = $ApplicationBlacklist_HashTable["$AppId"][0]
        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
        Write-Host "[Alert] Suspicious OAuth Application detected (ObjectId): $AppDisplayName ($Count)" -ForegroundColor $Severity
    }
}

# Application Blacklist - AppId
foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
{
    $Filter = $Hunt | Where-Object { $_.AppId -eq "$AppId" }
    $Count = ($Filter | Measure-Object).Count
    if ($Count -gt 0)
    {
        $AppDisplayName = $ApplicationBlacklist_HashTable["$AppId"][0]
        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
        Write-Host "[Alert] Suspicious OAuth Application detected (AppId): $AppDisplayName ($Count)" -ForegroundColor $Severity
    }
}

# ASN-Blacklist
foreach ($ASN in $AsnBlacklist_HashTable.Keys)
{
    $Filter = $Hunt | Where-Object { $_.ASN -eq "AS$ASN" }
    $Count = ($Filter | Measure-Object).Count
    if ($Count -gt 0)
    {
        $OrgName = $AsnBlacklist_HashTable["$ASN"][0]
        Write-Host "[Alert] Suspicious ASN detected: AS$ASN - $OrgName ($Count)" -ForegroundColor Red
    }
}

# Country Blacklist
foreach ($CountryName in $CountryBlacklist_HashTable.Keys) 
{
    $Filter = $Hunt | Where-Object { $_.CountryName -eq "$CountryName" }
    $Count = ($Filter | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Country detected: $CountryName ($Count)" -ForegroundColor Red
    }
}

# User-Agent Blacklist
foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
{
    $Filter = $Hunt | Where-Object { $_.UserAgent -eq "$UserAgent" }
    $Count = ($Filter | Measure-Object).Count
    if ($Count -gt 0)
    {
        $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
        Write-Host "[Alert] Suspicious User-Agent detected: $UserAgent ($Count)" -ForegroundColor $Severity
    }
}


$EndTime_Blacklists = (Get-Date)
$Time_Blacklists = ($EndTime_Blacklists-$StartTime_Blacklists)
('Blacklist Detections duration:         {0} h {1} min {2} sec' -f $Time_Blacklists.Hours, $Time_Blacklists.Minutes, $Time_Blacklists.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#############################################################################################################################################################################################
#############################################################################################################################################################################################

Function Get-Stats {

$StartTime_Stats = (Get-Date)

# Stats
Write-Output "[Info]  Creating Stats and Line Charts ..."
New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\Stats" -ItemType Directory -Force | Out-Null

# ActorInfoString (Stats)
if (Test-Path "$SCRIPT_DIR\Queries\Stats\ActorInfoString.sql")
{
    $Stats = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Stats\ActorInfoString.sql"
    $Stats | ConvertFrom-Csv | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Stats\ActorInfoString.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ActorInfoString" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"

    # ConditionalFormatting - ActorInfoString
    $Cells = "A:C"
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=WebServices;eM Client/",$A1)))' -BackgroundColor Red # eM Client (Traitorware)
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=WebServices;eMClient/",$A1)))' -BackgroundColor Red # eM Client (Traitorware)

    }
}

# AppId / AppDisplayName (Stats)
if (Test-Path "$SCRIPT_DIR\Queries\Stats\AppId-AppDisplayName.sql")
{
    $Stats = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Stats\AppId-AppDisplayName.sql"
    $Stats | ConvertFrom-Csv | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Stats\AppId-AppDisplayName.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AppId" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of column A-D
    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment = "Center"

    # Iterating over the Application-Blacklist HashTable
    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys)
    {
        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$A1)))' -f $AppId
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity   
    }

    # ConditionalFormatting - AppDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Third-Party Application",$B1)))' -BackgroundColor Yellow

    }
}

# ASN (Stats)
if (Test-Path "$SCRIPT_DIR\Queries\Stats\ASN.sql")
{
    $Stats = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Stats\ASN.sql"
    $Stats | ConvertFrom-Csv | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Stats\ASN.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ASN" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of column A-D
    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment = "Center"

    # Iterating over the ASN-Blacklist HashTable
    foreach ($ASN in $AsnBlacklist_HashTable.Keys) {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$A1)))' -f $ASN
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    # Count
    [int]$All = & $DuckDB $Database -noheader -csv -c "SELECT COUNT(ASN) FROM 'Hunt';"
    $Total = '{0:N0}' -f $All
    [int]$Unique = & $DuckDB $Database -noheader -csv -c "SELECT COUNT(DISTINCT ASN) FROM 'Hunt';"
    $ASN = '{0:N0}' -f $Unique
    Write-Output "[Info]  $ASN ASN found ($Total)"

    }
}

# ClientInfoString (Stats)
if (Test-Path "$SCRIPT_DIR\Queries\Stats\ClientInfoString.sql")
{
    $Stats = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Stats\ClientInfoString.sql"
    $Stats | ConvertFrom-Csv | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Stats\ClientInfoString.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ClientInfoString" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"

    # ConditionalFormatting - ClientInfoString
    $Cells = "A:C"
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=WebServices;eM Client/",$A1)))' -BackgroundColor Red # eM Client (Traitorware)
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=WebServices;eMClient/",$A1)))' -BackgroundColor Red # eM Client (Traitorware)

    }
}

# CountryCode / CountryName (Stats)
if (Test-Path "$SCRIPT_DIR\Queries\Stats\CountryCode-CountryName.sql")
{
    $Stats = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Stats\CountryCode-CountryName.sql"
    $Stats | ConvertFrom-Csv | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Stats\CountryCode-CountryName.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Countries" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of column A-D
    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"

    # Iterating over the Country-Blacklist HashTable
    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$B1)))' -f $Country
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    }

    # Count
    [int]$All = & $DuckDB $Database -noheader -csv -c "SELECT COUNT(CountryCode) FROM 'Hunt';"
    $Total = '{0:N0}' -f $All
    [int]$Unique = & $DuckDB $Database -noheader -csv -c "SELECT COUNT(DISTINCT CountryCode) FROM 'Hunt';"
    $Countries = '{0:N0}' -f $Unique
    Write-Output "[Info]  $Countries Countries found ($Total)"
}

# DeviceProperties (Stats)
if (Test-Path "$SCRIPT_DIR\Queries\Stats\DeviceProperties.sql")
{
    $Stats = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Stats\DeviceProperties.sql"
    $Objects = $Stats | ConvertFrom-Csv
    $Count = ($Objects | Measure-Object).Count
    if ($Count -ge "1")
    {
        $Objects | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Stats\DeviceProperties.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DeviceProperties" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of column B-D
        $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
        }
    }

    # Count
    [int]$All = & $DuckDB $Database -noheader -csv -c "SELECT COUNT(DeviceId) FROM 'Hunt';"
    $Total = '{0:N0}' -f $All
    [int]$Unique = & $DuckDB $Database -noheader -csv -c "SELECT COUNT(DISTINCT DeviceId) FROM 'Hunt';"
    $Devices = '{0:N0}' -f $Unique
    Write-Output "[Info]  $Devices Device Identities found ($Total)"
}

# IPAddress / CountryName (Stats)
if (Test-Path "$SCRIPT_DIR\Queries\Stats\IPAddress-CountryName.sql")
{
    $Stats = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Stats\IPAddress-CountryName.sql"
    $Stats | ConvertFrom-Csv | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Stats\IPAddress-CountryName.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "IPAddress" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of column A-G
    $WorkSheet.Cells["A:"].Style.HorizontalAlignment="Center"

    # Iterating over the ASN-Blacklist HashTable
    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$D1)))' -f $ASN
        Add-ConditionalFormatting -Address $WorkSheet.Cells["D:E"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    # Iterating over the Country-Blacklist HashTable
    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$C1)))' -f $Country
        Add-ConditionalFormatting -Address $WorkSheet.Cells["B:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    # Count
    [int]$All = & $DuckDB $Database -noheader -csv -c "SELECT COUNT(IPAddress) FROM 'Hunt';"
    $Total = '{0:N0}' -f $All
    [int]$Unique = & $DuckDB $Database -noheader -csv -c "SELECT COUNT(DISTINCT IPAddress) FROM 'Hunt';"
    $IP = '{0:N0}' -f $Unique
    Write-Output "[Info]  $IP IP addresses found ($Total)"

    }
}

# Operation
if (Test-Path "$SCRIPT_DIR\Queries\Stats\Operation.sql")
{
    $Stats = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Stats\Operation.sql"
    $Stats | ConvertFrom-Csv | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Stats\Operation.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Operations" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"

    # Iterating over the Operation-Blacklist HashTable
    foreach ($Operation in $OperationBlacklist_HashTable.Keys) 
    {
        $Severity = $OperationBlacklist_HashTable["$Operation"]
        $ConditionValue = 'EXACT("{0}",$A1)' -f $Operation
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
    }

    }
}

# RecordType (Stats)
if (Test-Path "$SCRIPT_DIR\Queries\Stats\RecordType.sql")
{
    $Stats = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Stats\RecordType.sql"
    $Stats | ConvertFrom-Csv | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Stats\RecordType.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RecordType" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }

    # Count
    $Operations = & $DuckDB $Database -noheader -csv -c "SELECT COUNT(DISTINCT Operation) FROM 'Hunt';"
    $RecordTypes = & $DuckDB $Database -noheader -csv -c "SELECT COUNT(DISTINCT RecordType) FROM 'Hunt';"
    Write-Output "[Info]  $RecordTypes RecordTypes and $Operations Operations found"
}

# RecordType / RecordId (Stats)
if (Test-Path "$SCRIPT_DIR\Queries\Stats\RecordType-RecordId.sql")
{
    $Stats = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Stats\RecordType-RecordId.sql"
    $Stats | ConvertFrom-Csv | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Stats\RecordType-RecordId.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RecordType" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of column A and C-D
    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
    $WorkSheet.Cells["C:D"].Style.HorizontalAlignment="Center"
    }
}

# RecordType / RecordId / Workload (Stats)
if (Test-Path "$SCRIPT_DIR\Queries\Stats\RecordType-RecordId-Workload.sql")
{
    $Stats = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Stats\RecordType-RecordId-Workload.sql"
    $Stats | ConvertFrom-Csv | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Stats\RecordType-RecordId-Workload.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RecordType" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of column A and C-E
    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
    $WorkSheet.Cells["C:E"].Style.HorizontalAlignment="Center"
    }
}

# RequestType (Stats)
if (Test-Path "$SCRIPT_DIR\Queries\Stats\RequestType.sql")
{
    $Stats = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Stats\RequestType.sql"
    $Stats | ConvertFrom-Csv | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Stats\RequestType.xlsx" -NoNumberConversion * -NoHyperLinkConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RequestType" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    # ConditionalFormatting - RequestType
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Consent:Set",$A1)))' -BackgroundColor Yellow # User Application Consent (Consent Permissions Grant)
    }
}

# UserAgent (Stats)
if (Test-Path "$SCRIPT_DIR\Queries\Stats\UserAgent.sql")
{
    $Stats = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Stats\UserAgent.sql"
    $Stats | ConvertFrom-Csv | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Stats\UserAgent.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserAgent" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"

    # Iterating over the UserAgent-Blacklist HashTable
    foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
    {
        $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$A1)))' -f $UserAgent
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
    }

    }
}

# UserAuthenticationMethod (Stats)
if (Test-Path "$SCRIPT_DIR\Queries\Stats\UserAuthenticationMethod.sql")
{
    $Stats = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Stats\UserAuthenticationMethod.sql"
    $Objects = $Stats | ConvertFrom-Csv
    $Count = ($Objects | Measure-Object).Count
    if ($Count -ge "1")
    {   
        $Objects | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Stats\UserAuthenticationMethod.xlsx" -NoNumberConversion * -NoHyperLinkConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserAuthenticationMethod" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-D
        $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
        }
    }
}

# Sessions Duration
if (Test-Path "$SCRIPT_DIR\Queries\Sessions\Sessions-Duration.sql")
{
    $Stats = & $DuckDB $Database -csv -f "$SCRIPT_DIR\Queries\Sessions\Sessions-Duration.sql"
    $Stats | ConvertFrom-Csv | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\XLSX\Sessions-Duration.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Sessions" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-F
    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
    }
}

# Suspicious Sessions
if (Test-Path "$SCRIPT_DIR\Queries\Sessions\Suspicious-Sessions.sql")
{
    $Sessions = & $DuckDB $Database -csv -f "$SCRIPT_DIR\Queries\Sessions\Suspicious-Sessions.sql"
    $Sessions | Out-File -FilePath "$OUTPUT_FOLDER\UnifiedAuditLog\CSV\Suspicious-Sessions.csv" -Encoding UTF8
    #$Sessions | ConvertFrom-Csv | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\XLSX\Suspicious-Sessions.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Suspicious Sessions" -CellStyleSB {
    $Import = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLog\CSV\Suspicious-Sessions.csv" -Delimiter "," -Encoding UTF8 | Select-Object SessionId, @{Name='IPAddress'; Expression={ $_.IPAddress -as [Int] }}, @{Name='Country'; Expression={ $_.Country -as [Int] }}, @{Name='ASN'; Expression={ $_.ASN -as [Int] }}, @{Name='OS'; Expression={ $_.OS -as [Int] }}, @{Name='BrowserType'; Expression={ $_.BrowserType -as [Int] }},@{Name='UserAgent'; Expression={ $_.UserAgent -as [Int] }}, @{Name='ClientInfoString'; Expression={ $_.ClientInfoString -as [Int] }}, @{Name='Devices'; Expression={ $_.Devices -as [Int] }}, @{Name='UserLoggedIn'; Expression={ $_.UserLoggedIn -as [Int] }}, @{Name='UniqueTokenId'; Expression={ $_.UniqueTokenId -as [Int] }}
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\XLSX\Suspicious-Sessions.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Suspicious Sessions" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-K
    $WorkSheet.Cells["A:K"].Style.HorizontalAlignment="Center"
    # ConditionalFormatting - Different IP addresses (and User-Agents) or missing Device Properties indicate Session Cookie Theft
    $LastRow = $WorkSheet.Dimension.End.Row
    Add-ConditionalFormatting -Address $WorkSheet.Cells["B2:B$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$B2>=2' -BackgroundColor Red # IPAddress
    Add-ConditionalFormatting -Address $WorkSheet.Cells["C2:C$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$C2>=2' -BackgroundColor Red # Country
    Add-ConditionalFormatting -Address $WorkSheet.Cells["D2:D$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$D2>=2' -BackgroundColor Red # ASN
    Add-ConditionalFormatting -Address $WorkSheet.Cells["E2:E$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$E2>=2' -BackgroundColor Red # OS
    Add-ConditionalFormatting -Address $WorkSheet.Cells["F2:F$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$F2>=2' -BackgroundColor Red # BrowserType
    Add-ConditionalFormatting -Address $WorkSheet.Cells["G2:G$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$G2>=2' -BackgroundColor Red # UserAgent
    Add-ConditionalFormatting -Address $WorkSheet.Cells["H2:H$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$H2>=2' -BackgroundColor Red # ClientInfoString
    Add-ConditionalFormatting -Address $WorkSheet.Cells["I2:I$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$I2=0' -BackgroundColor Red # Devices
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A2:A$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=AND($B2>=2,$D2>=2)' -BackgroundColor Red # IPAddress + ASN = Suspicious SessionId
    }
}

# Potential Adversary-in-The-Middle Phishing Attack [T1557]
$Total = & $DuckDB $Database -noheader -csv -c "SELECT COUNT(DISTINCT SessionId) FROM 'Hunt';"
$OfficeHome = & $DuckDB $Database -noheader -csv -c "SELECT COUNT(DISTINCT SessionId) FROM 'Hunt' WHERE ObjectId = '4765445b-32c6-49b0-83e6-1d93765276ca';"
$Office365 = & $DuckDB $Database -noheader -csv -c "SELECT COUNT(DISTINCT SessionId) FROM 'Hunt' WHERE ObjectId = '72782ba9-4490-4f03-8d82-562370ea3566';"
$Office365ExchangeOnline = & $DuckDB $Database -noheader -csv -c "SELECT COUNT(DISTINCT SessionId) FROM 'Hunt' WHERE ObjectId = '00000002-0000-0ff1-ce00-000000000000';"
$SuspiciousSessions = ($Import | Where-Object { [int]$_.IPAddress -ge "2" } | Where-Object { [int]$_.ASN -ge "2" } | Measure-Object).Count
if ($SuspiciousSessions -gt 0)
{
    Write-Host "[Info]  $SuspiciousSessions Potential AitM Attack(s) found (Total: $Total / OfficeHome: $OfficeHome / Office 365: $Office365 / Office 365 Exchange Online: $Office365ExchangeOnline)" -ForegroundColor Red
}
else
{
    Write-Host "[Info]  $Total Session(s) found (OfficeHome: $OfficeHome / Office 365: $Office365 / Office 365 Exchange Online: $Office365ExchangeOnline)"
}

# Adversary-in-The-Middle (AiTM) Credential Phishing Attack [T1557]

# Step 1: User enters credentials on the phishing page.
# Step 2: AiTM server relays credentials to the Microsoft server and authenticates.
# Step 3: User is redirected to the Microsoft portal or a fake landing page.

# In the Unified Audit Logs (UAL), steps 2 and 3 are recorded as consecutive logins from different IPs which occur within about 30 seconds of each other—and often within only a couple of seconds. 
# The first login will be the AiTM server (step 2), with the second login being from the user’s legitimate IP address (step 3).

# Note: The adversary may occasionally require more time to copy the session token from the AiTM server to a different machine.

# LETHAL-001: Find-AiTMSuspiciousUserLogin
if (Test-Path "$SCRIPT_DIR\Queries\Find-AiTMSuspiciousUserLogin.sql")
{
    Write-Output "[Info]  Hunting for Adversary-in-The-Middle (AiTM) Phishing Attacks [T1557] ..."
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Find-AiTMSuspiciousUserLogin.sql"
    $Import = $Result | ConvertFrom-Csv
    $Count  = ($Import | Measure-Object).Count
    if ($Count -gt 0)
    {
        $Sessions = ($Import | Select-Object SessionId -Unique | Measure-Object).Count
        Write-Host "[Alert] $Count Suspicious Authentication Events found - $Sessions Potential Hijacked Session(s)" -ForegroundColor Red
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\XLSX\Find-AiTMSuspiciousUserLogin.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AiTMSuspiciousUserLogin" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:AF1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-AF
        $WorkSheet.Cells["A:AF"].Style.HorizontalAlignment="Center"

        # Iterating over the Application-Blacklist HashTable - ObjectId
        foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
        {
            $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$G1)))' -f $AppId
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
        }

        # Iterating over the Application-Blacklist HashTable - ApplicationId
        foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
        {
            $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$H1)))' -f $AppId
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
        }

        # Iterating over the ASN-Blacklist HashTable
        foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("AS{0}",$M1)))' -f $ASN
            Add-ConditionalFormatting -Address $WorkSheet.Cells["M:N"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red

            $ConditionValue = '=AND(NOT(ISERROR(FIND("AS{0}",$M1))),$S1<>"")' -f $ASN
            Add-ConditionalFormatting -Address $WorkSheet.Cells["S:S"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # Colorize also the corresponding SessionId
        }

        # Iterating over the Country-Blacklist HashTable
        foreach ($Country in $CountryBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$L1)))' -f $Country
            Add-ConditionalFormatting -Address $WorkSheet.Cells["K:L"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # ConditionalFormatting - ObjectId
        $Cells = "G:G"
        Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("4765445b-32c6-49b0-83e6-1d93765276ca",$G1)))' -BackgroundColor Yellow # OfficeHome (AiTM)
        Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("00000002-0000-0ff1-ce00-000000000000",$G1)))' -BackgroundColor Yellow # Office 365 Exchange Online (AiTM)
        Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("72782ba9-4490-4f03-8d82-562370ea3566",$G1)))' -BackgroundColor Yellow # Office 365 (AiTM)

        # Iterating over the UserAgent-Blacklist HashTable
        foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
        {
            $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$O1)))' -f $UserAgent
            Add-ConditionalFormatting -Address $WorkSheet.Cells["O:O"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
        }

        }
    }
}

# ClientInfoString

# LETHAL-002: eM Client
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLog\CSV\Hunt.csv")
{
    if ((Get-Content "$OUTPUT_FOLDER\UnifiedAuditLog\CSV\Hunt.csv" -TotalCount 2).Count -gt 1)
    {
        $Import = $Hunt | Where-Object { $_.ClientInfoString -match "Client=WebServices;eM ?Client" } | Sort-Object { $_.CreationTime -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious ClientInfoString indicates Mailbox Synchronisation: Client=WebServices;eM Client ($Count)" -ForegroundColor Red
        }
    }
}

# Line Charts
New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\Stats\LineCharts" -ItemType Directory -Force | Out-Null

# Operations (Line Chart)
if (Test-Path "$SCRIPT_DIR\Queries\Stats\LineCharts\Operations.sql")
{
    $Result = & $DuckDB $Database -csv -f "$SCRIPT_DIR\Queries\Stats\LineCharts\Operations.sql"
    $Import = $Result | ConvertFrom-Csv
    $Count  = ($Import | Measure-Object).Count
    if ($Count -gt 0)
    {
        $ChartDefinition = New-ExcelChartDefinition -XRange CreationTime -YRange Count -Title "Operations" -ChartType Line -NoLegend -Width 1200
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Stats\LineCharts\Operations.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
    }
}

# UserLoggedIn (Line Chart)
if (Test-Path "$SCRIPT_DIR\Queries\Stats\LineCharts\UserLoggedIn.sql")
{
    $Result = & $DuckDB $Database -csv -f "$SCRIPT_DIR\Queries\Stats\LineCharts\UserLoggedIn.sql"
    $Import = $Result | ConvertFrom-Csv
    $Count  = ($Import | Measure-Object).Count
    if ($Count -gt 0)
    {
        $ChartDefinition = New-ExcelChartDefinition -XRange CreationTime -YRange Count -Title "UserLoggedIn" -ChartType Line -NoLegend -Width 1200
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Stats\LineCharts\UserLoggedIn.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
    }
}

# UserLoginFailed (Line Chart)
if (Test-Path "$SCRIPT_DIR\Queries\Stats\LineCharts\UserLoginFailed.sql")
{
    $Result = & $DuckDB $Database -csv -f "$SCRIPT_DIR\Queries\Stats\LineCharts\UserLoginFailed.sql"
    $Import = $Result | ConvertFrom-Csv
    $Count  = ($Import | Measure-Object).Count
    if ($Count -gt 0)
    {
        $ChartDefinition = New-ExcelChartDefinition -XRange CreationTime -YRange Count -Title "UserLoginFailed" -ChartType Line -NoLegend -Width 1200
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Stats\LineCharts\UserLoginFailed.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
    }
}

$EndTime_Stats = (Get-Date)
$Time_Stats = ($EndTime_Stats-$StartTime_Stats)
('Stats Creation duration:               {0} h {1} min {2} sec' -f $Time_Stats.Hours, $Time_Stats.Minutes, $Time_Stats.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#############################################################################################################################################################################################
#############################################################################################################################################################################################

Function Invoke-GeoIPMapping {

$StartTime_GeoIPMapping = (Get-Date)

# GeoIP Mapping - Generate a report URL for mapped IP locations
# Note: The map tool is a fully unauthenticated tool. This means regardless of your subscription plan there's no token usage. So unfortunately the rate limit is not something what can be bypassed. You can use the IP Map tool up to 5 times per day.
# https://ipinfo.io/tools/map
if (Test-Path "$($IPinfo)")
{
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\IPinfo" -ItemType Directory -Force | Out-Null

    # All-Operations.txt (incl. Brute Force)
    $AllOperations = & $DuckDB $Database -noheader -csv -c "SELECT DISTINCT IPAddress FROM 'Hunt' WHERE IPAddress IS NOT NULL;"
    $AllOperations | Out-File "$OUTPUT_FOLDER\UnifiedAuditLog\IPinfo\All-Operations.txt" -Encoding UTF8
    Get-Content "$OUTPUT_FOLDER\UnifiedAuditLog\IPinfo\All-Operations.txt" | & $IPinfo map 2>&1 | Out-File "$OUTPUT_FOLDER\UnifiedAuditLog\IPinfo\Map_All-Operations.txt"

    # Authenticated-Operations.txt
    $AuthenticatedOperations = & $DuckDB $Database -noheader -csv -c "SELECT DISTINCT IPAddress FROM 'Hunt' WHERE IPAddress IS NOT NULL AND Operation != 'UserLoginFailed';"
    $AuthenticatedOperations | Out-File "$OUTPUT_FOLDER\UnifiedAuditLog\IPinfo\Authenticated-Operations.txt" -Encoding UTF8
    Get-Content "$OUTPUT_FOLDER\UnifiedAuditLog\IPinfo\Authenticated-Operations.txt" | & $IPinfo map 2>&1 | Out-File "$OUTPUT_FOLDER\UnifiedAuditLog\IPinfo\Map_Authenticated-Operations.txt"

    # Summarize
    # https://ipinfo.io/summarize-ips

    # TXT --> Top Privacy Services
    Get-Content "$OUTPUT_FOLDER\UnifiedAuditLog\IPinfo\Authenticated-Operations.txt" | & $IPinfo summarize --token "$Token" 2>&1 | Out-File "$OUTPUT_FOLDER\UnifiedAuditLog\IPinfo\Summary.txt"

    # CSV
    Get-Content "$OUTPUT_FOLDER\UnifiedAuditLog\IPinfo\Authenticated-Operations.txt" | & $IPinfo --csv --token "$Token" 2>&1 | Out-File "$OUTPUT_FOLDER\UnifiedAuditLog\IPinfo\IPinfo.csv" -Encoding UTF8

    # Custom CSV (Free)
    if ($PrivacyDetection -eq "False")
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLog\IPinfo\IPinfo.csv")
        {
            if ((Get-Content "$OUTPUT_FOLDER\UnifiedAuditLog\IPinfo\IPinfo.csv" -TotalCount 2).Count -gt 1)
            {
                $IPinfoRecords = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLog\IPinfo\IPinfo.csv" -Delimiter "," -Encoding UTF8

                $Results = [Collections.Generic.List[PSObject]]::new()
                ForEach($IPinfoRecord in $IPinfoRecords)
                {
                    $Line = [PSCustomObject]@{
                        "IP"           = $IPinfoRecord.ip
                        "City"         = $IPinfoRecord.city
                        "Region"       = $IPinfoRecord.region
                        "Country"      = $IPinfoRecord.country
                        "Country Name" = $IPinfoRecord.country_name
                        "Continent"    = $IPinfoRecord.continent_name
                        "Location"     = $IPinfoRecord.loc
                        "ASN"          = $IPinfoRecord | Select-Object -ExpandProperty org | ForEach-Object{($_ -split "\s+")[0]}
                        "OrgName"      = $IPinfoRecord | Select-Object -ExpandProperty org | ForEach-Object {$_ -replace "^AS[0-9]+ "}
                        "Postal Code"  = $IPinfoRecord.postal
                        "Timezone"     = $IPinfoRecord.timezone
                    }

                    $Results.Add($Line)
                }

                $Results | Sort-Object {$_.IP -as [Version]} | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLog\IPinfo\IPinfo-Custom.csv" -NoTypeInformation -Encoding UTF8
            }
        }

        # Custom XLSX (Free)
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLog\IPinfo\IPinfo-Custom.csv")
        {
            if ((Get-Content "$OUTPUT_FOLDER\UnifiedAuditLog\IPinfo\IPinfo-Custom.csv" -TotalCount 2).Count -gt 1)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLog\IPinfo\IPinfo-Custom.csv" -Delimiter "," | Sort-Object {$_.IP -as [Version]}
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\IPinfo\IPinfo-Custom.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -PivotRows "Country Name" -PivotData @{"IP"="Count"} -WorkSheetname "IPinfo Lite" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
                # HorizontalAlignment "Center" of columns A-K
                $WorkSheet.Cells["A:K"].Style.HorizontalAlignment="Center"
                }
            }
        }
    }
}

$EndTime_GeoIPMapping = (Get-Date)
$Time_GeoIPMapping = ($EndTime_GeoIPMapping-$StartTime_GeoIPMapping)
('GeoIP Mapping duration:                {0} h {1} min {2} sec' -f $Time_GeoIPMapping.Hours, $Time_GeoIPMapping.Minutes, $Time_GeoIPMapping.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#############################################################################################################################################################################################
#############################################################################################################################################################################################

Function Invoke-SuspiciousOperations {

$StartTime_SuspiciousOperations = (Get-Date)

# Inbox Rules
# Inbox Rules let users automate actions on incoming emails when they match specific criteria, such as containing certain words in the subject line or coming from a particular sender. 
# These actions can include moving messages to designated folders, marking them as read, or forwarding them to external addresses. 

# LETHAL-003: New-InboxRule --> Create a new Inbox Rule in a mailbox
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\New-InboxRule.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\New-InboxRule.sql"
    $Data = $Result | ConvertFrom-Csv
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: New-InboxRule ($Count)" -ForegroundColor Red
        New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations" -ItemType Directory -Force | Out-Null

        # Inbox Rule 'Name' with only non-alphanumeric characters
        [array]$RegEx01 = $Data | Where-Object { $_.Name -match "^[^a-zA-Z\d\s:]" } | Select-Object -ExpandProperty Name
        $Count = ($RegEx01 | Measure-Object).Count
        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious Operation(s) detected: New-InboxRule + Inbox Rule Name w/ only non-alphanumeric characters ($Count)" -ForegroundColor Red
        }

        # Inbox Rule with a short 'Name' (5 or less characters)
        [array]$RegEx02 = $Data | Where-Object { $_.Name -match "^[a-zA-Z0-9]{1,5}$" } | Select-Object -ExpandProperty Name
        $Count = ($RegEx02 | Measure-Object).Count
        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious Operation(s) detected: New-InboxRule + Inbox Rule Name w/ 5 or less alphanumeric characters ($Count)" -ForegroundColor Red
        }
        
        $Data | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations\New-InboxRule.xlsx" -FreezePane 2,7 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "New-InboxRule" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:AI1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-AI
        $WorkSheet.Cells["A:AI"].Style.HorizontalAlignment="Center"
        
        # ConditionalFormatting - Operation
        Add-ConditionalFormatting -Address $WorkSheet.Cells["E:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("New-InboxRule",$F1)))' -BackgroundColor Red
        
        # Iterating over the ASN-Blacklist HashTable
        foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("AS{0}",$O1)))' -f $ASN
            Add-ConditionalFormatting -Address $WorkSheet.Cells["O:P"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # Iterating over the Country-Blacklist HashTable
        foreach ($Country in $CountryBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$N1)))' -f $Country
            Add-ConditionalFormatting -Address $WorkSheet.Cells["M:N"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }
        
        # ConditionalFormatting - Name

        # Inbox Rule 'Name' with only non-alphanumeric characters
        foreach ($Name in $RegEx01) 
        {
            $ConditionValue = 'EXACT("{0}",$Q1)' -f $Name
            Add-ConditionalFormatting -Address $WorkSheet.Cells["Q:Q"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # Inbox Rule with a short 'Name' (5 or less characters)
        foreach ($Name in $RegEx02) 
        {
            $ConditionValue = 'EXACT("{0}",$Q1)' -f $Name
            Add-ConditionalFormatting -Address $WorkSheet.Cells["Q:Q"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # ConditionalFormatting - MarkAsRead
        Add-ConditionalFormatting -Address $WorkSheet.Cells["S:S"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$S1)))' -BackgroundColor Red

        # ConditionalFormatting - DeleteMessage
        Add-ConditionalFormatting -Address $WorkSheet.Cells["T:T"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$T1)))' -BackgroundColor Red
            
        # Iterating over the MoveToFolder-Blacklist HashTable
        foreach ($MoveToFolder in $MoveToFolderBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$U1)))' -f $MoveToFolder
            Add-ConditionalFormatting -Address $WorkSheet.Cells["U:U"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # ConditionalFormatting - StopProcessingRules
        Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$X1)))' -BackgroundColor Red

        # ConditionalFormatting - ForwardAsAttachmentTo
        $LastRow = $WorkSheet.Dimension.End.Row
        Add-ConditionalFormatting -Address $WorkSheet.Cells["AC2:AC$LastRow"] -WorkSheet $WorkSheet -RuleType ContainsText -BackgroundColor Red

        # ConditionalFormatting - ForwardTo
        $LastRow = $WorkSheet.Dimension.End.Row
        Add-ConditionalFormatting -Address $WorkSheet.Cells["AD2:AD$LastRow"] -WorkSheet $WorkSheet -RuleType ContainsText -BackgroundColor Red

        # ConditionalFormatting - RedirectTo
        $LastRow = $WorkSheet.Dimension.End.Row
        Add-ConditionalFormatting -Address $WorkSheet.Cells["AE2:AE$LastRow"] -WorkSheet $WorkSheet -RuleType ContainsText -BackgroundColor Red

        }
    }
}

# LETHAL-004: Set-InboxRule --> Modify an existing Inbox Rule, often used for setting up Email Forwarding Rules
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\Set-InboxRule.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\Set-InboxRule.sql"
    $Data = $Result | ConvertFrom-Csv
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: Set-InboxRule ($Count)" -ForegroundColor Red
        New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations" -ItemType Directory -Force | Out-Null

        # Inbox Rule 'Name' with only non-alphanumeric characters
        [array]$RegEx01 = $Data | Where-Object { $_.Name -match "^[^a-zA-Z\d\s:]" } | Select-Object -ExpandProperty Name
        $Count = ($RegEx01 | Measure-Object).Count
        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious Operation(s) detected: Set-InboxRule + Inbox Rule Name w/ only non-alphanumeric characters ($Count)" -ForegroundColor Red
        }

        # Inbox Rule with a short 'Name' (5 or less characters)
        [array]$RegEx02 = $Data | Where-Object { $_.Name -match "^[a-zA-Z0-9]{1,5}$" } | Select-Object -ExpandProperty Name
        $Count = ($RegEx02 | Measure-Object).Count
        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious Operation(s) detected: Set-InboxRule + Inbox Rule Name w/ 5 or less alphanumeric characters ($Count)" -ForegroundColor Red
        }
        
        $Data | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations\Set-InboxRule.xlsx" -FreezePane 2,7 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Set-InboxRule" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:AI1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-AI
        $WorkSheet.Cells["A:AI"].Style.HorizontalAlignment="Center"
        
        # ConditionalFormatting - Operation
        Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("Set-InboxRule",$F1)))' -BackgroundColor Red
        
        # Iterating over the ASN-Blacklist HashTable
        foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("AS{0}",$O1)))' -f $ASN
            Add-ConditionalFormatting -Address $WorkSheet.Cells["O:P"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # Iterating over the Country-Blacklist HashTable
        foreach ($Country in $CountryBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$N1)))' -f $Country
            Add-ConditionalFormatting -Address $WorkSheet.Cells["M:N"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }
        
        # ConditionalFormatting - Name

        # Inbox Rule 'Name' with only non-alphanumeric characters
        foreach ($Name in $RegEx01) 
        {
            $ConditionValue = 'EXACT("{0}",$Q1)' -f $Name
            Add-ConditionalFormatting -Address $WorkSheet.Cells["Q:Q"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # Inbox Rule with a short 'Name' (5 or less characters)
        foreach ($Name in $RegEx02) 
        {
            $ConditionValue = 'EXACT("{0}",$Q1)' -f $Name
            Add-ConditionalFormatting -Address $WorkSheet.Cells["Q:Q"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # ConditionalFormatting - MarkAsRead
        Add-ConditionalFormatting -Address $WorkSheet.Cells["T:T"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$T1)))' -BackgroundColor Red

        # ConditionalFormatting - DeleteMessage
        Add-ConditionalFormatting -Address $WorkSheet.Cells["U:U"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$U1)))' -BackgroundColor Red
            
        # Iterating over the MoveToFolder-Blacklist HashTable
        foreach ($MoveToFolder in $MoveToFolderBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$V1)))' -f $MoveToFolder
            Add-ConditionalFormatting -Address $WorkSheet.Cells["V:V"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # ConditionalFormatting - StopProcessingRules
        Add-ConditionalFormatting -Address $WorkSheet.Cells["Y:Y"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$Y1)))' -BackgroundColor Red

        # ConditionalFormatting - ForwardAsAttachmentTo
        Add-ConditionalFormatting -Address $WorkSheet.Cells["AD:AD"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("@",$AD1)))' -BackgroundColor Red

        # ConditionalFormatting - ForwardTo
        Add-ConditionalFormatting -Address $WorkSheet.Cells["AE:AE"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("@",$AE1)))' -BackgroundColor Red

        # ConditionalFormatting - RedirectTo
        Add-ConditionalFormatting -Address $WorkSheet.Cells["AF:AF"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("@",$AF1)))' -BackgroundColor Red

        }
    }
}

# LETHAL-005: Remove-InboxRule --> Remove an existing Inbox Rule in a mailbox
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\Remove-InboxRule.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\Remove-InboxRule.sql"
    $Data = $Result | ConvertFrom-Csv
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: Remove-InboxRule ($Count)" -ForegroundColor Red
        New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations" -ItemType Directory -Force | Out-Null
        $Data | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations\Remove-InboxRule.xlsx" -FreezePane 2,7 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Remove-InboxRule" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:V1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-V
        $WorkSheet.Cells["A:V"].Style.HorizontalAlignment="Center"
        
        # ConditionalFormatting - Operation
        Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Remove-InboxRule",$F1)))' -BackgroundColor Red
    
        # Iterating over the ASN-Blacklist HashTable
        foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("AS{0}",$O1)))' -f $ASN
            Add-ConditionalFormatting -Address $WorkSheet.Cells["O:P"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # Iterating over the Country-Blacklist HashTable
        foreach ($Country in $CountryBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$N1)))' -f $Country
            Add-ConditionalFormatting -Address $WorkSheet.Cells["M:N"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        }
    }
}

# LETHAL-006: Enable-InboxRule --> Enable an existing Inbox Rule in a mailbox
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\Enable-InboxRule.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\Enable-InboxRule.sql"
    $Data = $Result | ConvertFrom-Csv
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: Enable-InboxRule ($Count)" -ForegroundColor Red
        New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations" -ItemType Directory -Force | Out-Null
        $Data | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations\Enable-InboxRule.xlsx" -FreezePane 2,7 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Enable-InboxRule" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:W1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-W
        $WorkSheet.Cells["A:W"].Style.HorizontalAlignment="Center"
        
        # ConditionalFormatting - Operation
        Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Enable-InboxRule",$F1)))' -BackgroundColor Red
    
        # Iterating over the ASN-Blacklist HashTable
        foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("AS{0}",$O1)))' -f $ASN
            Add-ConditionalFormatting -Address $WorkSheet.Cells["O:P"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # Iterating over the Country-Blacklist HashTable
        foreach ($Country in $CountryBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$N1)))' -f $Country
            Add-ConditionalFormatting -Address $WorkSheet.Cells["M:N"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        }
    }
}

# LETHAL-007: Disable-InboxRule --> Disable an existing Inbox Rule in a mailbox
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\Disable-InboxRule.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\Disable-InboxRule.sql"
    $Data = $Result | ConvertFrom-Csv
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: Disable-InboxRule ($Count)" -ForegroundColor Red
        New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations" -ItemType Directory -Force | Out-Null
        $Data | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations\Disable-InboxRule.xlsx" -FreezePane 2,7 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Disable-InboxRule" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:W1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-W
        $WorkSheet.Cells["A:W"].Style.HorizontalAlignment="Center"
        
        # ConditionalFormatting - Operation
        Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Disable-InboxRule",$F1)))' -BackgroundColor Red
    
        # Iterating over the ASN-Blacklist HashTable
        foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("AS{0}",$O1)))' -f $ASN
            Add-ConditionalFormatting -Address $WorkSheet.Cells["O:P"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # Iterating over the Country-Blacklist HashTable
        foreach ($Country in $CountryBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$N1)))' -f $Country
            Add-ConditionalFormatting -Address $WorkSheet.Cells["M:N"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        }
    }
}

# LETHAL-008: Email-Forwarding via New-InboxRule / Set-InboxRule
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\Email-Forwarding.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\Email-Forwarding.sql"
    $Data = $Result | ConvertFrom-Csv
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: Email-Forwarding via New-InboxRule / Set-InboxRule ($Count)" -ForegroundColor Red
        New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations" -ItemType Directory -Force | Out-Null

        # Inbox Rule 'Name' with only non-alphanumeric characters
        [array]$RegEx01 = $Data | Where-Object { $_.Name -match "^[^a-zA-Z\d\s:]" } | Select-Object -ExpandProperty Name
        $Count = ($RegEx01 | Measure-Object).Count
        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious Operation(s) detected: Email-Forwarding + Inbox Rule Name w/ only non-alphanumeric characters ($Count)" -ForegroundColor Red
        }

        # Inbox Rule with a short 'Name' (5 or less characters)
        [array]$RegEx02 = $Data | Where-Object { $_.Name -match "^[a-zA-Z0-9]{1,5}$" } | Select-Object -ExpandProperty Name
        $Count = ($RegEx02 | Measure-Object).Count
        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious Operation(s) detected: Email-Forwarding + Inbox Rule Name w/ 5 or less alphanumeric characters ($Count)" -ForegroundColor Red
        }
        
        $Data | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations\Email-Forwarding.xlsx" -FreezePane 2,7 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Email-Forwarding" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:AI1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-AI
        $WorkSheet.Cells["A:AI"].Style.HorizontalAlignment="Center"
        
        # ConditionalFormatting - Operation
        Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("New-InboxRule",$F1)))' -BackgroundColor Red
        Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("Set-InboxRule",$F1)))' -BackgroundColor Red
        
        # Iterating over the ASN-Blacklist HashTable
        foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("AS{0}",$O1)))' -f $ASN
            Add-ConditionalFormatting -Address $WorkSheet.Cells["O:P"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # Iterating over the Country-Blacklist HashTable
        foreach ($Country in $CountryBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$N1)))' -f $Country
            Add-ConditionalFormatting -Address $WorkSheet.Cells["M:N"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }
        
        # ConditionalFormatting - Name

        # Inbox Rule 'Name' with only non-alphanumeric characters
        foreach ($Name in $RegEx01) 
        {
            $ConditionValue = 'EXACT("{0}",$Q1)' -f $Name
            Add-ConditionalFormatting -Address $WorkSheet.Cells["Q:Q"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # Inbox Rule with a short 'Name' (5 or less characters)
        foreach ($Name in $RegEx02) 
        {
            $ConditionValue = 'EXACT("{0}",$Q1)' -f $Name
            Add-ConditionalFormatting -Address $WorkSheet.Cells["Q:Q"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # ConditionalFormatting - DeleteMessage
        Add-ConditionalFormatting -Address $WorkSheet.Cells["T:T"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$T1)))' -BackgroundColor Red

        # ConditionalFormatting - MarkAsRead
        Add-ConditionalFormatting -Address $WorkSheet.Cells["S:S"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$S1)))' -BackgroundColor Red
 
        # Iterating over the MoveToFolder-Blacklist HashTable
        foreach ($MoveToFolder in $MoveToFolderBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$U1)))' -f $MoveToFolder
            Add-ConditionalFormatting -Address $WorkSheet.Cells["U:U"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # ConditionalFormatting - StopProcessingRules
        Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$X1)))' -BackgroundColor Red

        # ConditionalFormatting - ForwardAsAttachmentTo
        Add-ConditionalFormatting -Address $WorkSheet.Cells["AC:AC"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("@",$AC1)))' -BackgroundColor Red

        # ConditionalFormatting - ForwardTo
        Add-ConditionalFormatting -Address $WorkSheet.Cells["AD:AD"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("@",$AD1)))' -BackgroundColor Red

        # ConditionalFormatting - RedirectTo
        Add-ConditionalFormatting -Address $WorkSheet.Cells["AE:AE"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("@",$AE1)))' -BackgroundColor Red

        }
    }
}

# LETHAL-009: UpdateInboxRules (Exchange Web Services)
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql"
    $Data = $Result | ConvertFrom-Csv
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: UpdateInboxRules ($Count)" -ForegroundColor Red
        New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations" -ItemType Directory -Force | Out-Null

        $Data | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations\UpdateInboxRules.xlsx" -FreezePane 2,7 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UpdateInboxRules" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:AF1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-Z and AB-AF
        $WorkSheet.Cells["A:Z"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["AB:AF"].Style.HorizontalAlignment="Center"

        # ConditionalFormatting - Operation
        Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("UpdateInboxRules",$F1)))' -BackgroundColor Red

        # ConditionalFormatting - AppId
        foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
        {
            $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$H1)))' -f $AppId
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:I"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
        }

        # ConditionalFormatting - ASN
        foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("AS{0}",$M1)))' -f $ASN
            Add-ConditionalFormatting -Address $WorkSheet.Cells["M:N"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # ConditionalFormatting - CountryName
        foreach ($Country in $CountryBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$L1)))' -f $Country
            Add-ConditionalFormatting -Address $WorkSheet.Cells["K:L"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # ConditionalFormatting - ClientInfoString
        Add-ConditionalFormatting -Address $WorkSheet.Cells["O:O"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=WebServices;eM Client/",$O1)))' -BackgroundColor Red # eM Client (Traitorware)
        Add-ConditionalFormatting -Address $WorkSheet.Cells["O:O"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=WebServices;eMClient/",$O1)))' -BackgroundColor Red # eM Client (Traitorware)

        # ConditionalFormatting - ActorInfoString
        Add-ConditionalFormatting -Address $WorkSheet.Cells["P:P"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=WebServices;eM Client/",$P1)))' -BackgroundColor Red # eM Client (Traitorware)
        Add-ConditionalFormatting -Address $WorkSheet.Cells["P:P"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=WebServices;eMClient/",$P1)))' -BackgroundColor Red # eM Client (Traitorware)

        # ConditionalFormatting - Actions
        $Cells = "S:S"
        Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("DeleteAction",$S1)))' -BackgroundColor Red
        Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("MarkAsReadAction",$S1)))' -BackgroundColor Red
        Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("MoveToFolderAction",$S1)))' -BackgroundColor Red
        Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("PermanentDeleteAction",$S1)))' -BackgroundColor Red
        Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("ForwardToRecipientsAction",$S1)))' -BackgroundColor Red # Email Forwarding
        Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("ForwardAsAttachmentToRecipientsAction",$S1)))' -BackgroundColor Red # Email Forwarding
        Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("RedirectToRecipientsAction",$S1)))' -BackgroundColor Red # Email Forwarding

        # ConditionalFormatting - RuleOperation
        $Cells = "Z:Z"
        Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Create",$Z1)))' -BackgroundColor Red
        Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Update",$Z1)))' -BackgroundColor Red
        Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Delete",$Z1)))' -BackgroundColor Red
        Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AddMailboxRule",$Z1)))' -BackgroundColor Red
        Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("ModifyMailboxRule",$Z1)))' -BackgroundColor Red
        Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("RemoveMailboxRule",$Z1)))' -BackgroundColor Red

        }
    }
}

# LETHAL-010: UpdateInboxRules + Create
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql"
    $Data = $Result | ConvertFrom-Csv | Where-Object {($_.RuleOperation -like "Create")}
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: UpdateInboxRules + Create ($Count)" -ForegroundColor Red
    }
}

# LETHAL-011: UpdateInboxRules + Update
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql"
    $Data = $Result | ConvertFrom-Csv | Where-Object {($_.RuleOperation -like "Update")}
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: UpdateInboxRules + Update ($Count)" -ForegroundColor Red
    }
}

# LETHAL-012: UpdateInboxRules + Delete
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql"
    $Data = $Result | ConvertFrom-Csv | Where-Object {($_.RuleOperation -like "Delete")}
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: UpdateInboxRules + Delete ($Count)" -ForegroundColor Red
    }
}

# RuleOperation --> Inbox Rules [T1564.008]

# LETHAL-013: UpdateInboxRules + AddMailboxRule
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql"
    $Data = $Result | ConvertFrom-Csv | Where-Object {($_.RuleOperation -like "AddMailboxRule")}
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: UpdateInboxRules + AddMailboxRule ($Count)" -ForegroundColor Red
    }
}

# LETHAL-014: UpdateInboxRules + ModifyMailboxRule
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql"
    $Data = $Result | ConvertFrom-Csv | Where-Object {($_.RuleOperation -like "ModifyMailboxRule")}
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: UpdateInboxRules + ModifyMailboxRule ($Count)" -ForegroundColor Red
    }
}

# LETHAL-015: UpdateInboxRules + RemoveMailboxRule
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql"
    $Data = $Result | ConvertFrom-Csv | Where-Object {($_.RuleOperation -like "RemoveMailboxRule")}
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: UpdateInboxRules + RemoveMailboxRule ($Count)" -ForegroundColor Red
    }
}

# LETHAL-016: UpdateInboxRules + MoveToFolderAction
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql"
    $Data = $Result | ConvertFrom-Csv | Where-Object {($_.Actions -like "MoveToFolderAction")}
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: UpdateInboxRules + MoveToFolderAction ($Count)" -ForegroundColor Red
    }
}

# LETHAL-017: UpdateInboxRules + MarkAsReadAction
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql"
    $Data = $Result | ConvertFrom-Csv | Where-Object {($_.Actions -like "MarkAsReadAction")}
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: UpdateInboxRules + MarkAsReadAction ($Count)" -ForegroundColor Red
    }
}

# LETHAL-018: UpdateInboxRules + DeleteAction
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql"
    $Data = $Result | ConvertFrom-Csv | Where-Object {($_.Actions -like "DeleteAction")}
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: UpdateInboxRules + DeleteAction ($Count)" -ForegroundColor Red
    }
}

# LETHAL-019: UpdateInboxRules + PermanentDeleteAction
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql"
    $Data = $Result | ConvertFrom-Csv | Where-Object {($_.Actions -like "PermanentDeleteAction")}
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: UpdateInboxRules + PermanentDeleteAction ($Count)" -ForegroundColor Red
    }
}

# Actions --> Email Forwarding Rules [T1114.003]

# LETHAL-020: UpdateInboxRules + DeleteForwardToRecipientsAction
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql"
    $Data = $Result | ConvertFrom-Csv | Where-Object {($_.Actions -like "DeleteForwardToRecipientsAction")}
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: UpdateInboxRules + DeleteForwardToRecipientsAction ($Count)" -ForegroundColor Red
    }
}

# LETHAL-021: UpdateInboxRules + ForwardAsAttachmentToRecipientsAction
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql"
    $Data = $Result | ConvertFrom-Csv | Where-Object {($_.Actions -like "ForwardAsAttachmentToRecipientsAction")}
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: UpdateInboxRules + ForwardAsAttachmentToRecipientsAction ($Count)" -ForegroundColor Red
    }
}

# LETHAL-022: UpdateInboxRules + RedirectToRecipientsAction
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\UpdateInboxRules.sql"
    $Data = $Result | ConvertFrom-Csv | Where-Object {($_.Actions -like "RedirectToRecipientsAction")}
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: UpdateInboxRules + RedirectToRecipientsAction ($Count)" -ForegroundColor Red
    }
}

# Transport Rules
# Transport Rules (or Mail Flow Rules) are similar to the Inbox Rules. The main difference is that the Transport Rule take action on messages while they're in transit, and not after the message is delivered to the mailbox. 
# An adversary or insider threat may create/modify a transport rule to exfiltrate data or evade defenses.

# LETHAL-023: New-TransportRule - Creates a new Transport Rule in an organization
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\New-TransportRule.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\New-TransportRule.sql"
    $Data = $Result | ConvertFrom-Csv
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: New-TransportRule ($Count)" -ForegroundColor Red
        New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations" -ItemType Directory -Force | Out-Null
        $Data | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations\New-TransportRule.xlsx" -NoNumberConversion * -FreezePane 2,7 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "New-TransportRule" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:AC1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-AC
        $WorkSheet.Cells["A:AC"].Style.HorizontalAlignment="Center"
        
        # ConditionalFormatting - Operation
        Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("New-TransportRule",$F1)))' -BackgroundColor Red

        # ConditionalFormatting - ASN
        foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("AS{0}",$O1)))' -f $ASN
            Add-ConditionalFormatting -Address $WorkSheet.Cells["O:P"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # ConditionalFormatting - CountryName
        foreach ($Country in $CountryBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$N1)))' -f $Country
            Add-ConditionalFormatting -Address $WorkSheet.Cells["M:N"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # ConditionalFormatting - BlindCopyTo
        Add-ConditionalFormatting -Address $WorkSheet.Cells["R:R"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("@",$R1)))' -BackgroundColor Red

        # ConditionalFormatting - CopyTo
        Add-ConditionalFormatting -Address $WorkSheet.Cells["S:S"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("@",$S1)))' -BackgroundColor Red

        # ConditionalFormatting - RedirectMessageTo
        Add-ConditionalFormatting -Address $WorkSheet.Cells["T:T"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("@",$T1)))' -BackgroundColor Red

        # ConditionalFormatting - StopRuleProcessing
        Add-ConditionalFormatting -Address $WorkSheet.Cells["V:V"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$V1)))' -BackgroundColor Red

        }
    }
}

# LETHAL-024: Set-TransportRule - Modify an existing Transport Rule in an organization
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\Set-TransportRule.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\Set-TransportRule.sql"
    $Data = $Result | ConvertFrom-Csv
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: Set-TransportRule ($Count)" -ForegroundColor Red
        New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations" -ItemType Directory -Force | Out-Null
        $Data | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations\Set-TransportRule.xlsx" -NoNumberConversion * -FreezePane 2,7 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Set-TransportRule" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:AG1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-AG
        $WorkSheet.Cells["A:AG"].Style.HorizontalAlignment="Center"
        
        # ConditionalFormatting - Operation
        Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("Set-TransportRule",$F1)))' -BackgroundColor Red

        # ConditionalFormatting - ASN
        foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("AS{0}",$O1)))' -f $ASN
            Add-ConditionalFormatting -Address $WorkSheet.Cells["O:P"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # ConditionalFormatting - CountryName
        foreach ($Country in $CountryBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$N1)))' -f $Country
            Add-ConditionalFormatting -Address $WorkSheet.Cells["M:N"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # ConditionalFormatting - BlindCopyTo
        Add-ConditionalFormatting -Address $WorkSheet.Cells["S:S"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("@",$S1)))' -BackgroundColor Red

        # ConditionalFormatting - CopyTo
        Add-ConditionalFormatting -Address $WorkSheet.Cells["T:T"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("@",$T1)))' -BackgroundColor Red

        # ConditionalFormatting - RedirectMessageTo
        Add-ConditionalFormatting -Address $WorkSheet.Cells["U:U"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("@",$U1)))' -BackgroundColor Red
        
        }
    }
}

# LETHAL-025: Email-Forwarding via New-TransportRule / Set-TransportRule
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\Email-Forwarding_TransportRule.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\Email-Forwarding_TransportRule.sql"
    $Data = $Result | ConvertFrom-Csv
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: Email-Forwarding via New-TransportRule / Set-TransportRule ($Count)" -ForegroundColor Red
    }
}

# LETHAL-026: Set-Mailbox - Change an existing mailbox, often used for setting up forwarding rules --> Email Collection: Email Forwarding Rule [T1114.003]
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\Set-Mailbox.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\Set-Mailbox.sql"
    $Data = $Result | ConvertFrom-Csv
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: Set-Mailbox ($Count)" -ForegroundColor Red
        New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations" -ItemType Directory -Force | Out-Null
        $Data | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations\Set-Mailbox.xlsx" -NoNumberConversion * -NoHyperLinkConversion * -FreezePane 2,7 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Set-Mailbox" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:Y1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-Y
        $WorkSheet.Cells["A:Y"].Style.HorizontalAlignment="Center"

        # ConditionalFormatting - Operation
        Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("Set-Mailbox",$F1)))' -BackgroundColor Red

        # ConditionalFormatting - ASN
        foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("AS{0}",$O1)))' -f $ASN
            Add-ConditionalFormatting -Address $WorkSheet.Cells["O:P"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # ConditionalFormatting - CountryName
        foreach ($Country in $CountryBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$N1)))' -f $Country
            Add-ConditionalFormatting -Address $WorkSheet.Cells["M:N"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # ConditionalFormatting - ForwardingAddress
        Add-ConditionalFormatting -Address $WorkSheet.Cells["R:R"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("@",$R1)))' -BackgroundColor Red

        # ConditionalFormatting - ForwardingSmtpAddress
        Add-ConditionalFormatting -Address $WorkSheet.Cells["S:S"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("@",$S1)))' -BackgroundColor Red

        # ConditionalFormatting - DeliverToMailboxAndForward
        Add-ConditionalFormatting -Address $WorkSheet.Cells["T:T"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$T1)))' -BackgroundColor Red

        }
    }
}

# LETHAL-027: Suspicious E-Mail Forwarding Rules (Set-Mailbox + DeliverToMailboxAndForward)
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\Set-Mailbox.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\Set-Mailbox.sql"
    $Data = $Result | ConvertFrom-Csv | Where-Object {($_.DeliverToMailboxAndForward -eq "True")}
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: Set-Mailbox + DeliverToMailboxAndForward ($Count)" -ForegroundColor Red
    }
}

# LETHAL-028: Suspicious E-Mail Forwarding Rules (Set-Mailbox + ForwardingAddress)
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\Set-Mailbox.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\Set-Mailbox.sql"
    $Data = $Result | ConvertFrom-Csv | Where-Object {($_.ForwardingAddress -match "@")}
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: Set-Mailbox + ForwardingAddress ($Count)" -ForegroundColor Red
    }
}

# LETHAL-029: Suspicious E-Mail Forwarding Rules (Set-Mailbox + ForwardingSmtpAddress)
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\Set-Mailbox.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\Set-Mailbox.sql"
    $Data = $Result | ConvertFrom-Csv | Where-Object {($_.ForwardingSmtpAddress -match "@")}
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: Set-Mailbox + ForwardingSmtpAddress ($Count)" -ForegroundColor Red
    }
}

# LETHAL-030: Set-MailboxJunkEmailConfiguration - Configure a Junk E-Mail rule for a specific mailbox
# https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-mailboxjunkemailconfiguration?view=exchange-ps
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\Set-MailboxJunkEmailConfiguration.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\Set-MailboxJunkEmailConfiguration.sql"
    $Data = $Result | ConvertFrom-Csv
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: Set-MailboxJunkEmailConfiguration ($Count)" -ForegroundColor Red
        New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations" -ItemType Directory -Force | Out-Null
        $Data | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations\Set-MailboxJunkEmailConfiguration.xlsx" -FreezePane 2,7 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Junk E-Mail Rules" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:AC1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-AC
        $WorkSheet.Cells["A:AC"].Style.HorizontalAlignment="Center"

        # ConditionalFormatting - Operation
        Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("Set-MailboxJunkEmailConfiguration",$F1)))' -BackgroundColor Red

        # ConditionalFormatting - ASN
        foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("AS{0}",$O1)))' -f $ASN
            Add-ConditionalFormatting -Address $WorkSheet.Cells["O:P"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # ConditionalFormatting - CountryName
        foreach ($Country in $CountryBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$N1)))' -f $Country
            Add-ConditionalFormatting -Address $WorkSheet.Cells["M:N"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        }
    }
}

# TrustedSendersAndDomains - The TrustedSendersAndDomains parameter specifies the Safe Senders list and Safe Recipients list, which are lists of email addresses and domains. Messages from these senders that reach the mailbox are never delivered to the Junk Email folder, regardless of the content.
# BlockedSendersAndDomains - The BlockedSendersAndDomains parameter specifies the Blocked Senders list, which is a list of sender email addresses and domains whose messages are automatically sent to the Junk Email folder. 
# TrustedListsOnly - The TrustedListsOnly parameter specifies that only messages from senders in the Safe Senders list are delivered to the Inbox. All other messages are treated as junk email.

# Mailbox Permission Changes

# LETHAL-031: Add-MailboxPermission - Added delegate mailbox permissions --> T1098.002 - Account Manipulation: Additional Email Delegate Permissions
# Description: An administrator assigned the FullAccess mailbox permission to a user (known as a delegate) to another person's mailbox. The FullAccess permission allows the delegate to open the other person's mailbox, and read and manage the contents of the mailbox.
# https://learn.microsoft.com/en-us/powershell/module/exchange/add-mailboxpermission?view=exchange-ps
# TODO

# LETHAL-032: Add-RecipientPermission - Add SendAs permission to users mailbox (in a cloud-based organization)
# Note: SendAs permission allows a user or group members to send messages that appear to come from the specified mailbox, mail contact, mail user, or group.
# https://learn.microsoft.com/en-us/powershell/module/exchange/add-recipientpermission?view=exchange-ps
# TODO

# LETHAL-033: Add-MailboxFolderPermission - Add permissions on a mailbox folder
# TODO

# LETHAL-034: Set-MailboxFolderPermission - Set permissions on a mailbox folder
# TODO

# LETHAL-035: New-InboundConnector - Setup a new email inbound connector
# TODO

# OAuth Applications / Permission Grants

# LETHAL-036: Suspicious Operation(s) detected: Add service principal.
# Description: An application was registered in Microsoft Entra ID. An application is represented by a service principal in the directory.
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\Add-service-principal.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\Add-service-principal.sql"
    $Data = $Result | ConvertFrom-Csv
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: Add service principal ($Count)" -ForegroundColor Red
        New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations" -ItemType Directory -Force | Out-Null
        $Data | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations\Add-service-principal.xlsx" -FreezePane 2,7 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Add service principal" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:N1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-G and I-N
        $WorkSheet.Cells["A:G"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["I:N"].Style.HorizontalAlignment="Center"

        # ConditionalFormatting - Operation
        Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("Add service principal.",$F1)))' -BackgroundColor Red

        # ConditionalFormatting - AppId
        foreach ($AppId in $ApplicationBlacklist_HashTable.Keys)
        {
            $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$J1)))' -f $AppId
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity   
        }

        # ConditionalFormatting - UserAgent
        foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
        {
            $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$L1)))' -f $UserAgent
            Add-ConditionalFormatting -Address $WorkSheet.Cells["L:L"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
        }

        }
    }
}

# LETHAL-037: Suspicious Operation(s) detected: Add delegated permission grant.
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\Add-delegated-permission-grant.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\Add-delegated-permission-grant.sql"
    $Data = $Result | ConvertFrom-Csv
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: Add delegated permission grant ($Count)" -ForegroundColor Red
        New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations" -ItemType Directory -Force | Out-Null
        $Data | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations\Add-delegated-permission-grant.xlsx" -FreezePane 2,7 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Add delegated permission grant" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:Q1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-N
        $WorkSheet.Cells["A:N"].Style.HorizontalAlignment="Center"

        # ConditionalFormatting - Operation
        Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("Add delegated permission grant.",$F1)))' -BackgroundColor Red
        
        # ConditionalFormatting - UserAgent
        foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
        {
            $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$I1)))' -f $UserAgent
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
        }

        }
    }
}

# LETHAL-038: Suspicious Operation(s) detected: Add app role assignment grant to user.
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\Add-app-role-assignment-grant-to-user.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\Add-app-role-assignment-grant-to-user.sql"
    $Data = $Result | ConvertFrom-Csv
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: Add app role assignment grant to user ($Count)" -ForegroundColor Red
        New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations" -ItemType Directory -Force | Out-Null
        $Data | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations\Add-app-role-assignment-grant-to-user.xlsx" -FreezePane 2,7 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "App Role Assignment" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-M
        $WorkSheet.Cells["A:M"].Style.HorizontalAlignment="Center"

        # ConditionalFormatting - Operation
        Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("Add app role assignment grant to user.",$F1)))' -BackgroundColor Red

        # ConditionalFormatting - UserAgent
        foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
        {
            $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$I1)))' -f $UserAgent
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
        }

        # ConditionalFormatting - AppId
        foreach ($AppId in $ApplicationBlacklist_HashTable.Keys)
        {
            $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$J1)))' -f $AppId
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:K"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity   
        }

        }
    }
}

# LETHAL-039: Suspicious Operation(s) detected: Consent to application.
# Consent is the process of a user granting authorization to an application to access protected resources on their behalf. Detects when a user grants permissions to an Entra-registered application or when an administrator grants tenant-wide permissions to an application. An adversary may create an Entra-registered application that requests access to data such as contact information, email, or documents.
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\Consent-to-application.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\Consent-to-application.sql"
    $Data = $Result | ConvertFrom-Csv
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: Consent to application ($Count)" -ForegroundColor Red
        New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations" -ItemType Directory -Force | Out-Null
        $Data | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations\Consent-to-application.xlsx" -FreezePane 2,7 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Consent to application" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:S1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-P
        $WorkSheet.Cells["A:P"].Style.HorizontalAlignment="Center"

        # ConditionalFormatting - Operation
        Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("Consent to application.",$F1)))' -BackgroundColor Red

        # ConditionalFormatting - UserAgent
        foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
        {
            $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$I1)))' -f $UserAgent
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
        }

        # ConditionalFormatting - AppId
        foreach ($AppId in $ApplicationBlacklist_HashTable.Keys)
        {
            $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$J1)))' -f $AppId
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:K"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity 
        }

        }
    }
}

# Sequence 1
# Add service principal.
# Add delegated permission grant.
# Consent to application.

# Sequence 2
# Add service principal.
# Add app role assignment grant to user.
# Add delegated permission grant.
# Consent to application.

# LETHAL-040: Suspicious Operation(s) detected: HygieneTenantEvents
# Note: Related to Exchange Online Protection and Microsoft Defender for Office 365. Hygiene Events are related to Outbound Spam Protection. These events are related to users who are restricted from sending email.
if (Test-Path "$SCRIPT_DIR\Queries\Suspicious-Operations\HygieneTenantEvents.sql")
{
    $Result = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\Suspicious-Operations\HygieneTenantEvents.sql"
    $Data = $Result | ConvertFrom-Csv
    $Count  = ($Data | Measure-Object).Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: HygieneTenantEvents - Outbound Spam Protection ($Count)" -ForegroundColor Red
        New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations" -ItemType Directory -Force | Out-Null
        $Data | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\Suspicious-Operations\HygieneTenantEvents.xlsx" -FreezePane 2,7 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "HygieneTenantEvents" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:V1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-V
        $WorkSheet.Cells["A:V"].Style.HorizontalAlignment="Center"

        # ConditionalFormatting - Operation
        Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("HygieneTenantEvents",$F1)))' -BackgroundColor Red

        # Iterating over the ASN-Blacklist HashTable
        foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("AS{0}",$T1)))' -f $ASN
            Add-ConditionalFormatting -Address $WorkSheet.Cells["T:U"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # Iterating over the Country-Blacklist HashTable
        foreach ($Country in $CountryBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$S1)))' -f $Country
            Add-ConditionalFormatting -Address $WorkSheet.Cells["R:S"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        }
    }
}

$EndTime_SuspiciousOperations = (Get-Date)
$Time_SuspiciousOperations = ($EndTime_SuspiciousOperations-$StartTime_SuspiciousOperations)
('Suspicious Operations duration:        {0} h {1} min {2} sec' -f $Time_SuspiciousOperations.Hours, $Time_SuspiciousOperations.Minutes, $Time_SuspiciousOperations.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#############################################################################################################################################################################################
#############################################################################################################################################################################################

Function Get-MailItemsAccessed {

$StartTime_MailItemsAccessed = (Get-Date)

if (Test-Path "$SCRIPT_DIR\Queries\MailItemsAccessed.sql")
{
    Write-Output "[Info]  Creating MailItemsAccessed View ..."
    $ResultSet = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\MailItemsAccessed.sql"
    $ResultSet | Out-File -FilePath "$OUTPUT_FOLDER\UnifiedAuditLog\CSV\MailItemsAccessed.csv" -Encoding UTF8
    $script:MailItemsAccessed = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLog\CSV\MailItemsAccessed.csv" -Delimiter "," -Encoding UTF8
    $MailItemsAccessed | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\MailItemsAccessed\MailItemsAccessed.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezePane 2,7 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MailItemsAccessed" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:AM1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-AM
    $WorkSheet.Cells["A:AM"].Style.HorizontalAlignment="Center"

    # ConditionalFormatting - AppId
    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys)
    {
        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$H1)))' -f $AppId
        Add-ConditionalFormatting -Address $WorkSheet.Cells["H:I"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity 
    }

    # ConditionalFormatting - AppDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Third Party Application",$I1)))' -BackgroundColor Yellow

    # ConditionalFormatting - ASN
    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("AS{0}",$M1)))' -f $ASN
        Add-ConditionalFormatting -Address $WorkSheet.Cells["M:N"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red

        $ConditionValue = '=AND(NOT(ISERROR(FIND("{0}",$M1))),$AI1<>"")' -f $ASN
        Add-ConditionalFormatting -Address $WorkSheet.Cells["AI:AI"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # Colorize also the corresponding SessionId
    }

    # ConditionalFormatting - CountryName
    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$L1)))' -f $Country
        Add-ConditionalFormatting -Address $WorkSheet.Cells["K:L"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    # ConditionalFormatting - ClientInfoString
    $Cells = "O:O"
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=WebServices;eM Client/",$O1)))' -BackgroundColor Red # eM Client (Traitorware)
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=WebServices;eMClient/",$O1)))' -BackgroundColor Red # eM Client (Traitorware)

    # ConditionalFormatting - ActorInfoString
    $Cells = "P:P"
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=WebServices;eM Client/",$P1)))' -BackgroundColor Red # eM Client (Traitorware)
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=WebServices;eMClient/",$P1)))' -BackgroundColor Red # eM Client (Traitorware)

    # ConditionalFormatting - MailAccessType
    Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Sync",$X1)))' -BackgroundColor Yellow # Potential Mailbox Synchronisation for Offline Usage / Exfiltration via Sync Access

    # ConditionalFormatting - InternetMessageId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AD:AD"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("<em",$AD1)))' -BackgroundColor Red # Messages sent by eM Client (Inbound and Outbound)

    }
}

# Create 'MailItemsAccessed' Table
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLog\CSV\MailItemsAccessed.csv")
{
    & $DuckDB $Database -c "CREATE OR REPLACE TABLE 'MailItemsAccessed' AS SELECT * FROM read_csv('$OUTPUT_FOLDER\UnifiedAuditLog\CSV\MailItemsAccessed.csv', nullstr=' ');"
}

# Stats
New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\MailItemsAccessed\Stats" -ItemType Directory -Force | Out-Null

# ActorInfoString (Stats)
if (Test-Path "$SCRIPT_DIR\Queries\MailItemsAccessed\Stats\ActorInfoString.sql")
{
    $Stats = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\MailItemsAccessed\Stats\ActorInfoString.sql"
    $Stats | ConvertFrom-Csv | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\MailItemsAccessed\Stats\ActorInfoString.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ActorInfoString" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"

    # ConditionalFormatting - ActorInfoString
    $Cells = "A:C"
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=WebServices;eM Client/",$A1)))' -BackgroundColor Red # eM Client (Traitorware)
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=WebServices;eMClient/",$A1)))' -BackgroundColor Red # eM Client (Traitorware)

    }
}

# AggregatedFolders (Stats)
$Total = ($MailItemsAccessed | Select-Object Folder | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $MailItemsAccessed | Group-Object Folder | Select-Object @{Name='Folder'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\MailItemsAccessed\Stats\AggregatedFolders.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AggregatedFolders" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# AppId / AppDisplayName (Stats)
if (Test-Path "$SCRIPT_DIR\Queries\MailItemsAccessed\Stats\AppId-AppDisplayName.sql")
{
    $Stats = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\MailItemsAccessed\Stats\AppId-AppDisplayName.sql"
    $Stats | ConvertFrom-Csv | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\MailItemsAccessed\Stats\AppId-AppDisplayName.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AppId" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-D
    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment = "Center"

    # ConditionalFormatting - AppId
    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys)
    {
        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$A1)))' -f $AppId
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity   
    }

    # ConditionalFormatting - AppDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Third Party Application",$B1)))' -BackgroundColor Yellow

    }
}

# ASN (Stats)
if (Test-Path "$SCRIPT_DIR\Queries\MailItemsAccessed\Stats\ASN.sql")
{
    $Stats = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\MailItemsAccessed\Stats\ASN.sql"
    $Stats | ConvertFrom-Csv | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\MailItemsAccessed\Stats\ASN.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ASN" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of column A-D
    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment = "Center"

    # ConditionalFormatting - ASN
    foreach ($ASN in $AsnBlacklist_HashTable.Keys) {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$A1)))' -f $ASN
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    }
}

# ClientInfoString (Stats)
if (Test-Path "$SCRIPT_DIR\Queries\MailItemsAccessed\Stats\ClientInfoString.sql")
{
    $Stats = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\MailItemsAccessed\Stats\ClientInfoString.sql"
    $Stats | ConvertFrom-Csv | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\MailItemsAccessed\Stats\ClientInfoString.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ClientInfoString" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    
    # ConditionalFormatting - ClientInfoString
    $Cells = "A:C"
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=WebServices;eM Client/",$A1)))' -BackgroundColor Red # eM Client (Traitorware)
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=WebServices;eMClient/",$A1)))' -BackgroundColor Red # eM Client (Traitorware)

    }
}

# CountryCode / CountryName (Stats)
if (Test-Path "$SCRIPT_DIR\Queries\MailItemsAccessed\Stats\CountryCode-CountryName.sql")
{
    $Stats = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\MailItemsAccessed\Stats\CountryCode-CountryName.sql"
    $Stats | ConvertFrom-Csv | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\MailItemsAccessed\Stats\CountryCode-CountryName.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Countries" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of column A-D
    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"

    # ConditionalFormatting - CountryName
    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$B1)))' -f $Country
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    }
}

# Folder (Stats)
if (Test-Path "$SCRIPT_DIR\Queries\MailItemsAccessed\Stats\Folder.sql")
{
    $Stats = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\MailItemsAccessed\Stats\Folder.sql"
    $Stats | ConvertFrom-Csv | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\MailItemsAccessed\Stats\Folder.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Folder" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of column A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# IPAddress / CountryName (Stats)
if (Test-Path "$SCRIPT_DIR\Queries\MailItemsAccessed\Stats\IPAddress-CountryName.sql")
{
    $Stats = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\MailItemsAccessed\Stats\IPAddress-CountryName.sql"
    $Stats | ConvertFrom-Csv | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\MailItemsAccessed\Stats\IPAddress-CountryName.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "IPAddress" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of column A-G
    $WorkSheet.Cells["A:"].Style.HorizontalAlignment="Center"

    # ConditionalFormatting - ASN
    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$D1)))' -f $ASN
        Add-ConditionalFormatting -Address $WorkSheet.Cells["D:E"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    # ConditionalFormatting - CountryName
    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$C1)))' -f $Country
        Add-ConditionalFormatting -Address $WorkSheet.Cells["B:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    }
}

# MailAccessType (Stats) --> MailItemsAccessed events are triggered by two event types: Sync and Bind operations.
# Auditing Sync Access --> Sync access is recorded when a mailbox is accessed by a desktop version of the Outlook client for Windows or Mac.
# Auditing Bind Access --> Bind access is recorded when an individual message is accessed.
if (Test-Path "$SCRIPT_DIR\Queries\MailItemsAccessed\Stats\MailAccessType.sql")
{
    $Stats = & $DuckDB $Database -csv -nullvalue " " -f "$SCRIPT_DIR\Queries\MailItemsAccessed\Stats\MailAccessType.sql"
    $Stats | ConvertFrom-Csv | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\MailItemsAccessed\Stats\MailAccessType.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "IPAddress" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of column A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# OperationCount
# Note: The MailItemsAccess operation writes an aggregated 2-minute window of activity into a single audit record.
[int]$Sum = ($MailItemsAccessed | Select-Object OperationCount | Measure-Object -Property OperationCount -Sum).Sum
$OperationCount = '{0:N0}' -f $Sum
Write-Output "[Info]  Total Number of Accessed Mailbox Items: $OperationCount"

# Count
[int]$Bind = ($MailItemsAccessed | Where-Object { $_.MailAccessType -eq "Bind" } | Measure-Object).Count
[int]$Sync = ($MailItemsAccessed | Where-Object { $_.MailAccessType -eq "Sync" } | Measure-Object).Count
$BindAccess = '{0:N0}' -f $Bind
$SyncAccess = '{0:N0}' -f $Sync
Write-Output "[Info]  $SyncAccess Sync Access Operation(s) found"
Write-Output "[Info]  $BindAccess Bind Access Operation(s) found"

# Line Charts
New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\MailItemsAccessed\Stats\LineCharts" -ItemType Directory -Force | Out-Null

# Accessed Mailbox Items (per day)
if (Test-Path "$SCRIPT_DIR\Queries\MailItemsAccessed\LineCharts\MailItemsAccessed.sql")
{
    $Result = & $DuckDB $Database -csv -f "$SCRIPT_DIR\Queries\MailItemsAccessed\LineCharts\MailItemsAccessed.sql"
    $Import = $Result | ConvertFrom-Csv
    $Count  = ($Import | Measure-Object).Count
    if ($Count -gt 0)
    {
        $ChartDefinition = New-ExcelChartDefinition -XRange CreationTime -YRange Count -Title "MailItemsAccessed" -ChartType Line -NoLegend -Width 1200
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLog\MailItemsAccessed\Stats\LineCharts\MailItemsAccessed.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
    }
}

# Throttling of MailItemsAccessed Audit Records
# If more than 1000 MailItemsAccessed audit records are generated in less than 24 hours, Exchange Online will stop generating auditing records for MailItemsAccessed activity. 
# When a mailbox is throttled, MailItemsAccessed activity won't be logged for 24 hours after the mailbox was throttled. 
# If the mailbox was throttled, there's a potential that mailbox could have been compromised during this period. 
# The recording of MailItemsAccessed activity will be resumed following a 24-hour period.

# - Less than 1% of all mailboxes in Exchange Online are throttled
# - When a mailbox is throttling, only audit records for MailItemsAccessed activity aren't audited. Other mailbox auditing actions aren't affected.
# - Mailboxes are throttled only for Bind operations. Audit records for sync operations aren't throttled.
# - If a mailbox is throttled, you can probably assume there was MailItemsAccessed activity that wasn't recorded in the audit logs.

# LETHAL-0xx: IsThrottled --> Mailbox Synchronisation for Offline Usage / Exfiltration
$Count = & $DuckDB $Database -noheader -csv -c "SELECT COUNT(DISTINCT Id) FROM 'MailItemsAccessed' WHERE IsThrottled = 'true';"
if ($Count -gt 0)
{
    Write-Host "[Alert] MailItemsAccessed Throttling: More than 1000 MailItemsAccessed Audit Records were generated in less than 24 hours ($Count)" -ForegroundColor Red
}

# LETHAL-0xx: Suspicious Sync Access Operation(s) --> Mailbox Synchronization for Offline Usage / Exfiltration
# Note: Sync access is recorded when a mailbox is accessed by a desktop version of the Outlook client for Windows or Mac.
# Important: The Microsoft Outlook Data File aka Offline Storage Table (.ost) will remain on the Threat Actors Device after containment/remediation!
$Count = & $DuckDB $Database -noheader -csv -c "SELECT COUNT(DISTINCT Id) FROM 'MailItemsAccessed' WHERE MailAccessType = 'Sync' AND ResultStatus = 'Succeeded';"
if ($Count -gt 0)
{
    Write-Host "[Alert] Potential Mailbox Synchronisation for Offline Usage / Exfiltration via Sync Access detected ($Count Outlook Folders)" -ForegroundColor Red 
}

$EndTime_MailItemsAccessed = (Get-Date)
$Time_MailItemsAccessed = ($EndTime_MailItemsAccessed-$StartTime_MailItemsAccessed)
('MailItemsAccessed Processing duration: {0} h {1} min {2} sec' -f $Time_MailItemsAccessed.Hours, $Time_MailItemsAccessed.Minutes, $Time_MailItemsAccessed.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

# MailItemsAccessed Processing

#############################################################################################################################################################################################
#############################################################################################################################################################################################

Function Export-Notebooks {

Write-Output "[Info]  Exporting Notebook(s) from DuckDB UI ..."
New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\DuckDB\Notebooks" -ItemType Directory -Force | Out-Null

# The DuckDB UI stores the content of the interactive notebooks in an internal database called '_duckdb_ui'.
# You can query and export the content of the interactive notebooks, as well as insert new queries into the database.
# Note: Modifying the internal database may lead to corruption and data loss. Be cautious and use it on your own risk!
$InternalDatabase = "$env:USERPROFILE\.duckdb\extension_data\ui\ui.db"
if (Test-Path "$InternalDatabase")
{
    $Data = & $DuckDB $InternalDatabase -json -c "select title,json from ui.main.notebook_versions where expires is null"
    $Notebooks = $Data | ConvertFrom-Json

    $Count = ($Notebooks | Measure-Object).Count
    Write-Output "[Info]  $Count Notebook(s) found"

    ForEach($Notebook in $Notebooks)
    {
        $Title   = $Notebook.title
        $JSON    = $Notebook.json
        $Cells   = $JSON | ConvertFrom-Json | Select-Object -ExpandProperty cells

        $Count = ($Cells | Measure-Object).Count
        Write-Output "[Info]  $Title ($Count)"

        # Create Output Directory for Notebook
        New-Item "$OUTPUT_FOLDER\UnifiedAuditLog\DuckDB\Notebooks\$Title" -ItemType Directory -Force | Out-Null

        # Dump all SQL Queries
        $Counter=1
        ForEach($Cell in $Cells)
        {
            $Query = $Cell.query
            $Query | Out-File "$OUTPUT_FOLDER\UnifiedAuditLog\DuckDB\Notebooks\$Title\$Counter.sql" -Encoding UTF8
            $Counter++
        }
    }
}
else
{
    Write-Host "[Alert] DuckDB database NOT found." -ForegroundColor Red
}

}

#############################################################################################################################################################################################
#############################################################################################################################################################################################

Function Start-DuckUI {

# Launching DuckDB UI (w/ Interactive Notebooks) --> http://localhost:4213/
Start-Process -FilePath "$DuckDB" -ArgumentList "-ui", "$Database" -WindowStyle Minimized

}

#endregion Analysis

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# IPinfo Clear Cache (Optional)
Function Clear-IPInfoCache {

    if (Test-Path "$($IPinfo)")
    {
        & $IPinfo cache clear > $null
    }
}

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Footer

Function Invoke-Footer {

# Get End Time
$EndTime = (Get-Date)

# Echo Time elapsed
Write-Output ""
Write-Output "FINISHED!"

$Time = ($EndTime-$StartTime)
$ElapsedTime = ('Overall analysis duration: {0} h {1} min {2} sec' -f $Time.Hours, $Time.Minutes, $Time.Seconds)
Write-Output "$ElapsedTime"

# Stop logging
Write-Host ""
Stop-Transcript
Start-Sleep 0.5

# IPinfo Logout
if (Test-Path "$($IPinfo)")
{
    & $IPinfo logout > $null
}

# Cleaning up
Clear-Variable Token

# MessageBox UI
$MessageBody = "Status: Unified Audit Log Analysis completed.`n`nPress CTRL + D to shutdown DuckDB UI." # Happy M365 Investigation!
$MessageTitle = "UALGraph-Analyzer.ps1 (https://lethal-forensics.com/)"
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

}

#endregion Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Main

# Main
Invoke-Header
Invoke-InitialProcessing
Invoke-DuckDB
Invoke-BlacklistDetections
Get-Stats
Invoke-GeoIPMapping
Invoke-SuspiciousOperations
Get-MailItemsAccessed
#Export-Notebooks
Start-DuckUI
#Clear-IPInfoCache
Invoke-Footer

#endregion Main

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# SIG # Begin signature block
# MIIrywYJKoZIhvcNAQcCoIIrvDCCK7gCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUR0tlplwh+TSZadcla6ghP04G
# MdWggiUEMIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
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
# 1FiAhORFe1rYMIIGFDCCA/ygAwIBAgIQeiOu2lNplg+RyD5c9MfjPzANBgkqhkiG
# 9w0BAQwFADBXMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MS4wLAYDVQQDEyVTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFJvb3QgUjQ2
# MB4XDTIxMDMyMjAwMDAwMFoXDTM2MDMyMTIzNTk1OVowVTELMAkGA1UEBhMCR0Ix
# GDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJs
# aWMgVGltZSBTdGFtcGluZyBDQSBSMzYwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAw
# ggGKAoIBgQDNmNhDQatugivs9jN+JjTkiYzT7yISgFQ+7yavjA6Bg+OiIjPm/N/t
# 3nC7wYUrUlY3mFyI32t2o6Ft3EtxJXCc5MmZQZ8AxCbh5c6WzeJDB9qkQVa46xiY
# Epc81KnBkAWgsaXnLURoYZzksHIzzCNxtIXnb9njZholGw9djnjkTdAA83abEOHQ
# 4ujOGIaBhPXG2NdV8TNgFWZ9BojlAvflxNMCOwkCnzlH4oCw5+4v1nssWeN1y4+R
# laOywwRMUi54fr2vFsU5QPrgb6tSjvEUh1EC4M29YGy/SIYM8ZpHadmVjbi3Pl8h
# JiTWw9jiCKv31pcAaeijS9fc6R7DgyyLIGflmdQMwrNRxCulVq8ZpysiSYNi79tw
# 5RHWZUEhnRfs/hsp/fwkXsynu1jcsUX+HuG8FLa2BNheUPtOcgw+vHJcJ8HnJCrc
# UWhdFczf8O+pDiyGhVYX+bDDP3GhGS7TmKmGnbZ9N+MpEhWmbiAVPbgkqykSkzyY
# Vr15OApZYK8CAwEAAaOCAVwwggFYMB8GA1UdIwQYMBaAFPZ3at0//QET/xahbIIC
# L9AKPRQlMB0GA1UdDgQWBBRfWO1MMXqiYUKNUoC6s2GXGaIymzAOBgNVHQ8BAf8E
# BAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNVHSUEDDAKBggrBgEFBQcDCDAR
# BgNVHSAECjAIMAYGBFUdIAAwTAYDVR0fBEUwQzBBoD+gPYY7aHR0cDovL2NybC5z
# ZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0YW1waW5nUm9vdFI0Ni5jcmww
# fAYIKwYBBQUHAQEEcDBuMEcGCCsGAQUFBzAChjtodHRwOi8vY3J0LnNlY3RpZ28u
# Y29tL1NlY3RpZ29QdWJsaWNUaW1lU3RhbXBpbmdSb290UjQ2LnA3YzAjBggrBgEF
# BQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQADggIB
# ABLXeyCtDjVYDJ6BHSVY/UwtZ3Svx2ImIfZVVGnGoUaGdltoX4hDskBMZx5NY5L6
# SCcwDMZhHOmbyMhyOVJDwm1yrKYqGDHWzpwVkFJ+996jKKAXyIIaUf5JVKjccev3
# w16mNIUlNTkpJEor7edVJZiRJVCAmWAaHcw9zP0hY3gj+fWp8MbOocI9Zn78xvm9
# XKGBp6rEs9sEiq/pwzvg2/KjXE2yWUQIkms6+yslCRqNXPjEnBnxuUB1fm6bPAV+
# Tsr/Qrd+mOCJemo06ldon4pJFbQd0TQVIMLv5koklInHvyaf6vATJP4DfPtKzSBP
# kKlOtyaFTAjD2Nu+di5hErEVVaMqSVbfPzd6kNXOhYm23EWm6N2s2ZHCHVhlUgHa
# C4ACMRCgXjYfQEDtYEK54dUwPJXV7icz0rgCzs9VI29DwsjVZFpO4ZIVR33LwXyP
# DbYFkLqYmgHjR3tKVkhh9qKV2WCmBuC27pIOx6TYvyqiYbntinmpOqh/QPAnhDge
# xKG9GX/n1PggkGi9HCapZp8fRwg8RftwS21Ln61euBG0yONM6noD2XQPrFwpm3Gc
# uqJMf0o8LLrFkSLRQNwxPDDkWXhW+gZswbaiie5fd/W2ygcto78XCSPfFWveUOSZ
# 5SqK95tBO8aTHmEa4lpJVD7HrTEn9jb1EGvxOb1cnn0CMIIGGjCCBAKgAwIBAgIQ
# Yh1tDFIBnjuQeRUgiSEcCjANBgkqhkiG9w0BAQwFADBWMQswCQYDVQQGEwJHQjEY
# MBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS0wKwYDVQQDEyRTZWN0aWdvIFB1Ymxp
# YyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYwHhcNMjEwMzIyMDAwMDAwWhcNMzYwMzIx
# MjM1OTU5WjBUMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MSswKQYDVQQDEyJTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgQ0EgUjM2MIIB
# ojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAmyudU/o1P45gBkNqwM/1f/bI
# U1MYyM7TbH78WAeVF3llMwsRHgBGRmxDeEDIArCS2VCoVk4Y/8j6stIkmYV5Gej4
# NgNjVQ4BYoDjGMwdjioXan1hlaGFt4Wk9vT0k2oWJMJjL9G//N523hAm4jF4UjrW
# 2pvv9+hdPX8tbbAfI3v0VdJiJPFy/7XwiunD7mBxNtecM6ytIdUlh08T2z7mJEXZ
# D9OWcJkZk5wDuf2q52PN43jc4T9OkoXZ0arWZVeffvMr/iiIROSCzKoDmWABDRzV
# /UiQ5vqsaeFaqQdzFf4ed8peNWh1OaZXnYvZQgWx/SXiJDRSAolRzZEZquE6cbcH
# 747FHncs/Kzcn0Ccv2jrOW+LPmnOyB+tAfiWu01TPhCr9VrkxsHC5qFNxaThTG5j
# 4/Kc+ODD2dX/fmBECELcvzUHf9shoFvrn35XGf2RPaNTO2uSZ6n9otv7jElspkfK
# 9qEATHZcodp+R4q2OIypxR//YEb3fkDn3UayWW9bAgMBAAGjggFkMIIBYDAfBgNV
# HSMEGDAWgBQy65Ka/zWWSC8oQEJwIDaRXBeF5jAdBgNVHQ4EFgQUDyrLIIcouOxv
# SK4rVKYpqhekzQwwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwGwYDVR0gBBQwEjAGBgRVHSAAMAgGBmeBDAEE
# ATBLBgNVHR8ERDBCMECgPqA8hjpodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3Rp
# Z29QdWJsaWNDb2RlU2lnbmluZ1Jvb3RSNDYuY3JsMHsGCCsGAQUFBwEBBG8wbTBG
# BggrBgEFBQcwAoY6aHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGlj
# Q29kZVNpZ25pbmdSb290UjQ2LnA3YzAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Au
# c2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQADggIBAAb/guF3YzZue6EVIJsT/wT+
# mHVEYcNWlXHRkT+FoetAQLHI1uBy/YXKZDk8+Y1LoNqHrp22AKMGxQtgCivnDHFy
# AQ9GXTmlk7MjcgQbDCx6mn7yIawsppWkvfPkKaAQsiqaT9DnMWBHVNIabGqgQSGT
# rQWo43MOfsPynhbz2Hyxf5XWKZpRvr3dMapandPfYgoZ8iDL2OR3sYztgJrbG6VZ
# 9DoTXFm1g0Rf97Aaen1l4c+w3DC+IkwFkvjFV3jS49ZSc4lShKK6BrPTJYs4NG1D
# GzmpToTnwoqZ8fAmi2XlZnuchC4NPSZaPATHvNIzt+z1PHo35D/f7j2pO1S8BCys
# QDHCbM5Mnomnq5aYcKCsdbh0czchOm8bkinLrYrKpii+Tk7pwL7TjRKLXkomm5D1
# Umds++pip8wH2cQpf93at3VDcOK4N7EwoIJB0kak6pSzEu4I64U6gZs7tS/dGNSl
# jf2OSSnRr7KWzq03zl8l75jy+hOds9TWSenLbjBQUGR96cFr6lEUfAIEHVC1L68Y
# 1GGxx4/eRI82ut83axHMViw1+sVpbPxg51Tbnio1lB93079WPFnYaOvfGAA0e0zc
# fF/M9gXr+korwQTh2Prqooq2bYNMvUoUKD85gnJ+t0smrWrb8dee2CvYZXD5laGt
# aAxOfy/VKNmwuWuAh9kcMIIGYjCCBMqgAwIBAgIRAKQpO24e3denNAiHrXpOtyQw
# DQYJKoZIhvcNAQEMBQAwVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28g
# TGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBD
# QSBSMzYwHhcNMjUwMzI3MDAwMDAwWhcNMzYwMzIxMjM1OTU5WjByMQswCQYDVQQG
# EwJHQjEXMBUGA1UECBMOV2VzdCBZb3Jrc2hpcmUxGDAWBgNVBAoTD1NlY3RpZ28g
# TGltaXRlZDEwMC4GA1UEAxMnU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBT
# aWduZXIgUjM2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA04SV9G6k
# U3jyPRBLeBIHPNyUgVNnYayfsGOyYEXrn3+SkDYTLs1crcw/ol2swE1TzB2aR/5J
# IjKNf75QBha2Ddj+4NEPKDxHEd4dEn7RTWMcTIfm492TW22I8LfH+A7Ehz0/safc
# 6BbsNBzjHTt7FngNfhfJoYOrkugSaT8F0IzUh6VUwoHdYDpiln9dh0n0m545d5A5
# tJD92iFAIbKHQWGbCQNYplqpAFasHBn77OqW37P9BhOASdmjp3IijYiFdcA0WQIe
# 60vzvrk0HG+iVcwVZjz+t5OcXGTcxqOAzk1frDNZ1aw8nFhGEvG0ktJQknnJZE3D
# 40GofV7O8WzgaAnZmoUn4PCpvH36vD4XaAF2CjiPsJWiY/j2xLsJuqx3JtuI4akH
# 0MmGzlBUylhXvdNVXcjAuIEcEQKtOBR9lU4wXQpISrbOT8ux+96GzBq8TdbhoFcm
# YaOBZKlwPP7pOp5Mzx/UMhyBA93PQhiCdPfIVOCINsUY4U23p4KJ3F1HqP3H6Slw
# 3lHACnLilGETXRg5X/Fp8G8qlG5Y+M49ZEGUp2bneRLZoyHTyynHvFISpefhBCV0
# KdRZHPcuSL5OAGWnBjAlRtHvsMBrI3AAA0Tu1oGvPa/4yeeiAyu+9y3SLC98gDVb
# ySnXnkujjhIh+oaatsk/oyf5R2vcxHahajMCAwEAAaOCAY4wggGKMB8GA1UdIwQY
# MBaAFF9Y7UwxeqJhQo1SgLqzYZcZojKbMB0GA1UdDgQWBBSIYYyhKjdkgShgoZsx
# 0Iz9LALOTzAOBgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8E
# DDAKBggrBgEFBQcDCDBKBgNVHSAEQzBBMDUGDCsGAQQBsjEBAgEDCDAlMCMGCCsG
# AQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQUzAIBgZngQwBBAIwSgYDVR0f
# BEMwQTA/oD2gO4Y5aHR0cDovL2NybC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGlj
# VGltZVN0YW1waW5nQ0FSMzYuY3JsMHoGCCsGAQUFBwEBBG4wbDBFBggrBgEFBQcw
# AoY5aHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0YW1w
# aW5nQ0FSMzYuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNv
# bTANBgkqhkiG9w0BAQwFAAOCAYEAAoE+pIZyUSH5ZakuPVKK4eWbzEsTRJOEjbIu
# 6r7vmzXXLpJx4FyGmcqnFZoa1dzx3JrUCrdG5b//LfAxOGy9Ph9JtrYChJaVHrus
# Dh9NgYwiGDOhyyJ2zRy3+kdqhwtUlLCdNjFjakTSE+hkC9F5ty1uxOoQ2ZkfI5WM
# 4WXA3ZHcNHB4V42zi7Jk3ktEnkSdViVxM6rduXW0jmmiu71ZpBFZDh7Kdens+PQX
# PgMqvzodgQJEkxaION5XRCoBxAwWwiMm2thPDuZTzWp/gUFzi7izCmEt4pE3Kf0M
# Ot3ccgwn4Kl2FIcQaV55nkjv1gODcHcD9+ZVjYZoyKTVWb4VqMQy/j8Q3aaYd/jO
# Q66Fhk3NWbg2tYl5jhQCuIsE55Vg4N0DUbEWvXJxtxQQaVR5xzhEI+BjJKzh3TQ0
# 26JxHhr2fuJ0mV68AluFr9qshgwS5SpN5FFtaSEnAwqZv3IS+mlG50rK7W3qXbWw
# i4hmpylUfygtYLEdLQukNEX1jiOKMIIGazCCBNOgAwIBAgIRAIxBnpO/K86siAYo
# O3YZvTwwDQYJKoZIhvcNAQEMBQAwVDELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1Nl
# Y3RpZ28gTGltaXRlZDErMCkGA1UEAxMiU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWdu
# aW5nIENBIFIzNjAeFw0yNDExMTQwMDAwMDBaFw0yNzExMTQyMzU5NTlaMFcxCzAJ
# BgNVBAYTAkRFMRYwFAYDVQQIDA1OaWVkZXJzYWNoc2VuMRcwFQYDVQQKDA5NYXJ0
# aW4gV2lsbGluZzEXMBUGA1UEAwwOTWFydGluIFdpbGxpbmcwggIiMA0GCSqGSIb3
# DQEBAQUAA4ICDwAwggIKAoICAQDRn27mnIzB6dsJFLMexQQNRd8aMv73DTla68G6
# Q8u+V2TY1JQ/Z4j2oCI9ATW3K3P7NAPdlE0QmtdjC0F/74jsfil/i8LwxuyT034w
# abViZKUcodmKsEFhM9am8W5kUgLuC5FIK4wNOq5TfzYdHTyJu1eR2XuSDoMp0wg4
# 5mOuFNBbYB8DVBtHxobvWq4eCs3lUxX07wR3Qr2Utb92w8eU2vKr2Ss9xIh/YvM4
# UxgBpO1I6O+W2tAB5mmynIgoCfX7mu6iD3A+AhpQ9Gv209G83y8FPrFJIWU77TTe
# hErbPjZ074xXwrlEkhnGUCk1w+KiNtZHaSn0X+vnhqJ7otBxQZQAESlhWXpDKCun
# nnVnVgwvVWtccAhxZO95eif6Vss/UhCaBZ26szlneGtFeTClI4+k3mqfWuodtXjH
# c8ohAclWp7XVywliwhCFEsAcFkpkCyivey0sqEfrwiMnRy1elH1S37XcQaav5+bt
# 4KxtIXuOVEx3vM9MHdlraW0y1on5E8i4tagdI45TH0LU080ubc2MKqq6ZXtplTu1
# wdF2Cgy3hfSSLkJscRWApvpvOO6Vtc4jTG/AO6iqN5M6Swd+g40XtsxBD/gSk9kM
# qkgJ1pD1Gp5gkHnP1veut+YgJ9xWcRDJI7vcis9qsXwtVybeOCh56rTQvC/Tf6BJ
# tiieEQIDAQABo4IBszCCAa8wHwYDVR0jBBgwFoAUDyrLIIcouOxvSK4rVKYpqhek
# zQwwHQYDVR0OBBYEFIxyZAmEHl7uAfEwbB4nzI8MCCLbMA4GA1UdDwEB/wQEAwIH
# gDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMEoGA1UdIARDMEEw
# NQYMKwYBBAGyMQECAQMCMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGlnby5j
# b20vQ1BTMAgGBmeBDAEEATBJBgNVHR8EQjBAMD6gPKA6hjhodHRwOi8vY3JsLnNl
# Y3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmluZ0NBUjM2LmNybDB5Bggr
# BgEFBQcBAQRtMGswRAYIKwYBBQUHMAKGOGh0dHA6Ly9jcnQuc2VjdGlnby5jb20v
# U2VjdGlnb1B1YmxpY0NvZGVTaWduaW5nQ0FSMzYuY3J0MCMGCCsGAQUFBzABhhdo
# dHRwOi8vb2NzcC5zZWN0aWdvLmNvbTAoBgNVHREEITAfgR1td2lsbGluZ0BsZXRo
# YWwtZm9yZW5zaWNzLmNvbTANBgkqhkiG9w0BAQwFAAOCAYEAZ0dBMMwluWGb+MD1
# rGWaPtaXrNZnlZqOZxgbdrMLBKAQr0QGcILCVIZ4SZYaevT5yMR6jFGSAjgaFtnk
# 8ZpbtGwig/ed/C/D1Ne8SZyffdtALns/5CHxMnU8ks7ut7dsR6zFD4/bmljuoUoi
# 55W6/XU/1pr+tqRaZGJvjSKJQCN9MhFAvXSpPPqRsj27ze1+KYIBF1/L0BW0HS0d
# 9ZhGSUoEwqMDLpQf2eqJFyyyzWt21VVhLF6mgZ1dE5tCLZY7ERzx6/h5N7F0w361
# oigizMbCMdST29XOc5mB8q6Cye7OmEfM2jByRWa+cd4RycsN2p2wHRukpq48iX+t
# PVKmHwNKf+upuKPDQAeV4J7gUCtevIsOtoyiC2+amimu81o424Dl+NsAyCLz0SXv
# NAhVvtU73H61gtoPa/SWouem2S+bzp7oGvGPop/9mh4CXki6LVeDH3hDM8hZsJg/
# EToIWiDozTc2yWqwV4Ozyd4x5Ix8lckXMgWuyWcxmLK1RmKpMIIGgjCCBGqgAwIB
# AgIQNsKwvXwbOuejs902y8l1aDANBgkqhkiG9w0BAQwFADCBiDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4w
# HAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVz
# dCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMjEwMzIyMDAwMDAwWhcN
# MzgwMTE4MjM1OTU5WjBXMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBM
# aW1pdGVkMS4wLAYDVQQDEyVTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFJv
# b3QgUjQ2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAiJ3YuUVnnR3d
# 6LkmgZpUVMB8SQWbzFoVD9mUEES0QUCBdxSZqdTkdizICFNeINCSJS+lV1ipnW5i
# hkQyC0cRLWXUJzodqpnMRs46npiJPHrfLBOifjfhpdXJ2aHHsPHggGsCi7uE0awq
# KggE/LkYw3sqaBia67h/3awoqNvGqiFRJ+OTWYmUCO2GAXsePHi+/JUNAax3kpqs
# tbl3vcTdOGhtKShvZIvjwulRH87rbukNyHGWX5tNK/WABKf+Gnoi4cmisS7oSimg
# HUI0Wn/4elNd40BFdSZ1EwpuddZ+Wr7+Dfo0lcHflm/FDDrOJ3rWqauUP8hsokDo
# I7D/yUVI9DAE/WK3Jl3C4LKwIpn1mNzMyptRwsXKrop06m7NUNHdlTDEMovXAIDG
# AvYynPt5lutv8lZeI5w3MOlCybAZDpK3Dy1MKo+6aEtE9vtiTMzz/o2dYfdP0KWZ
# wZIXbYsTIlg1YIetCpi5s14qiXOpRsKqFKqav9R1R5vj3NgevsAsvxsAnI8Oa5s2
# oy25qhsoBIGo/zi6GpxFj+mOdh35Xn91y72J4RGOJEoqzEIbW3q0b2iPuWLA911c
# RxgY5SJYubvjay3nSMbBPPFsyl6mY4/WYucmyS9lo3l7jk27MAe145GWxK4O3m3g
# EFEIkv7kRmefDR7Oe2T1HxAnICQvr9sCAwEAAaOCARYwggESMB8GA1UdIwQYMBaA
# FFN5v1qqK0rPVIDh2JvAnfKyA2bLMB0GA1UdDgQWBBT2d2rdP/0BE/8WoWyCAi/Q
# Cj0UJTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUEDDAK
# BggrBgEFBQcDCDARBgNVHSAECjAIMAYGBFUdIAAwUAYDVR0fBEkwRzBFoEOgQYY/
# aHR0cDovL2NybC51c2VydHJ1c3QuY29tL1VTRVJUcnVzdFJTQUNlcnRpZmljYXRp
# b25BdXRob3JpdHkuY3JsMDUGCCsGAQUFBwEBBCkwJzAlBggrBgEFBQcwAYYZaHR0
# cDovL29jc3AudXNlcnRydXN0LmNvbTANBgkqhkiG9w0BAQwFAAOCAgEADr5lQe1o
# RLjlocXUEYfktzsljOt+2sgXke3Y8UPEooU5y39rAARaAdAxUeiX1ktLJ3+lgxto
# LQhn5cFb3GF2SSZRX8ptQ6IvuD3wz/LNHKpQ5nX8hjsDLRhsyeIiJsms9yAWnvdY
# OdEMq1W61KE9JlBkB20XBee6JaXx4UBErc+YuoSb1SxVf7nkNtUjPfcxuFtrQdRM
# Ri/fInV/AobE8Gw/8yBMQKKaHt5eia8ybT8Y/Ffa6HAJyz9gvEOcF1VWXG8OMeM7
# Vy7Bs6mSIkYeYtddU1ux1dQLbEGur18ut97wgGwDiGinCwKPyFO7ApcmVJOtlw9F
# VJxw/mL1TbyBns4zOgkaXFnnfzg4qbSvnrwyj1NiurMp4pmAWjR+Pb/SIduPnmFz
# bSN/G8reZCL4fvGlvPFk4Uab/JVCSmj59+/mB2Gn6G/UYOy8k60mKcmaAZsEVkhO
# Fuoj4we8CYyaR9vd9PGZKSinaZIkvVjbH/3nlLb0a7SBIkiRzfPfS9T+JesylbHa
# 1LtRV9U/7m0q7Ma2CQ/t392ioOssXW7oKLdOmMBl14suVFBmbzrt5V5cQPnwtd3U
# OTpS9oCG+ZZheiIvPgkDmA8FzPsnfXW5qHELB43ET7HHFHeRPRYrMBKjkb8/IN7P
# o0d0hQoF4TeMM+zYAJzoKQnVKOLg8pZVPT8xggYxMIIGLQIBATBpMFQxCzAJBgNV
# BAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxKzApBgNVBAMTIlNlY3Rp
# Z28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYCEQCMQZ6TvyvOrIgGKDt2Gb08
# MAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3
# DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEV
# MCMGCSqGSIb3DQEJBDEWBBTBhztBcFTbZ7E/DCSkxqMyXbT06TANBgkqhkiG9w0B
# AQEFAASCAgAmQFciDhvHA9dzHbYvbUWOF+oWC1R+zwBfd5OOW3OxJKdnfA3uhIp2
# JzK9PpaKm1GO6qthRi1lz2MY3W8lNOwTZh5FhzYYAba4RnE5qAQhKlwUhf3Rb1qu
# O4X6GTAJMHuVNiaD3bU86hlhwgEHfeGWUjU2sU6G+qsltE3WKwkc+je3bmVT0fiH
# HgQxmvw5jJBUvwRqA2wVR9X/RzkfwVipAbTdO7N3Ss8PCbAY+lhkafDQcT/Q9jMc
# FL5/2aCxodWH3uN8MM/HtPQAAffxGzO6pIIa3wNVyykKQ4um5lSN/hPn3vnwg3K9
# HTxTWuHmk9R4Sz1vnbi9NLkRgucppx70FniRfgpTXE85PxNksscJfILt+aUFSdyZ
# Oxf51imU61hV0CRz4gOMHwsfALfE7SiOhKOfzKJHpRm+pKIrZWQcQsk5hlnaqzsr
# 2X/0TH1EUkbXW9mY+CD9fb8TCNz+phANikkC4xjRIoEB2yl+UYPKH/PMZriqfucA
# UhhzdvjaYO0UtVYhENQaY7J90EKbrHpRbtUoolPpsl7k1a3XSjdOu0tZNeubo1U4
# fRCFUHzJSt1xyFmC1Ss6xxFfa+JkReuHPDHD6KnjKepodcAxYRN/c/RNyLiaOheD
# 2bZDHpA2+807lWuTriFO2sIgMdTmS6Ok7BURMKoMQFCHYCzi/g5sSqGCAyMwggMf
# BgkqhkiG9w0BCQYxggMQMIIDDAIBATBqMFUxCzAJBgNVBAYTAkdCMRgwFgYDVQQK
# Ew9TZWN0aWdvIExpbWl0ZWQxLDAqBgNVBAMTI1NlY3RpZ28gUHVibGljIFRpbWUg
# U3RhbXBpbmcgQ0EgUjM2AhEApCk7bh7d16c0CIetek63JDANBglghkgBZQMEAgIF
# AKB5MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2
# MDYwMTA0NTg0NVowPwYJKoZIhvcNAQkEMTIEMGXyxf1My0XGFi/ooUBCBhIDJ0Bn
# jtRU8IZ9KoYjCfMWAvyJcU8HYkfx9m3po9EKRTANBgkqhkiG9w0BAQEFAASCAgDN
# N7xcEbGva/T8hvW27If4Wgeg40jzw3KxLGprABYXrzp1n7PRdjsyTlg+5TZWgxjy
# YechiolvG9x2Z4d3SW2JKJspOonGOx743Dt2w/myc2KhW6RQ54xbIqpXD72hbclk
# nRl2RDVgL/3taXA0kQL7Lxi/pTta19Thx1I9CKW2PbEhNDkH/3pmVC+w2x0rvZx5
# x1n877qjQ0e+Xl2HZr6HnE69SWqnq6il2oKDwdBFrCq0TTCeeZjlE9TxjAQVhrS7
# TGWiA6q/rbpd/yEDlnSfZwyhejN3lCpkNTpO3RBagp02LJsldKZA/wsF2OQju9jM
# FDy/wd6Ohx+VIrz8M4WIMDD1L4UTi30jQICyhgvOSFOU/7q/ImylD6X9JuDKK44T
# 5l1LwLHn58fRjeSftqyI5oJI8vP38vGMYqIVpAurjCVTxrinsHnHle2akYPJBjUK
# pZznNXG/dWEyHM19Sj4tl2PZzRJv4cXyXvGnOQwFvqESAPCs768orup1842DcOk4
# dVsV3efL3AQ8RZQZASiUnu340cr49Emzot7W68SN5gO6WqqWiQlAjZEApBFiw43e
# 0k85288/TgYGFDdCG4pOkPLgeLoGSlD42kYPG9Q7XN9x4fyd3GH+3JZ0SPsRPMNo
# 8plFYtB40f8FXWlkFC33nEqCtxkTQiInDK7SXOZwsg==
# SIG # End signature block
