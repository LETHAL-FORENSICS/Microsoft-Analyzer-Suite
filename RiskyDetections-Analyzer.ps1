# RiskyDetections-Analyzer
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
  RiskyDetections-Analyzer - Automated Processing of 'RiskyDetections.csv' (Microsoft-Extractor-Suite by Invictus-IR)

.DESCRIPTION
  RiskyDetections-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of the Risk Detections from the Entra ID Identity Protection extracted via "Microsoft-Extractor-Suite" by Invictus Incident Response.

  https://github.com/invictus-ir/Microsoft-Extractor-Suite (Microsoft-Extractor-Suite v4.1.0)

  https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/Azure/GetUserInfo.html#retrieves-the-risky-detections

.PARAMETER OutputDir
  Specifies the output directory. Default is "$env:USERPROFILE\Desktop\RiskyDetections-Analyzer".

  Note: The subdirectory 'RiskyDetections-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the CSV-based input file (*-RiskyDetections.csv).

.EXAMPLE
  PS> .\RiskyDetections-Analyzer.ps1

.EXAMPLE
  PS> .\RiskyDetections-Analyzer.ps1 -Path "$env:USERPROFILE\Desktop\*-RiskyDetections.csv"

.EXAMPLE
  PS> .\RiskyDetections-Analyzer.ps1 -Path "H:\Microsoft-Extractor-Suite\*-RiskyDetections.csv" -OutputDir "H:\Microsoft-Analyzer-Suite"

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
    $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\RiskyDetections-Analyzer" # Default
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
        $script:OUTPUT_FOLDER = "$OutputDir\RiskyDetections-Analyzer" # Custom
    }
}

# Tools

# IPinfo CLI
$script:IPinfo = "$SCRIPT_DIR\Tools\IPinfo\ipinfo.exe"

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
$Host.UI.RawUI.WindowTitle = "RiskyDetections-Analyzer - Automated Processing of 'RiskyDetections.csv' (Microsoft-Extractor-Suite by Invictus-IR)"

# Colors
Add-Type -AssemblyName System.Drawing
$script:Orange = [System.Drawing.Color]::FromArgb(255,192,0) # Orange
$script:Green  = [System.Drawing.Color]::FromArgb(0,176,80) # Green

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
        $OpenFileDialog.Filter = "Risky Detections|*-RiskyDetections.csv|All Files (*.*)|*.*"
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
Write-Output "RiskyDetections-Analyzer - Automated Processing of 'RiskyDetections.csv'"
Write-Output "(c) 2026 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
Write-Output ""

# Analysis date (ISO 8601)
$AnalysisDate = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "Analysis date: $AnalysisDate UTC"
Write-Output ""

# Create HashTable and import 'ASN-Blacklist.csv'
$script:AsnBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\ASN-Blacklist.csv")
{
    if(Test-Csv -Path "$SCRIPT_DIR\Blacklists\ASN-Blacklist.csv" -MaxLines 2)
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
    if(Test-Csv -Path "$SCRIPT_DIR\Blacklists\Country-Blacklist.csv" -MaxLines 2)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\Country-Blacklist.csv" -Delimiter "," | ForEach-Object { $CountryBlacklist_HashTable[$_.Country] = $_."Country Name" }

        # Count Ingested Properties
        $Count = $CountryBlacklist_HashTable.Count
        Write-Output "[Info]  Initializing 'Country-Blacklist.csv' Lookup Table ($Count) ..."
    }
}

# Create HashTable and import 'UserAgent-Blacklist.csv'
$script:UserAgentBlacklist_HashTable = New-Object System.Collections.Hashtable
if (Test-Path "$SCRIPT_DIR\Blacklists\UserAgent-Blacklist.csv")
{
    if(Test-Csv -Path "$SCRIPT_DIR\Blacklists\UserAgent-Blacklist.csv" -MaxLines 2)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\UserAgent-Blacklist.csv" -Delimiter "," | ForEach-Object { $UserAgentBlacklist_HashTable[$_.UserAgent] = $_.Category,$_.Severity }

        # Count Ingested Properties
        $Count = $UserAgentBlacklist_HashTable.Count
        Write-Output "[Info]  Initializing 'UserAgent-Blacklist.csv' Lookup Table ($Count) ..."
    }
}

#endregion Header

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Analysis

# Risky Detections include any identified suspicious actions related to user accounts in the directory.
# https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks

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

# Input Size
$InputSize = Get-FileSize((Get-Item "$LogFile").Length)
Write-Output "[Info]  Total Input Size: $InputSize"

# Count rows of CSV (w/ thousands separators)
$Count = 0
switch -File "$LogFile" { default { ++$Count } }
$Rows = '{0:N0}' -f $Count
Write-Output "[Info]  Total Lines: $Rows"

# Processing RiskyDetections.csv
Write-Output "[Info]  Processing RiskyDetections.csv ..."
New-Item "$OUTPUT_FOLDER" -ItemType Directory -Force | Out-Null

# Import CSV
$Data = Import-Csv -Path "$LogFile" -Delimiter "," | Sort-Object { $_.ActivityDateTime -as [datetime] } -Descending

# Time Frame
$Last  = ($Data | Select-Object -Last 1).ActivityDateTime
$First = ($Data | Select-Object -First 1).ActivityDateTime
$StartDate = (Get-Date $Last).ToString("yyyy-MM-dd HH:mm:ss")
$EndDate = (Get-Date $First).ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "[Info]  Log data from $StartDate UTC until $EndDate UTC"

# CSV
# https://learn.microsoft.com/en-us/graph/api/resources/riskdetection?view=graph-rest-1.0
# https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/v1.0/resources/riskdetection.md
# https://learn.microsoft.com/en-us/powershell/module/Microsoft.Graph.Beta.Identity.SignIns/Get-MgBetaRiskDetection?view=graph-powershell-beta
$Data = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Sort-Object { $_.ActivityDateTime -as [DateTime] } -Descending

$Results = [Collections.Generic.List[PSObject]]::new()
ForEach($Record in $Data)
{
    $AdditionalInfo = $Record.AdditionalInfo | ConvertFrom-Json

    # Data Enrichment w/ IPInfo
    $IPAddress   = $Record.IPAddress
    $Data        = & $IPinfo "$IPAddress" --json | ConvertFrom-Json
    $Country     = $Data.country
    $CountryName = $Data.country_name
    $ASN         = $Data | Select-Object -ExpandProperty org | ForEach-Object{($_ -split "\s+")[0]}
    $OrgName     = $Data | Select-Object -ExpandProperty org | ForEach-Object {$_ -replace "^AS[0-9]+ "}

    $Line = [PSCustomObject]@{
    "Activity"                    = $Record.Activity # Indicates the activity type the detected risk is linked to.
    "ActivityDateTime"            = (Get-Date $Record.ActivityDateTime).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
    "DetectedDateTime"            = (Get-Date $Record.DetectedDateTime).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
    "LastUpdatedDateTime"         = (Get-Date $Record.LastUpdatedDateTime).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
    "UserPrincipalName"           = $Record.UserPrincipalName # The user principal name (UPN) of the user.
    "UserDisplayName"             = $Record.UserDisplayName # The user principal name (UPN) of the user.
    "UserId"                      = $Record.UserId # Unique ID of the user.
    "mitreTechniques"             = ($AdditionalInfo | Where-Object {$_.Key -eq "mitreTechniques"}).Value
    "RiskDetail"                  = $Record.RiskDetail # Details of the detected risk.
    "RiskEventType"               = $Record.RiskEventType # The type of risk event detected.
    "RiskLevel"                   = $Record.RiskLevel # Level of the detected risk.
    "RiskReasons"                 = ($AdditionalInfo | Where-Object {$_.Key -eq "riskReasons"}).Value -join ","
    "RiskState"                   = $Record.RiskState # The state of a detected risky user or sign-in.
    "IPAddress"                   = $IPAddress # Provides the IP address of the client from where the risk occurred.
    "City"                        = $Record.City # Location of the sign-in.
    "State"                       = $Record.State # Location of the sign-in.
    "CountryOrRegion"             = $Record.CountryOrRegion # Location of the sign-in.
    "Country"                     = $Country
    "Country Name"                = $CountryName
    "ASN"                         = $ASN
    "OrgName"                     = $OrgName
    "DetectionTimingType"         = $Record.DetectionTimingType # Timing of the detected risk (real-time/offline).
    "Source"                      = $Record.Source # Source of the risk detection.
    "TokenIssuerType"             = $Record.TokenIssuerType # Indicates the type of token issuer for the detected sign-in risk. 
    "UserAgent"                   = ($AdditionalInfo | Where-Object {$_.Key -eq "userAgent"}).Value
    "AlertUrl"                    = ($AdditionalInfo | Where-Object {$_.Key -eq "alertUrl"}).Value # e.g. MicrosoftCloudAppSecurity
    "relatedEventTimeInUtc"       = ($AdditionalInfo | Where-Object {$_.Key -eq "relatedEventTimeInUtc"}).Value
    "relatedUserAgent"            = ($AdditionalInfo | Where-Object {$_.Key -eq "relatedUserAgent"}).Value
    "DeviceInformation"           = ($AdditionalInfo | Where-Object {$_.Key -eq "deviceInformation"}).Value
    "relatedLocation_clientIP"    = ($AdditionalInfo | Where-Object {$_.Key -eq "relatedLocation"}).Value | Select-Object -ExpandProperty clientIP
    "relatedLocation_latitude"    = ($AdditionalInfo | Where-Object {$_.Key -eq "relatedLocation"}).Value | Select-Object -ExpandProperty latitude
    "relatedLocation_longitude"   = ($AdditionalInfo | Where-Object {$_.Key -eq "relatedLocation"}).Value | Select-Object -ExpandProperty longitude
    "relatedLocation_asn"         = ($AdditionalInfo | Where-Object {$_.Key -eq "relatedLocation"}).Value | Select-Object -ExpandProperty asn
    "relatedLocation_countryCode" = ($AdditionalInfo | Where-Object {$_.Key -eq "relatedLocation"}).Value | Select-Object -ExpandProperty countryCode
    "relatedLocation_countryName" = ($AdditionalInfo | Where-Object {$_.Key -eq "relatedLocation"}).Value | Select-Object -ExpandProperty countryName
    "relatedLocation_state"       = ($AdditionalInfo | Where-Object {$_.Key -eq "relatedLocation"}).Value | Select-Object -ExpandProperty state
    "relatedLocation_city"        = ($AdditionalInfo | Where-Object {$_.Key -eq "relatedLocation"}).Value | Select-Object -ExpandProperty city
    "LastActivityTimeInUtc"       = ($AdditionalInfo | Where-Object {$_.Key -eq "lastActivityTimeInUtc"}).Value
    "MalwareName"                 = ($AdditionalInfo | Where-Object {$_.Key -eq "malwareName"}).Value
    "ClientLocation"              = ($AdditionalInfo | Where-Object {$_.Key -eq "clientLocation"}).Value
    "ClientIp"                    = ($AdditionalInfo | Where-Object {$_.Key -eq "clientIp"}).Value
    "Id"                          = $Record.Id # Unique ID of the risk event.
    "CorrelationId"               = $Record.CorrelationId # Correlation ID of the sign-in associated with the risk detection. 
    "RequestId"                   = $Record.RequestId # Request ID of the sign-in associated with the risk detection. This property is null if the risk detection is not associated with a sign-in.
    }

    $Results.Add($Line)
}

$Results | Export-Csv -Path "$OUTPUT_FOLDER\RiskyDetections.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Test-Path "$OUTPUT_FOLDER\RiskyDetections.csv")
{
    if(!([String]::IsNullOrWhiteSpace((Get-Content "$OUTPUT_FOLDER\RiskyDetections.csv"))))
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\RiskyDetections.csv" -Delimiter "," -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\RiskyDetections.xlsx" -NoNumberConversion * -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Risky Detections" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:AR1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-AR
        $WorkSheet.Cells["A:AR"].Style.HorizontalAlignment="Center"
        
        # ConditionalFormatting - MITRE ATT&CK Techniques
        Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("T1110.001",$H1)))' -BackgroundColor Red # Brute Force: Password Guessing --> https://attack.mitre.org/techniques/T1110/001/
        Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("T1110.003",$H1)))' -BackgroundColor Red # Brute Force: Password Spraying --> https://attack.mitre.org/techniques/T1110/003/
        Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("T1114.003",$H1)))' -BackgroundColor Red # Email Collection: Email Forwarding Rule --> https://attack.mitre.org/techniques/T1114/003/
        Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("T1539",$H1)))' -BackgroundColor Red # Steal Web Session Cookie --> https://attack.mitre.org/techniques/T1539/
        Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("T1564.008",$H1)))' -BackgroundColor Red # Hide Artifacts: Email Hiding Rules --> https://attack.mitre.org/techniques/T1564/008/
        Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("T1589.001",$H1)))' -BackgroundColor Red # Gather Victim Identity Information: Credentials --> https://attack.mitre.org/techniques/T1589/001/
        
        # ConditionalFormatting - RiskEventType
        Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("maliciousIPAddress",$J1)))' -BackgroundColor Red
        Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("mcasSuspiciousInboxManipulationRules",$J1)))' -BackgroundColor Red
        Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("nationStateIP",$J1)))' -BackgroundColor Red
        Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("passwordSpray",$J1)))' -BackgroundColor Red
        Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("unlikelyTravel",$J1)))' -BackgroundColor $Orange
        
        # ConditionalFormatting - RiskLevel
        Add-ConditionalFormatting -Address $WorkSheet.Cells["K:K"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("high",$K1)))' -BackgroundColor Red
        Add-ConditionalFormatting -Address $WorkSheet.Cells["K:K"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("medium",$K1)))' -BackgroundColor $Orange
        Add-ConditionalFormatting -Address $WorkSheet.Cells["K:K"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("low",$K1)))' -BackgroundColor Yellow
        Add-ConditionalFormatting -Address $WorkSheet.Cells["K:K"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("none",$K1)))' -BackgroundColor $Green
        
        # ConditionalFormatting - RiskState
        Add-ConditionalFormatting -Address $WorkSheet.Cells["M:M"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("atRisk",$M1)))' -BackgroundColor Red
        
        # ConditionalFormatting - CountryOrRegion
        foreach ($Country in $CountryBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$Q1)))' -f $Country
            Add-ConditionalFormatting -Address $WorkSheet.Cells["Q:Q"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # ConditionalFormatting - Country
        foreach ($Country in $CountryBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$R1)))' -f $Country
            Add-ConditionalFormatting -Address $WorkSheet.Cells["R:S"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # ConditionalFormatting - ASN
        foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$T1)))' -f $ASN
            Add-ConditionalFormatting -Address $WorkSheet.Cells["T:U"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        # ConditionalFormatting - UserAgent
        foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
        {
            $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$Y1)))' -f $UserAgent
            Add-ConditionalFormatting -Address $WorkSheet.Cells["Y:Y"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
        }

        # ConditionalFormatting - relatedLocation_countryCode
        foreach ($Country in $CountryBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AH1)))' -f $Country
            Add-ConditionalFormatting -Address $WorkSheet.Cells["AH:AH"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }
        
        }
    }
}

# Count Risky Detections
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Measure-Object).Count
$RiskyDetections = '{0:N0}' -f $Count

# Count Users
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object UserId -Unique | Measure-Object).Count
$Users = '{0:N0}' -f $Count

Write-Output "[Info]  $RiskyDetections Risky Detection(s) found ($Users Users)"

#############################################################################################################################################################################################

# Stats
New-Item "$OUTPUT_FOLDER\Stats" -ItemType Directory -Force | Out-Null

$RiskyDetections = Import-Csv -Path "$OUTPUT_FOLDER\RiskyDetections.csv" -Delimiter "," -Encoding UTF8 | Sort-Object { $_.ActivityDateTime -as [datetime] } -Descending

# Activity (Stats)
$Total = ($RiskyDetections | Select-Object Activity | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $RiskyDetections | Group-Object Activity | Select-Object @{Name='Activity'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\Activity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Activity" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# ASN (Stats)
$Total = ($RiskyDetections | Select-Object ASN | Where-Object {$_.ASN -ne '' } | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $RiskyDetections | Select-Object ASN,OrgName | Where-Object {$_.ASN -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object ASN,OrgName | Select-Object @{Name='ASN'; Expression={ $_.Values[0] }},@{Name='OrgName'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\ASN.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ASN" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-D
    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"

    # Iterating over the ASN-Blacklist HashTable
    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$A1)))' -f $ASN
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    }
}

# ClientIP / Country Name (Stats)
$Total = ($RiskyDetections | Select-Object IPAddress | Where-Object {$_.IPAddress -ne '' } | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $RiskyDetections | Select-Object IPAddress,Country,"Country Name",ASN,OrgName | Where-Object {$_.IPAddress -ne '' } | Where-Object {$_."Country Name" -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object IPAddress,Country,"Country Name",ASN,OrgName | Select-Object @{Name='IPAddress'; Expression={ $_.Values[0] }},@{Name='Country'; Expression={ $_.Values[1] }},@{Name='Country Name'; Expression={ $_.Values[2] }},@{Name='ASN'; Expression={ $_.Values[3] }},@{Name='OrgName'; Expression={ $_.Values[4] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\IPAddress.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "IPAddress" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-G
    $WorkSheet.Cells["A:G"].Style.HorizontalAlignment="Center"

    # Iterating over the ASN-Blacklist HashTable
    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$D1)))' -f $ASN
        Add-ConditionalFormatting -Address $WorkSheet.Cells["D:E"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    # Iterating over the Country-Blacklist HashTable
    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$B1)))' -f $Country
        Add-ConditionalFormatting -Address $WorkSheet.Cells["B:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }
                                    
    }
}

# Country / Country Name (Stats)
$Total = ($RiskyDetections | Select-Object Country | Where-Object {$_.Country -ne '' } | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $RiskyDetections | Select-Object Country,"Country Name" | Where-Object {$_.Country -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object Country,"Country Name" | Select-Object @{Name='Country'; Expression={ $_.Values[0] }},@{Name='Country Name'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\Country.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Countries" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-D
    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"

    # Iterating over the Country-Blacklist HashTable
    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$A1)))' -f $Country
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    }
}

# DetectionTimingType (Stats)
$Total = ($RiskyDetections | Select-Object DetectionTimingType | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $RiskyDetections | Group-Object DetectionTimingType | Select-Object @{Name='DetectionTimingType'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\DetectionTimingType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DetectionTimingType" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# MITRE ATT&CK Techniques (Stats)
# https://attack.mitre.org/matrices/enterprise/cloud/azuread/
# https://attack.mitre.org/matrices/enterprise/cloud/office365/
$Total = ($RiskyDetections | Select-Object mitreTechniques | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $RiskyDetections | Group-Object mitreTechniques | Select-Object @{Name='mitreTechniques'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\mitreTechniques.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MITRE ATT&CK" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    # ConditionalFormatting
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("T1110.001",$A1)))' -BackgroundColor Red # Brute Force: Password Guessing --> https://attack.mitre.org/techniques/T1110/001/
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("T1110.003",$A1)))' -BackgroundColor Red # Brute Force: Password Spraying --> https://attack.mitre.org/techniques/T1110/003/
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("T1114.003",$A1)))' -BackgroundColor Red # Email Collection: Email Forwarding Rule --> https://attack.mitre.org/techniques/T1114/003/
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("T1539",$A1)))' -BackgroundColor Red # Steal Web Session Cookie --> https://attack.mitre.org/techniques/T1539/
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("T1564.008",$A1)))' -BackgroundColor Red # Hide Artifacts: Email Hiding Rules --> https://attack.mitre.org/techniques/T1564/008/
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("T1589.001",$A1)))' -BackgroundColor Red # Gather Victim Identity Information: Credentials --> https://attack.mitre.org/techniques/T1589/001/
    }
}

# T1078     - Valid Accounts                                  --> https://attack.mitre.org/techniques/T1078/
# T1078.004 - Valid Accounts: Cloud Accounts                  --> https://attack.mitre.org/techniques/T1078/004/
# T1090.003 - Proxy: Multi-hop Proxy                          --> https://attack.mitre.org/techniques/T1090/003/
# T1110.001 - Brute Force: Password Guessing                  --> https://attack.mitre.org/techniques/T1110/001/
# T1110.003 - Brute Force: Password Spraying                  --> https://attack.mitre.org/techniques/T1110/003/
# T1114.003 - Email Collection: Email Forwarding Rule         --> https://attack.mitre.org/techniques/T1114/003/
# T1539     - Steal Web Session Cookie                        --> https://attack.mitre.org/techniques/T1539/
# T1564.008 - Hide Artifacts: Email Hiding Rules              --> https://attack.mitre.org/techniques/T1564/008/
# T1589.001 - Gather Victim Identity Information: Credentials --> https://attack.mitre.org/techniques/T1589/001/

# RiskEventType (Stats)
$Total = ($RiskyDetections | Select-Object RiskEventType | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $RiskyDetections | Group-Object RiskEventType | Select-Object @{Name='RiskEventType'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\RiskEventType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskEventType" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    # ConditionalFormatting
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("maliciousIPAddress",$A1)))' -BackgroundColor Red
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("mcasSuspiciousInboxManipulationRules",$A1)))' -BackgroundColor Red
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("passwordSpray",$A1)))' -BackgroundColor Red
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("unlikelyTravel",$A1)))' -BackgroundColor $Orange
    }
}

# RiskLevel (Stats)
# Note: hidden --> Microsoft Entra ID Premium P2 required.
$Total = ($RiskyDetections | Select-Object RiskLevel | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $RiskyDetections | Group-Object RiskLevel | Select-Object @{Name='RiskLevel'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\RiskLevel.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskLevel" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    # ConditionalFormatting - RiskLevel
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("high",$A1)))' -BackgroundColor Red
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("medium",$A1)))' -BackgroundColor $Orange
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("low",$A1)))' -BackgroundColor Yellow
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("none",$A1)))' -BackgroundColor $Green
    }
}

# RiskDetail (Stats)
# Note: hidden --> Microsoft Entra ID Premium P2 required.
$Total = ($RiskyDetections | Select-Object RiskDetail | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $RiskyDetections | Group-Object RiskDetail | Select-Object @{Name='RiskDetail'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\RiskDetail.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskDetail" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# Microsoft Entra ID Premium P2
$P2 = (($RiskyDetections | Where-Object { $_.RiskDetail -match "hidden" }) -or ($RiskyDetections | Where-Object { $_.RiskLevel -match "hidden" }))
if ($P2)
{
    Write-Output "[Info]  No Microsoft Entra ID Premium P2 found"
}

# RiskReasons (Stats)
$Total = ($RiskyDetections | Select-Object RiskReasons | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $RiskyDetections | Group-Object RiskReasons | Select-Object @{Name='RiskReasons'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\RiskReasons.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskReasons" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# RiskState (Stats)
$Total = ($RiskyDetections | Select-Object RiskState | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $RiskyDetections | Group-Object RiskState | Select-Object @{Name='RiskState'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\RiskState.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskState" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# remediated
# A remediated risk state in Microsoft Entra ID Protection means that a user has successfully taken actions to reduce their risk, such as completing multi-factor authentication (MFA) or changing their password. 
# This indicates that the user's account is now considered protected and the risk has been mitigated. 
# --> RiskDetail: User performed secured password reset

# Source (Stats)
$Total = ($RiskyDetections | Select-Object Source | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $RiskyDetections | Group-Object Source | Select-Object @{Name='Source'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\Source.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Source" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# UserAgent (Stats)
$Total = ($RiskyDetections | Select-Object UserAgent | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $RiskyDetections | Group-Object UserAgent | Select-Object @{Name='UserAgent'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\UserAgent.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserAgent" -CellStyleSB {
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

# Line Charts
New-Item "$OUTPUT_FOLDER\Stats\LineCharts" -ItemType Directory -Force | Out-Null

# Risk Detections (Line Chart) --> Risk Detections per day
$Import = $RiskyDetections | Group-Object{($_.ActivityDateTime -split "\s+")[0]} | Select-Object Count,@{Name='ActivityDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.ActivityDateTime -as [datetime] }
$ChartDefinition = New-ExcelChartDefinition -XRange ActivityDateTime -YRange Count -Title "Risk Detections" -ChartType Line -NoLegend -Width 1200
$Import | Export-Excel -Path "$OUTPUT_FOLDER\Stats\LineCharts\RiskDetections.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
 
# Risky Detections Count by User
$Total = ($RiskyDetections | Select-Object UserId | Measure-Object).Count
if ($Total -ge "1")
{
    $UPN = $RiskyDetections | Group-Object UserPrincipalName,UserId | Select-Object @{Name='UserPrincipalName'; Expression={ $_.Values[0] }},@{Name='UserId'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $UPN | Export-Excel -Path "$OUTPUT_FOLDER\Stats\UserPrincipalName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserPrincipalName" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns B-D
    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
    }
}

# Number of Risky Users with Risk Level "High" (Last 7 days)
$Date = (Get-Date).AddDays(-7)
$Count = ($RiskyDetections | Where-Object -FilterScript {[DateTime]::Parse($_.ActivityDateTime) -gt $Date}  | Where-Object { $_.RiskLevel -eq "high" } | Measure-Object).Count
if ($Count -gt 0)
{
    $HighRiskUsers = '{0:N0}' -f $Count
    Write-Host "[Alert] Number of High Risk Users (Last 7 days): $HighRiskUsers" -ForegroundColor Red
}

# Number of Risky Users with Risk Level "High" (Last 30 days)
$Date = (Get-Date).AddDays(-30)
$Count = ($RiskyDetections | Where-Object -FilterScript {[DateTime]::Parse($_.ActivityDateTime) -gt $Date}  | Where-Object { $_.RiskLevel -eq "high" } | Measure-Object).Count
if ($Count -gt 0)
{
    $HighRiskUsers = '{0:N0}' -f $Count
    Write-Host "[Alert] Number of High Risk Users (Last 30 days): $HighRiskUsers" -ForegroundColor Red
}

# Number of Risky Users with Risk Level "High" (Last 90 days)
$Date = (Get-Date).AddDays(-90)
$Count = ($RiskyDetections | Where-Object -FilterScript {[DateTime]::Parse($_.ActivityDateTime) -gt $Date}  | Where-Object { $_.RiskLevel -eq "high" } | Measure-Object).Count
if ($Count -gt 0)
{
    $HighRiskUsers = '{0:N0}' -f $Count
    Write-Host "[Alert] Number of High Risk Users (Last 90 days): $HighRiskUsers" -ForegroundColor Red
}

# Number of Risky Users with Risk Level "High" (Past 6 months)
$Date = (Get-Date).AddDays(-180)
$Count = ($RiskyDetections | Where-Object -FilterScript {[DateTime]::Parse($_.ActivityDateTime) -gt $Date}  | Where-Object { $_.RiskLevel -eq "high" } | Measure-Object).Count
if ($Count -gt 0)
{
    $HighRiskUsers = '{0:N0}' -f $Count
    Write-Host "[Alert] Number of High Risk Users (Past 6 months): $HighRiskUsers" -ForegroundColor Red
}

# Number of Risky Users with Risk Level "High" (Past 12 months)
$Date = (Get-Date).AddDays(-360)
$Count = ($RiskyDetections | Where-Object -FilterScript {[DateTime]::Parse($_.ActivityDateTime) -gt $Date}  | Where-Object { $_.RiskLevel -eq "high" } | Measure-Object).Count

if ($Count -gt 0)
{
    $HighRiskUsers = '{0:N0}' -f $Count
    Write-Host "[Alert] Number of High Risk Users (Past 12 months): $HighRiskUsers" -ForegroundColor Red
}
else
{
    Write-Host "[Info]  Number of High Risk Users (Past 12 months): 0" -ForegroundColor Green
}

# RiskState
$Import = $RiskyDetections | Where-Object { $_.RiskState -eq "atRisk" }
$Total = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
$Count = ($Import | Select-Object UserId -Unique | Measure-Object).Count
if ($Count -gt 0)
{
    Write-Host "[Alert] $Count User(s) whose Risk State is 'atRisk' detected ($Total)" -ForegroundColor Red
}

# MITRE ATT&CK Techniques

# T1110.001 - Brute Force: Password Guessing
# https://attack.mitre.org/techniques/T1110/001/
$Import = $RiskyDetections | Where-Object { $_.mitreTechniques -like "*T1110.001*" }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] MITRE ATT&CK T1110.001 - Brute Force: Password Guessing ($Count)" -ForegroundColor Red
}

# T1110.003 - Brute Force: Password Spraying
# https://attack.mitre.org/techniques/T1110/003/
$Import = $RiskyDetections | Where-Object { $_.mitreTechniques -like "*T1110.003*" }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] MITRE ATT&CK T1110.003 - Brute Force: Password Spraying ($Count)" -ForegroundColor Red
}

# T1539 - Steal Web Session Cookie (AiTM)
# https://attack.mitre.org/techniques/T1539/
$Import = $RiskyDetections | Where-Object { $_.mitreTechniques -like "*T1539*" }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] MITRE ATT&CK T1539 - Steal Web Session Cookie ($Count)" -ForegroundColor Red
}

# T1589.001 - Gather Victim Identity Information: Credentials
# https://attack.mitre.org/techniques/T1589/001/
$Import = $RiskyDetections | Where-Object { $_.mitreTechniques -like "*T1589.001*" }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] MITRE ATT&CK T1589.001 - Gather Victim Identity Information: Credentials ($Count)" -ForegroundColor Red
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
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUWzxGnc+mS4UnTw7hhmf8bnjn
# sSmggiYXMIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
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
# MRYEFGLxhao+lWwZonNWApvZtYhwSFkFMA0GCSqGSIb3DQEBAQUABIICAKLpJtAx
# +aHQZuz2+vM+BTFzTmypIdH4LmkMbj5K7JaLzC0goaLaukYGO3VyHlzd75YoeQAt
# 3sQQeld8nKn9TAxWcONTYOl+J0RMPAGGEi4krg6zjJhrrWROaaCS0+p1eRFsqJ/L
# k9GKTLJjx3ZeGuuFC3cC2tnvYVKQKL1Asnq7ghMbMLYQf58qVscv/KT4U8xoQ77P
# 4d60llRAIkjHNQNfSRxVWWYeZz9DoX+fZZhCXk8kVI2lvGN8D9UhvV4RuraF0rS2
# eT699Y0hzAfN1bQ93QBmBdaryZeT8lfs4r3svO0JS3I3jlpxhwVQlvKA6bS4slNW
# KdauhlMPmHGU1oHAdulWiSEOIpAA2zdQSZd6gk9pBUz4NeBe7Hagb/sUf2jEtnvG
# gws5GvNEdRxW9m24A3u0wWlDJw2C+MdOi7h/sPulbsmmK9b7GxMVIFyJjWhYUrnz
# bzGaqdF9xQ7Yp5jW0vobqVKeEst/iz88nJ4ytdm3iXhJDKI6adDfBNLPaZlk4f7X
# u06N9jRJYNHhTe6shppnAyjv64io5aLKH5TvkhAP5hiEYOq1b/V2Pec+ZTOflOaQ
# CG1HQubQZgwlzAj/lA8u2e/Gsy/t2YN5vr7/dzDojF3casbWbWeuT6d4zmClp4NY
# WfYu3w0aFQ2PyNoasaZlAA22g7/lR4wvgLD5oYIDIzCCAx8GCSqGSIb3DQEJBjGC
# AxAwggMMAgEBMGowVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGlt
# aXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBDQSBS
# NDECEQDnTvJVsFBP+tum3/f8i6MVMA0GCWCGSAFlAwQCAgUAoHkwGAYJKoZIhvcN
# AQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYwNzA2MTEzMTExWjA/
# BgkqhkiG9w0BCQQxMgQwsCmv5rTXEA+OmxjbhoREYv2YrkBS/tHzrU9zK6smpIxZ
# y1R9YjvRtRSdFN4CKcV8MA0GCSqGSIb3DQEBAQUABIICACuzzTxOjixzwQUWvtIo
# 2GodjJe02CG54Rvq2pCgGCn4UY5D2pBaKUQa7mhmM1/4pADbRZLAM3bIagBr4XOQ
# UCadaAO2mrEUvLq8S4V1tujbjG4SHMrRPjE7loIBwiQNTXC6egrKHl2Y+I6UJNcn
# NyxAFeASBXSeJFwYgS5v6vawsDZ8VYOqZmytvurlObPfnb5XaK38sA/HIYZs7p8n
# hssNQGIObYE4NXdi74SqhqmZWfFOuFUTB08Bbd/l5OZ7xnAHZ1/RT2o2JhDfUEuy
# 5Q8BtCXfYwz/Bw81RBxTG7gfYGBWBf7CjwYHX0pp/vJwCs5dsbUokljjZtsOyMzh
# xCVOAgbIXNs5Jkw0sO/9TB/iu3/+D6BrAhmX6uFJ8RI4M0D6WjGm0uLXDGcE5ORm
# FOyfQXp9JG9GUOCSEGQnKefaI8/8DS2L3SUXEOZDXTxYfpg6iWdW5CjFjVduXA+T
# 0novSi8myVP477Ayo9DQu4Ixwyn4Wz6u0deRmLxW66ttFoG+MAFn5Mx3zMIQWomH
# +kEIr8M0okZ+aRHUigwPRTw+ycpCZRybJHN353PlINaYiJfURaYBiDwydNmg5Zgj
# d7UhqJPAFClMhN7yqunTw8OPd0qTaMPcr3GeVBRfsdXT0fuwWl6kp1hDTVmwJGUu
# wNnK9Girp4Rp2V76jeQvASZx
# SIG # End signature block
