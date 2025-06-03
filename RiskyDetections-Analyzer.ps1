# RiskyDetections-Analyzer
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2025 Martin Willing. All rights reserved. Licensed under the MIT license.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2025-06-03
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
# IPinfo CLI 3.3.1 (2024-03-01)
# https://ipinfo.io/signup?ref=cli --> Sign up for free
# https://github.com/ipinfo/cli
#
#
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.5854) and PowerShell 5.1 (5.1.19041.5848)
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.5854) and PowerShell 7.5.1
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  RiskyDetections-Analyzer - Automated Processing of 'RiskyDetections.csv' (Microsoft-Extractor-Suite by Invictus-IR)

.DESCRIPTION
  RiskyDetections-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of the Risk Detections from the Entra ID Identity Protection extracted via "Microsoft-Extractor-Suite" by Invictus Incident Response.

  https://github.com/invictus-ir/Microsoft-Extractor-Suite (Microsoft-Extractor-Suite v3.0.4)

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
Write-Output "(c) 2025 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
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
$script:UserAgentBlacklist_HashTable = [ordered]@{}
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
    Write-Host "[Error] No IPinfo CLI Access Token provided. Please add your personal access token to 'Config.ps1'" -ForegroundColor Red
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
    "ActivityDateTime"            = ($Record | Select-Object @{Name="ActivityDateTime";Expression={([DateTime]::ParseExact($_.ActivityDateTime, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}}).ActivityDateTime # Date and time that the risky activity occurred (UTC). 
    "DetectedDateTime"            = ($Record | Select-Object @{Name="DetectedDateTime";Expression={([DateTime]::ParseExact($_.DetectedDateTime, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}}).DetectedDateTime # Date and time that the risk was detected.
    "LastUpdatedDateTime"         = ($Record | Select-Object @{Name="LastUpdatedDateTime";Expression={([DateTime]::ParseExact($_.LastUpdatedDateTime, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}}).LastUpdatedDateTime # Date and time that the risk detection was last updated.
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
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:AR1"] -BackgroundColor $BackgroundColor -FontColor White
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
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
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
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
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
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
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
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
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
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
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
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
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
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
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
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
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
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
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
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
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
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
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
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
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
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
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
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
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
# MIIrywYJKoZIhvcNAQcCoIIrvDCCK7gCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUnrHtPotACn5d2dwA7AEdh98s
# WVeggiUEMIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
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
# MCMGCSqGSIb3DQEJBDEWBBT7i91ZZkHByo+4RxEzd8Ql+JRYejANBgkqhkiG9w0B
# AQEFAASCAgCOVo8S8Pd/THbHgLiNd8MPZicE+BSSCksvCMscumNhem7JnlukFBQ8
# tUBpxPU80Ycse5UifE8osC8QWPdNsNifiVa86bTLcbvM7OMj5yEW+6LKXspnze/n
# CUZ6omUDJT5iTgKd019akyFwSshiksE+22kWQ6jG+guGb2u7SClM2MgfnUZQChjZ
# TM/8ZSBfqJS8Yo7JMToavllVfQJJ8w/yFy7XVgywhAw4RWmTZy1t/sQL4TwZ5K2g
# ImXha4umgSBvwdTiW6i+Ww/1gqbjk0/6pGB+F4zvB2Ixx32v6leMgvnrYnSOgukR
# x1cyOiQIv3EXUMfCKj/DF8klGT7wjRzQ382UwlljbKHBX5MALoez0Num5cPPbfmG
# y8Tu3/RNDrXrjpvYhNmNPzu7SZ5AZkzvMqe/EQicR3/+uzYjW7lrQo65AtXaPIfj
# rCvEZq1njrdW3t38janlGl0D/tV8PxJLnz0Kry4NqEBFX83V8ttln6Bd9oBmmdm6
# 9yNmz9PE//1XebW/5i9MscKM1jil4rYACkGvNshJ35Y83M8Pv9Sth4ZWyNFP/Dng
# wleCRt6O9vQV9IBuSWQKFb92kjT6g0u2O4Wk7Yl//pe96n163WkzNO5E4Z+GxMB7
# nZ1Wi8Dwy2X6bkCrgeN7ir6yEhewZzhWl9vAtmJ20e7EP/g4Vyv+PqGCAyMwggMf
# BgkqhkiG9w0BCQYxggMQMIIDDAIBATBqMFUxCzAJBgNVBAYTAkdCMRgwFgYDVQQK
# Ew9TZWN0aWdvIExpbWl0ZWQxLDAqBgNVBAMTI1NlY3RpZ28gUHVibGljIFRpbWUg
# U3RhbXBpbmcgQ0EgUjM2AhEApCk7bh7d16c0CIetek63JDANBglghkgBZQMEAgIF
# AKB5MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MDYwMzA3NDU1OFowPwYJKoZIhvcNAQkEMTIEMKiyjbw0+SOYVjljTK9FT1iiwdZd
# hYNLZ0CUo/vTuDlFW4spzA+bAaoSqyJyjrGtSzANBgkqhkiG9w0BAQEFAASCAgBN
# Z8MURVhV5kjNJvXWStsKPFIwmRcg+Nf6k4V+F9ZJ/192ZV91feFWzTUGBHVcgiGr
# EvRaTmEM4akEOY9VB/H4cSpoDGDSlr7yJxAT6l1XxLL/+b8TBvHjq3U3wlY/nlYf
# cyFvTVurD2dsc6hT3h25g4p/GIRzRBW5bdCW7NdhzIz24msxa/J/8nn4fn7WYZ03
# KmFzFEEXtUQLph0mVVRvqDgEjA4nnXrTzssFYu38qF9W+zkD8SBaDCdmxtvSc9zN
# hSd3rTp/V8/JPNQdBZJuCMfZag6OzBQ9yqMZaQGpZcPg4RC1BwQRS0aXHp+g2HDU
# +tFWVuk3S8mwt99CHcxya/q9HLt02eqb9j7rgILwPlTc0McQD/+mO1ybPfMFMTv2
# vInHWnI7RKJLeKOn9MO0z96wrVPno3AVvtRGsn5QbejnFmZ1Bja112N9z/cZfo5Q
# 0a/TRcxTxX6Lmu/1vxOKoDCmpaMqUnGMGS+2dbaCKWAHpUxGkynW5dWW5wUOWBuc
# 5B+U0gkFRA64UlD4bfcwyp0YJlHIkmG0/EIZrse0q2JFBE6zEfP6SzqVauyfx68S
# UA6/wbT46IS6vEY8hJwINcw3RULhzLzMbJnVl5iHsQpRkDGbS7rs58FN0eJYwP3N
# EL1PYodzZW2nVheAIqeSZnhQlvnWEFBuPuYe2KFL+w==
# SIG # End signature block
