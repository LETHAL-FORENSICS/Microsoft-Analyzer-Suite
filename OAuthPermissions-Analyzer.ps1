# OAuthPermissions-Analyzer
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2025 Martin Willing. All rights reserved. Licensed under the MIT license.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2025-05-15
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
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.5737) and PowerShell 5.1 (5.1.19041.5737)
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.5737) and PowerShell 7.5.1
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  OAuthPermissions-Analyzer - Automated Processing of M365 OAuth Permissions for DFIR

.DESCRIPTION
  OAuthPermissions-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of M365 OAuth Permissions extracted via "Microsoft Extractor Suite" by Invictus Incident Response.

  https://github.com/invictus-ir/Microsoft-Extractor-Suite (Microsoft-Extractor-Suite v3.0.3)

  https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/Azure/OAuthPermissions.html

  List delegated permissions (OAuth2PermissionGrants) and application permissions (AppRoleAssignments).

  Note: Get-OAuthPermissionGraph (Microsoft Graph)

.PARAMETER OutputDir
  Specifies the output directory. Default is "$env:USERPROFILE\Desktop\OAuthPermissions-Analyzer".

  Note: The subdirectory 'OAuthPermissions-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the CSV-based input file (*-OAuthPermissions.csv).

.EXAMPLE
  PS> .\OAuthPermissions-Analyzer.ps1

.EXAMPLE
  PS> .\OAuthPermissions-Analyzer.ps1 -Path "$env:USERPROFILE\Desktop\*-OAuthPermissions.csv"

.EXAMPLE
  PS> .\OAuthPermissions-Analyzer.ps1 -Path "H:\Microsoft-Extractor-Suite\*-OAuthPermissions.csv" -OutputDir "H:\Microsoft-Analyzer-Suite"

.NOTES
  Author - Martin Willing

.LINK
  https://lethal-forensics.com/
#>

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# Incident Response Checklist (Source: Invictus Incident Response)

# Use this checklist to remediate and recover from Azure App related incidents!

# - Identify the affected user accounts and applications: Determine which user accounts and applications were involved in the security incident.
# - Disable affected user accounts: Disable the user accounts associated with the security incident to prevent further unauthorized access.
# - Revoke application access: Revoke access to the affected applications for the disabled user accounts.
# - Review application permissions: Review the permissions granted to the affected applications and remove any unnecessary permissions.
# - Reset application credentials: Reset any credentials, such as passwords or secrets, for the affected applications.
# - Monitor for suspicious activity: Monitor the affected applications for any suspicious activity that could indicate ongoing security threats.
# - Investigate the security incident: Conduct a thorough investigation of the security incident to identify any vulnerabilities that need to be addressed to prevent similar incidents in the future.
# - Implement remediation measures: Implement remediation measures based on the findings of the investigation to address any security weaknesses and prevent future incidents.

# By following these steps, you can effectively revoke access for Azure applications after a security incident and take appropriate measures to protect your organization's data and resources.

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

# Colors
Add-Type -AssemblyName System.Drawing
$script:HighColor   = [System.Drawing.Color]::FromArgb(255,0,0) # Red
$script:MediumColor = [System.Drawing.Color]::FromArgb(255,192,0) # Orange
$script:LowColor    = [System.Drawing.Color]::FromArgb(255,255,0) # Yellow
$script:Green       = [System.Drawing.Color]::FromArgb(0,176,80) # Green

# Output Directory
if (!($OutputDir))
{
    $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\OAuthPermissions-Analyzer" # Default
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
        $script:OUTPUT_FOLDER = "$OutputDir\OAuthPermissions-Analyzer" # Custom
    }
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
    Write-Host "[Info]  Check out: https://github.com/evild3ad/Microsoft-Analyzer-Suite/wiki#setup"
    Exit
}

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "OAuthPermissions-Analyzer - Automated Processing of M365 OAuth Permissions for DFIR"

# Check if Microsoft Excel is running and stop all instances
$ProcessName = "EXCEL"
$Process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
if($Process)
{    
    Stop-Process -Id $Process.Id -Force
    Start-Sleep -Milliseconds 500
}

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

# Function Get-ScopeLink by Merill Fernando (@merill)
Function Get-ScopeLink($Scope) {
    if ([string]::IsNullOrEmpty($Scope)) { return $Scope }
    return "=HYPERLINK(`"https://graphpermissions.merill.net/permission/$Scope`",`"Link`")"
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
        $OpenFileDialog.Filter = "OAuthPermissions|*-OAuthPermissions.csv|All Files (*.*)|*.*"
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
Write-Output "OAuthPermissions-Analyzer - Automated Processing of M365 OAuth Permissions for DFIR"
Write-Output "(c) 2025 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
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
    if(Test-Csv -Path "$SCRIPT_DIR\Blacklists\Application-Blacklist.csv" -MaxLines 2)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\Application-Blacklist.csv" -Delimiter "," | ForEach-Object { $ApplicationBlacklist_HashTable[$_.AppId] = $_.AppDisplayName,$_.Severity }

        # Count Ingested Properties
        $Count = $ApplicationBlacklist_HashTable.Count
        Write-Output "[Info]  Initializing 'Application-Blacklist.csv' Lookup Table ($Count) ..."
    }
}

# Create HashTable and import 'ApplicationPermission-Blacklist.csv'
$script:ApplicationPermissionBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\ApplicationPermission-Blacklist.csv")
{
    if(Test-Csv -Path "$SCRIPT_DIR\Blacklists\ApplicationPermission-Blacklist.csv" -MaxLines 2)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\ApplicationPermission-Blacklist.csv" -Delimiter "," | ForEach-Object { $ApplicationPermissionBlacklist_HashTable[$_.Permission] = $_.DisplayText,$_.Severity }

        # Count Ingested Properties
        $Count = $ApplicationPermissionBlacklist_HashTable.Count
        Write-Output "[Info]  Initializing 'ApplicationPermission-Blacklist.csv' Lookup Table ($Count) ..."
    }
}

# Create HashTable and import 'DelegatedPermission-Blacklist.csv'
$script:DelegatedPermissionBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\DelegatedPermission-Blacklist.csv")
{
    if(Test-Csv -Path "$SCRIPT_DIR\Blacklists\DelegatedPermission-Blacklist.csv" -MaxLines 2)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\DelegatedPermission-Blacklist.csv" -Delimiter "," | ForEach-Object { $DelegatedPermissionBlacklist_HashTable[$_.Permission] = $_.DisplayText,$_.Severity }

        # Count Ingested Properties
        $Count = $DelegatedPermissionBlacklist_HashTable.Count
        Write-Output "[Info]  Initializing 'DelegatedPermission-Blacklist.csv' Lookup Table ($Count) ..."
    }
}

#endregion Header

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Analysis

# What is OAuth?
# OAuth is open source standard that is used by web platforms to grant other platforms access to your environment. Entra ID uses OAuth to allow third party applications to integrate with your Microsoft 365 environment.

# OAuth Permissions

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

# Processing OAuth Permissions
Write-Output "[Info]  Processing M365 OAuth Permissions ..."
New-Item "$OUTPUT_FOLDER\OAuthPermissions" -ItemType Directory -Force | Out-Null

# Custom CSV
$Data = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Sort-Object { $_.CreatedDateTime -as [datetime] } -Descending

# https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0#properties
# https://learn.microsoft.com/en-us/graph/api/resources/oauth2permissiongrant?view=graph-rest-1.0#properties
# https://learn.microsoft.com/en-us/graph/api/resources/approleassignment?view=graph-rest-1.0#properties
# https://learn.microsoft.com/en-us/graph/api/resources/application?view=graph-rest-1.0#properties

$Results = [Collections.Generic.List[PSObject]]::new()
ForEach($Record in $Data)
{
    $Description = ($Record | Select-Object @{Name='Description';Expression={if($_.Description){$_.Description}else{Get-ScopeLink $_.Permission}}}).Description
    $SignInAudience = ($Record | Select-Object @{Name='SignInAudience';Expression={if($_.SignInAudience){$_.SignInAudience}else{'N/A'}}}).SignInAudience

    $Line = [PSCustomObject]@{
    "CreatedDateTime"        = $Record | Select-Object -ExpandProperty CreationTimestamp | ForEach-Object {$_ -replace 'T',' '} | ForEach-Object {$_ -replace 'Z'} # The time when the app role assignment was created. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time.
    "PermissionType"         = $Record.PermissionType # Delegated access (access on behalf of a user) or App-only access (Access without a user) 
    "AppDisplayName"         = $Record.AppDisplayName # The display name exposed by the associated application.
    "AppId"                  = $Record.AppId # The unique identifier for the associated application.
    "ClientObjectId"         = $Record.ClientObjectId # The object id (not AppId) of the client service principal for the application that's authorized to act on behalf of a signed-in user when accessing an API.
    "ResourceDisplayName"    = $Record.ResourceDisplayName # The display name of the resource app's service principal to which the assignment is made.
    "ResourceId"             = $Record.ResourceObjectId # The id of the resource service principal to which access is authorized. This identifies the API that the client is authorized to attempt to call on behalf of a signed-in user.
    "Permission"             = $Record.Permission
    "Description"            = $Description
    "ConsentType"            = $Record.ConsentType # Indicates if authorization is granted for the client application to impersonate all users or only a specific user. AllPrincipals indicates authorization to impersonate all users. Principal indicates authorization to impersonate a specific user. Consent on behalf of all users can be granted by an administrator. Nonadmin users might be authorized to consent on behalf of themselves in some cases, for some delegated permissions.
    "PrincipalDisplayName"   = $Record.PrincipalDisplayName # The display name of the user, group, or service principal that was granted the app role assignment.
    "PrincipalId"            = $Record.PrincipalObjectId # The id of the user on behalf of whom the client is authorized to access the resource, when consentType is Principal. If consentType is AllPrincipals this value is null. Required when consentType is Principal.
    "PublisherName"          = $Record.PublisherName
    "ExpiryTime"             = $Record.ExpiryTime
    "AppOwnerOrganizationId" = $Record.AppOwnerOrganizationId # Contains the tenant ID where the application is registered.
    "ApplicationStatus"      = $Record.ApplicationStatus # true if the service principal account is enabled; otherwise, false. If set to false, then no users are able to sign in to this app, even if they're assigned to it.
    "ApplicationVisibility"  = $Record.ApplicationVisibility # Hidden for the user (e.g My Apps Portal --> https://myapps.microsoft.com/)
    "AssignmentRequired"     = $Record.AssignmentRequired # Specifies whether users or other service principals need to be granted an app role assignment for this service principal before users can sign in or apps can get tokens.
    "IsAppProxy"             = $Record.IsAppProxy # Microsoft Entra ID has an application proxy service that enables users to access on-premises applications by signing in with their Microsoft Entra account.
    "PublisherDisplayName"   = $Record.PublisherDisplayName # The verified publisher name from the app publisher's Partner Center account.
    "PublisherId"            = $Record.VerifiedPublisherId # The ID of the verified publisher from the app publisher's Partner Center account.
    "LastUpdated"            = $Record.AddedDateTime # The timestamp when the verified publisher was first added or most recently updated.
    "SignInAudience"         = $SignInAudience # Specifies the Microsoft accounts that are supported for the current application. Read-only.
    "ApplicationType"        = $Record.ApplicationType # Identifies whether the service principal represents an application, a managed identity, or a legacy application. This is set by Microsoft Entra ID internally.
    "Homepage"               = $Record.Homepage # Home page or landing page of the application.
    "ReplyUrls"              = $Record.ReplyUrls # The URLs that user tokens are sent to for sign in with the associated application, or the redirect URIs that OAuth 2.0 authorization codes and access tokens are sent to for the associated application.
    "IsEnabled"              = $Record.IsEnabled
    }

    $Results.Add($Line)
}

# "PermissionType","AppId","ClientDisplayName","ClientObjectId","ResourceDisplayName","ResourceObjectId","Permission","ConsentType","PrincipalObjectId","Homepage","PublisherName","ReplyUrls","ExpiryTime","PrincipalDisplayName","IsEnabled","Description","CreationTimestamp"

$Results | Export-Csv -Path "$OUTPUT_FOLDER\OAuthPermissions\OAuthPermissions.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Test-Path "$OUTPUT_FOLDER\OAuthPermissions\OAuthPermissions.csv")
{
    if(Test-Csv -Path "$OUTPUT_FOLDER\OAuthPermissions\OAuthPermissions.csv" -MaxLines 2)
    {
        $Import = Import-Csv -Path "$OUTPUT_FOLDER\OAuthPermissions\OAuthPermissions.csv" -Delimiter "," -Encoding UTF8

        # LETHAL-001: AppDisplayName with only non-alphanumeric characters
        [array]$RegEx01 = $Import | Where-Object { $_.AppDisplayName -match "^[^a-zA-Z0-9]+$" } | Select-Object -ExpandProperty AppDisplayName
        $Count = ($RegEx01 | Select-Object AppId -Unique | Measure-Object).Count
        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious OAuth Application detected: AppDisplayName w/ only non-alphanumeric characters ($Count)" -ForegroundColor Red
        }

        # LETHAL-002: Anomalous ReplyUrls including a local loopback URL
        [array]$RegEx02 = $Import | Where-Object { $_.ReplyUrls -match "http://localhost:\d+/access/?" } | Select-Object -ExpandProperty ReplyUrls
        $Count = ($RegEx02 | Select-Object AppId -Unique | Measure-Object).Count
        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious OAuth Application detected: Anomalous ReplyUrl including a local loopback URL ($Count)" -ForegroundColor Red
        }

        # LETHAL-003: Common Naming Patterns of Malicious OAuth Applications
        [array]$RegEx03 = $Import | Where-Object { $_.AppDisplayName -match "^(test|test app|app test|apptest)$" } | Select-Object -ExpandProperty AppDisplayName
        $Count = ($RegEx03 | Select-Object AppId -Unique | Measure-Object).Count
        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious OAuth Application detected: Common Naming Pattern of Malicious OAuth Applications ($Count)" -ForegroundColor Red
        }

        # LETHAL-004: UPN Naming Pattern (incl. B2B Collaboration User)
        [array]$RegEx04 = $Import | Where-Object { $_.AppDisplayName -match "^([\w-\.]+)(#EXT#)?@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([\w-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$" } | Select-Object -ExpandProperty AppDisplayName
        $Count = ($RegEx04 | Select-Object AppId -Unique | Measure-Object).Count
        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious OAuth Application detected: UPN Naming Pattern ($Count)" -ForegroundColor Red
        }

        # LETHAL-005: User Naming Pattern (PrincipalDisplayName)
        [array]$PrincipalDisplayNames = $Import | Where-Object {$_.PrincipalDisplayName -ne ""} | Select-Object -ExpandProperty PrincipalDisplayName -Unique
        $Principals = @()
        foreach ($PrincipalDisplayName in $PrincipalDisplayNames)
        {
            $Principals += $Import | Where-Object { $_.AppDisplayName -eq "$PrincipalDisplayName" } | Select-Object -ExpandProperty AppDisplayName -Unique
        }

        $Count = ($Principals | Select-Object AppId -Unique | Measure-Object).Count
        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious OAuth Application detected: User Naming Pattern ($Count)" -ForegroundColor Red
        }

        $Import | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\OAuthPermissions.xlsx" -NoHyperLinkConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "OAuthPermissions" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:Z1"] -BackgroundColor $BackgroundColor -FontColor White
        # HorizontalAlignment "Center" of columns A-Y
        $WorkSheet.Cells["A:Y"].Style.HorizontalAlignment="Center"

        # Font Style "Underline" of column I (Link)
        Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Link",$I1)))' -Underline

        # ConditionalFormatting - AppDisplayName
        Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("LethalForensics_IR-App",$C1)))' -BackgroundColor $Green

        foreach ($AppDisplayName in $RegEx01) 
        {
            $ConditionValue = 'EXACT("{0}",$C1)' -f $AppDisplayName
            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx01
        }

        foreach ($AppDisplayName in $RegEx03) 
        {
            $ConditionValue = 'EXACT("{0}",$C1)' -f $AppDisplayName
            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx03
        }

        foreach ($AppDisplayName in $RegEx04) 
        {
            $ConditionValue = 'EXACT("{0}",$C1)' -f $AppDisplayName
            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx04
        }

        foreach ($PrincipalDisplayName in $PrincipalDisplayNames)
        {
            $ConditionValue = 'EXACT("{0}",$C1)' -f $PrincipalDisplayName
            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # PrincipalDisplayName
        }

        # ConditionalFormatting - AppId
        Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("fb4c470b-9133-42c7-8db0-f786adc04715",$D1)))' -BackgroundColor $Green # Invictus Cloud Insights

        # ConditionalFormatting - AppOwnerOrganizationId
        Add-ConditionalFormatting -Address $WorkSheet.Cells["O:O"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("72f988bf-86f1-41af-91ab-2d7cd011db47",$O1)))' -BackgroundColor $Green # Microsoft Application
        Add-ConditionalFormatting -Address $WorkSheet.Cells["O:O"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("f8cdef31-a31e-4b4a-93e4-5f571e91255a",$O1)))' -BackgroundColor $Green # Microsoft Application

        # ConditionalFormatting - PublisherName
        Add-ConditionalFormatting -Address $WorkSheet.Cells["T:T"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("eM Client s.r.o.",$T1)))' -BackgroundColor Red # eM Client

        # ConditionalFormatting - ReplyUrls
        foreach ($ReplyUrl in $RegEx02) 
        {
            $ConditionValue = 'EXACT("{0}",$Z1)' -f $ReplyUrl
            Add-ConditionalFormatting -Address $WorkSheet.Cells["Z:Z"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx02
        }

        # LETHAL-006: Iterating over the Application-Blacklist HashTable
        foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
        {
            $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$D1)))' -f $AppId
            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
        }

        # Iterating over the Application-Blacklist HashTable
        [int]$Matches = "0"
        foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
        {
            $Count = ($Import | Where-Object { $_.AppId -eq "$AppId" } | Measure-Object).Count
            if ($Count -gt 0)
            {
                $Matches++
                $AppDisplayName = $ApplicationBlacklist_HashTable["$AppId"][0]
                $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                Write-Host "[Alert] Suspicious OAuth Application detected: $AppDisplayName ($Count)" -ForegroundColor $Severity
            }
        }

        # Count Matches
        if ($Matches -eq "0") 
        {
            Write-Host "[Info]  No blacklisted Application (Traitorware) found." -ForegroundColor Green
        }

        # Iterating over the ApplicationPermission-Blacklist HashTable
        foreach ($Permission in $ApplicationPermissionBlacklist_HashTable.Keys) 
        {
            $Severity = $ApplicationPermissionBlacklist_HashTable["$Permission"][1]
            if ($Severity -eq "High"){$BackgroundColor = $HighColor}
            if ($Severity -eq "Medium"){$BackgroundColor = $MediumColor}
            if ($Severity -eq "Low"){$BackgroundColor = $LowColor}
            $ConditionValue = '=AND($B1="Application",$H1="{0}")' -f $Permission
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $BackgroundColor
        }

        # Iterating over the DelegatedPermission-Blacklist HashTable
        foreach ($Permission in $DelegatedPermissionBlacklist_HashTable.Keys) 
        {
            $Severity = $DelegatedPermissionBlacklist_HashTable["$Permission"][1]
            if ($Severity -eq "High"){$BackgroundColor = $HighColor}
            if ($Severity -eq "Medium"){$BackgroundColor = $MediumColor}
            if ($Severity -eq "Low"){$BackgroundColor = $LowColor}
            $ConditionValue = '=AND($B1="Delegated",$H1="{0}")' -f $Permission
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $BackgroundColor
        }

        }
    }
}

# OAuthApps
$ClientObjectId = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object ClientObjectId -Unique | Measure-Object).Count
$ClientObjectIdCount = '{0:N0}' -f $ClientObjectId
$AppDisplayName = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object AppDisplayName -Unique | Measure-Object).Count
$AppDisplayNameCount = '{0:N0}' -f $AppDisplayName
Write-Output "[Info]  $ClientObjectIdCount OAuth Applications found (AppDisplayName: $AppDisplayNameCount)"

# PermissionType
[int]$Delegated = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.PermissionType -eq "Delegated" } | Measure-Object).Count
[int]$Application = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.PermissionType -eq "Application" } | Measure-Object).Count
$DelegatedCount = '{0:N0}' -f $Delegated
$ApplicationCount = '{0:N0}' -f $Application
Write-Output "[Info]  $DelegatedCount Delegated Permissions and $ApplicationCount Application Permissions found"

# Application Permissions (AppRoleAssignments) vs. Delegated Permissions (OAuth2PermissionGrants)
# Microsoft 365 has two types of OAuth permissions: application permissions and delegated permissions. They often have similar or even identical names, but the difference is important because the scope of each permission type varies considerably.
# - Application permissions grant tenant-wide access to the permission requested. For example, an app that has been granted the application permissions Mail.Read and Files.Read.All can read all user mail and read all files. For obvious reasons, application permissions can only be granted by an admin.
# - Delegated Permissions grant the app access as that user within the confines of the permissions requested. For example, an app that has been granted the delegated permission Mail.Read can read the mail of the user who consented to the app.

# By default in Microsoft Entra ID, all users can register applications and manage all aspects of applications they create. Everyone also has the ability to consent to apps accessing company data on their behalf.
# https://learn.microsoft.com/en-us/azure/active-directory/roles/delegate-app-roles

# Create Application Registrations
# 1. Sign in to the Microsoft Entra admin center as a Global Administrator.
# 2. Browse to Identity > Users > User settings.
# 3. Set the Users can register applications setting to No.
# --> This will disable the default ability for users to create application registrations.

# Consent to applications
# 1. Browse to Identity > Enterprise applications > Consent and permissions.
# 2. Select the "Do not allow user consent" option.
# --> This will disable the default ability for users to consent to applications accessing company data on their behalf.

# File Size (XLSX)
if (Test-Path "$OUTPUT_FOLDER\OAuthPermissions\OAuthPermissions.xlsx")
{
    $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\OAuthPermissions\OAuthPermissions.xlsx").Length)
    Write-Output "[Info]  File Size (XLSX): $Size"
}

# ConsentType
# Principal - Grant consent on behalf of a single user
# AllPrincipals - Grant consent on behalf of your organization

# Application Permissions --> ...without a signed-in user

# Name - This is the name of the application that users see on 'My Apps', admins see when managing access to this app, or other tenants see when integrating this app into their directory.
# AppId - This is the unique application ID of this application in your directory. You can use this application ID if you ever need help from Microsoft Support, or if you want to perform operations against this specific instance of the application using Microsoft Graph or PowerShell APIs.
# ObjectId - This is the unique ID of the service principal object associated with this application. This ID can be useful when performing management operations against this application using PowerShell or other programmatic interfaces.

# AccountEnabled (Enabled for users to sign-in?) - If this option is set to yes, then assigned users will be able to sign in to this application, either from My Apps, the User access URL, or by navigating to the application URL directly. If this option is set to no, then no users will be able to sign in to this app, even if they are assigned to it.
# AppRoleAssignmentRequired  (Assignment required?) - If this option is set to yes, then users and other apps or services must first be assigned to this application before being able to access it. If this option is set to no, then all users will be able to sign in, and other apps and services will be able to obtain an access token to this service.
# ApplicationVisibility (Visible to users?) - If this option is set to yes, then assigned users will see the application on My Apps and O365 app launcher. If this option is set to no, then no users will see this application on their My Apps and O365 launcher.

# SignInAudience - Specifies the Microsoft accounts that are supported for the current application. Read-only.
# - AzureADMyOrg: Users with a Microsoft work or school account in my organization's Microsoft Entra tenant (single-tenant).
# - AzureADMultipleOrgs: Users with a Microsoft work or school account in any organization's Microsoft Entra tenant (multitenant).
# - AzureADandPersonalMicrosoftAccount: Users with a personal Microsoft account, or a work or school account in any organization's Microsoft Entra tenant.
# - PersonalMicrosoftAccount: Users with a personal Microsoft account only.

# Account Types
# Who can use this application or access this API?
# 1. Accounts in this organizational directory only (Lethal Company only - Single tenant)
# 2. Accounts in any organizational directory (Any Microsoft Entra ID tenant - Multitenant)
# 3. Accounts in any organizational directory (Any Microsoft Entra ID tenant - Multitenant) and personal Microsoft accounts (e.g. Skype, Xbox)
# 4. Personal Microsoft accounts only

# Understanding Different Account Types
# 1. Accounts in this organizational directory only (Lethal Company only - Single tenant)
#    All user and guest accounts in your directory can use your application or API.
#    Use this option if your target audience is internal to your organization.
# 2. Accounts in any organizational directory (Any Microsoft Entra ID tenant - Multitenant)
#    All users with a work or school account from Microsoft can use your application or API. This includes schools and businesses that use Office 365.
#    Use this option if your target audience is business or educational customers and to enable multitenancy.
# 3. Accounts in any organizational directory (Any Microsoft Entra ID tenant - Multitenant) and personal Microsoft accounts (e.g. Skype, Xbox)
#    All users with a work or school, or personal Microsoft account can use your application or API. It includes schools and businesses that use Office 365 as well as personal accounts that are used to sign in to services like Xbox and Skype.
#    Use this option to target the widest set of Microsoft identities and to enable multitenancy.
# 4. Personal Microsoft accounts only
#    Personal accounts that are used to sign in to services like Xbox and Skype.
#    Use this option to target the widest set of Microsoft identities.

# ServicePrincipalType - Identifies whether the service principal represents an application, a managed identity, or a legacy application. This is set by Microsoft Entra ID internally.
# - Application - A service principal that represents an application or service. The appId property identifies the associated app registration, and matches the appId of an application, possibly from a different tenant. If the associated app registration is missing, tokens aren't issued for the service principal.
# - ManagedIdentity - A service principal that represents a managed identity. Service principals representing managed identities can be granted access and permissions, but can't be updated or modified directly.
# - Legacy - A service principal that represents an app created before app registrations, or through legacy experiences. A legacy service principal can have credentials, service principal names, reply URLs, and other properties that are editable by an authorized user, but doesn't have an associated app registration. The appId value doesn't associate the service principal with an app registration. The service principal can only be used in the tenant where it was created.

# Enterprise Applications shows non-Microsoft applications.
# Microsoft Applications shows Microsoft applications.
# Managed Identities shows applications that are used to authenticate to services that support Microsoft Entra authentication.

#############################################################################################################################################################################################

# Stats
New-Item "$OUTPUT_FOLDER\OAuthPermissions\Stats" -ItemType Directory -Force | Out-Null

# Import Data
$Data = Import-Csv -Path "$OUTPUT_FOLDER\OAuthPermissions\OAuthPermissions.csv" -Delimiter "," -Encoding UTF8

# AppOwnerOrganizationId (Stats)
$Total = ($Data | Select-Object AppOwnerOrganizationId | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Data | Group-Object AppOwnerOrganizationId | Select-Object @{Name='AppOwnerOrganizationId'; Expression={ $_.Values[0] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\AppOwnerOrganizationId.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AppOwnerOrganizationId" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"

    # ConditionalFormatting - AppOwnerOrganizationId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("72f988bf-86f1-41af-91ab-2d7cd011db47",$A1)))' -BackgroundColor $Green # Microsoft Application
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("f8cdef31-a31e-4b4a-93e4-5f571e91255a",$A1)))' -BackgroundColor $Green # Microsoft Application

    }
}

# AppDisplayName (Stats)
$Applications = ($Data | Select-Object AppDisplayName -Unique | Sort-Object AppDisplayName).AppDisplayName

$Stats = [Collections.Generic.List[PSObject]]::new()
ForEach($App in $Applications)
{
    $Count = ($Data | Where-Object {$_.AppDisplayName -eq "$App"} | Select-Object PrincipalDisplayName -Unique | Measure-Object).Count
    $ConsentType = ($Data | Where-Object {$_.AppDisplayName -eq "$App"} | Select-Object -ExpandProperty ConsentType -Unique | Sort-Object) -join ", " 

    $Line = [PSCustomObject]@{
        "AppDisplayName" = $App
        "ConsentType"    = $ConsentType
        "Count"          = $Count
    }

    $Stats.Add($Line)
}

# XLSX
$Stats | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\AppDisplayName-ConsentType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AppDisplayName" -CellStyleSB {
param($WorkSheet)
# BackgroundColor and FontColor for specific cells of TopRow
$BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
# HorizontalAlignment "Center" of column B-C
$WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"

# ConditionalFormatting - AppDisplayName
Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Invictus Cloud Insights",$A1)))' -BackgroundColor $Green
Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("LethalForensics_IR-App",$A1)))' -BackgroundColor $Green

foreach ($AppDisplayName in $RegEx01) 
{
    $ConditionValue = 'EXACT("{0}",$A1)' -f $AppDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx01
}

foreach ($AppDisplayName in $RegEx03) 
{
    $ConditionValue = 'EXACT("{0}",$A1)' -f $AppDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx03
}

foreach ($AppDisplayName in $RegEx04) 
{
    $ConditionValue = 'EXACT("{0}",$A1)' -f $AppDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx04
}

foreach ($PrincipalDisplayName in $PrincipalDisplayNames)
{
    $ConditionValue = 'EXACT("{0}",$A1)' -f $PrincipalDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # PrincipalDisplayName
}

}

# AppDisplayName / AppId (Stats)
$Applications = ($Data | Select-Object AppId -Unique | Sort-Object AppId).AppId

$Stats = [Collections.Generic.List[PSObject]]::new()
ForEach($App in $Applications)
{
    $Count = ($Data | Where-Object {$_.AppId -eq "$App"} | Select-Object PrincipalDisplayName -Unique | Measure-Object).Count
    $AppDisplayName = $Data | Where-Object {$_.AppId -eq "$App"} | Select-Object AppDisplayName -Unique

    $Line = [PSCustomObject]@{
        "AppDisplayName"    = $AppDisplayName.AppDisplayName
        "AppId"             = $App
        "Count"             = $Count
    }

    $Stats.Add($Line)
}

# XLSX
$Stats | Sort-Object AppDisplayName | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\AppDisplayName-AppId.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Applications" -CellStyleSB {
param($WorkSheet)
# BackgroundColor and FontColor for specific cells of TopRow
$BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
# HorizontalAlignment "Center" of column B-C
$WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"

# ConditionalFormatting - AppDisplayName 
Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("LethalForensics_IR-App",$A1)))' -BackgroundColor $Green
    
foreach ($AppDisplayName in $RegEx01) 
{
    $ConditionValue = 'EXACT("{0}",$A1)' -f $AppDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx01
}

foreach ($AppDisplayName in $RegEx03) 
{
    $ConditionValue = 'EXACT("{0}",$A1)' -f $AppDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx03
}

foreach ($AppDisplayName in $RegEx04) 
{
    $ConditionValue = 'EXACT("{0}",$A1)' -f $AppDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx04
}

foreach ($PrincipalDisplayName in $PrincipalDisplayNames)
{
    $ConditionValue = 'EXACT("{0}",$A1)' -f $PrincipalDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # PrincipalDisplayName
}

# ConditionalFormatting - AppId
Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("fb4c470b-9133-42c7-8db0-f786adc04715",$B1)))' -BackgroundColor $Green # Invictus Cloud Insights

# Iterating over the Application-Blacklist HashTable
foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
{
    $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
    $ConditionValue = 'NOT(ISERROR(FIND("{0}",$B1)))' -f $AppId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
}

}

# AppDisplayName / AppId / AppOwnerOrganizationId (Stats)
$Data = Import-Csv -Path "$OUTPUT_FOLDER\OAuthPermissions\OAuthPermissions.csv" -Delimiter "," -Encoding UTF8
$Total = ($Data | Select-Object AppId | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Data | Group-Object AppDisplayName,AppId,AppOwnerOrganizationId | Select-Object @{Name='AppDisplayName'; Expression={ $_.Values[0] }},@{Name='AppId'; Expression={ $_.Values[1] }},@{Name='AppOwnerOrganizationId'; Expression={ $_.Values[2] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}}
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\AppDisplayName-AppId-AppOwnerOrganizationId.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Applications" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of column B-E
    $WorkSheet.Cells["B:E"].Style.HorizontalAlignment="Center"

    # ConditionalFormatting - AppDisplayName 
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:E"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("LethalForensics_IR-App",$A1)))' -BackgroundColor $Green
    
    foreach ($AppDisplayName in $RegEx01) 
    {
        $ConditionValue = 'EXACT("{0}",$A1)' -f $AppDisplayName
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:E"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx01
    }

    foreach ($AppDisplayName in $RegEx03) 
    {
        $ConditionValue = 'EXACT("{0}",$A1)' -f $AppDisplayName
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:E"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx03
    }

    foreach ($AppDisplayName in $RegEx04) 
    {
        $ConditionValue = 'EXACT("{0}",$A1)' -f $AppDisplayName
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:E"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx04
    }

    foreach ($PrincipalDisplayName in $PrincipalDisplayNames)
    {
        $ConditionValue = 'EXACT("{0}",$A1)' -f $PrincipalDisplayName
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:E"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # PrincipalDisplayName
    }

    # ConditionalFormatting - AppId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:E"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("fb4c470b-9133-42c7-8db0-f786adc04715",$B1)))' -BackgroundColor $Green # Invictus Cloud Insights

    # Iterating over the Application-Blacklist HashTable
    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
    {
        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$B1)))' -f $AppId
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:E"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
    }

    }
}

# AppDisplayName / AppId / AppOwnerOrganizationId / ApplicationType (Stats)
$Applications = ($Data | Select-Object AppId -Unique | Sort-Object AppId).AppId
$Stats = [Collections.Generic.List[PSObject]]::new()
ForEach($AppId in $Applications)
{
    $AppDisplayName = $Data | Where-Object {$_.AppId -eq "$AppId"} | Select-Object -ExpandProperty AppDisplayName -Unique
    $AppOwnerOrganizationId = $Data  | Where-Object {$_.AppId -eq "$AppId"} | Select-Object -ExpandProperty AppOwnerOrganizationId -Unique

    if ($AppOwnerOrganizationId -eq "72f988bf-86f1-41af-91ab-2d7cd011db47" -or $AppOwnerOrganizationId -eq "f8cdef31-a31e-4b4a-93e4-5f571e91255a")
    {
        $ApplicationType = "First-Party Application" # Microsoft Application
    }
    else
    {
        $ApplicationType = "Third-Party Application"
    }

    $Line = [PSCustomObject]@{
        "AppDisplayName"         = $AppDisplayName
        "AppId"                  = $AppId
        "AppOwnerOrganizationId" = $AppOwnerOrganizationId
        "ApplicationType"        = $ApplicationType
    }

    $Stats.Add($Line)
}

# XLSX
$Stats | Sort-Object AppDisplayName | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\AppDisplayName-AppId-AppOwnerOrganizationId-ApplicationType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Applications" -CellStyleSB {
param($WorkSheet)
# BackgroundColor and FontColor for specific cells of TopRow
$BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
# HorizontalAlignment "Center" of column B-D
$WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"

# ConditionalFormatting - AppDisplayName 
Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("LethalForensics_IR-App",$A1)))' -BackgroundColor $Green
    
foreach ($AppDisplayName in $RegEx01) 
{
    $ConditionValue = 'EXACT("{0}",$A1)' -f $AppDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx01
}

foreach ($AppDisplayName in $RegEx03) 
{
    $ConditionValue = 'EXACT("{0}",$A1)' -f $AppDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx03
}

foreach ($AppDisplayName in $RegEx04) 
{
    $ConditionValue = 'EXACT("{0}",$A1)' -f $AppDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx04
}

foreach ($PrincipalDisplayName in $PrincipalDisplayNames)
{
    $ConditionValue = 'EXACT("{0}",$A1)' -f $PrincipalDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # PrincipalDisplayName
}

# ConditionalFormatting - AppId
Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("fb4c470b-9133-42c7-8db0-f786adc04715",$B1)))' -BackgroundColor $Green # Invictus Cloud Insights

# Iterating over the Application-Blacklist HashTable
foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
{
    $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
    $ConditionValue = 'NOT(ISERROR(FIND("{0}",$B1)))' -f $AppId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
}

}

# ClientObjectId (Stats)
$ClientObjectIds = ($Data | Select-Object ClientObjectId -Unique | Sort-Object ClientObjectId).ClientObjectId

$Stats = [Collections.Generic.List[PSObject]]::new()
ForEach($Id in $ClientObjectIds)
{
    $Name = $Data | Where-Object {$_.ClientObjectId -eq "$Id"} | Select-Object -ExpandProperty AppDisplayName -Unique
    $Count = ($Data | Where-Object {$_.ClientObjectId -eq "$Id"} | Select-Object PrincipalDisplayName -Unique | Measure-Object).Count

    $Line = [PSCustomObject]@{
        "AppDisplayName"    = $Name
        "ClientObjectId"    = $Id
        "Users"             = $Count
    }

    $Stats.Add($Line)
}

# XLSX
$Stats | Sort-Object AppDisplayName | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\ClientObjectId.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ClientObjectId" -CellStyleSB {
param($WorkSheet)
# BackgroundColor and FontColor for specific cells of TopRow
$BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
# HorizontalAlignment "Center" of column B-C
$WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"

# ConditionalFormatting - AppDisplayName 
Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Invictus Cloud Insights",$A1)))' -BackgroundColor $Green
Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("LethalForensics_IR-App",$A1)))' -BackgroundColor $Green
    
foreach ($AppDisplayName in $RegEx01) 
{
    $ConditionValue = 'EXACT("{0}",$A1)' -f $AppDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx01
}

foreach ($AppDisplayName in $RegEx03) 
{
    $ConditionValue = 'EXACT("{0}",$A1)' -f $AppDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx03
}

foreach ($AppDisplayName in $RegEx04) 
{
    $ConditionValue = 'EXACT("{0}",$A1)' -f $AppDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx04
}

foreach ($PrincipalDisplayName in $PrincipalDisplayNames)
{
    $ConditionValue = 'EXACT("{0}",$A1)' -f $PrincipalDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # PrincipalDisplayName
}

}

# Permissions (Stats)
$Stats = $Data | Select-Object PermissionType,Permission,@{Name='Description';Expression={if($_.Description){$_.Description}else{Get-ScopeLink $_.Permission}}} | Group-Object PermissionType,Permission,Description | Select-Object @{Name='PermissionType'; Expression={ $_.Values[0] }},@{Name='Permission'; Expression={ $_.Values[1] }},@{Name='Description'; Expression={ $_.Values[2] }},Count | Sort-Object Count -Descending | Sort-Object Count -Descending

# XLSX
$Stats | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\Permissions.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Permissions" -CellStyleSB {
param($WorkSheet)
# BackgroundColor and FontColor for specific cells of TopRow
$BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
# HorizontalAlignment "Center" of columns A-D
$WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
# Font Style "Underline" of column C (Link)
Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Link",$C1)))' -Underline

# Iterating over the ApplicationPermission-Blacklist HashTable
foreach ($Permission in $ApplicationPermissionBlacklist_HashTable.Keys) 
{
    $Severity = $ApplicationPermissionBlacklist_HashTable["$Permission"][1]
    if ($Severity -eq "High"){$BackgroundColor = $HighColor}
    if ($Severity -eq "Medium"){$BackgroundColor = $MediumColor}
    if ($Severity -eq "Low"){$BackgroundColor = $LowColor}
    $ConditionValue = '=AND($A1="Application",$B1="{0}")' -f $Permission
    Add-ConditionalFormatting -Address $WorkSheet.Cells["B:B"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $BackgroundColor
}

# Iterating over the DelegatedPermission-Blacklist HashTable
foreach ($Permission in $DelegatedPermissionBlacklist_HashTable.Keys) 
{
    $Severity = $DelegatedPermissionBlacklist_HashTable["$Permission"][1]
    if ($Severity -eq "High"){$BackgroundColor = $HighColor}
    if ($Severity -eq "Medium"){$BackgroundColor = $MediumColor}
    if ($Severity -eq "Low"){$BackgroundColor = $LowColor}
    $ConditionValue = '=AND($A1="Delegated",$B1="{0}")' -f $Permission
    Add-ConditionalFormatting -Address $WorkSheet.Cells["B:B"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $BackgroundColor
}

}

# PermissionType / Permission (Stats)
$Total = ($Data | Select-Object PermissionType | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Data | Group-Object PermissionType,Permission | Select-Object @{Name='PermissionType'; Expression={ $_.Values[0] }},@{Name='Permission'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\PermissionType-Permission.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Permissions" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-D
    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"

    # Iterating over the ApplicationPermission-Blacklist HashTable
    foreach ($Permission in $ApplicationPermissionBlacklist_HashTable.Keys) 
    {
        $Severity = $ApplicationPermissionBlacklist_HashTable["$Permission"][1]
        if ($Severity -eq "High"){$BackgroundColor = $HighColor}
        if ($Severity -eq "Medium"){$BackgroundColor = $MediumColor}
        if ($Severity -eq "Low"){$BackgroundColor = $LowColor}
        $ConditionValue = '=AND($A1="Application",$B1="{0}")' -f $Permission
        Add-ConditionalFormatting -Address $WorkSheet.Cells["B:B"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $BackgroundColor
    }

    # Iterating over the DelegatedPermission-Blacklist HashTable
    foreach ($Permission in $DelegatedPermissionBlacklist_HashTable.Keys) 
    {
        $Severity = $DelegatedPermissionBlacklist_HashTable["$Permission"][1]
        if ($Severity -eq "High"){$BackgroundColor = $HighColor}
        if ($Severity -eq "Medium"){$BackgroundColor = $MediumColor}
        if ($Severity -eq "Low"){$BackgroundColor = $LowColor}
        $ConditionValue = '=AND($A1="Delegated",$B1="{0}")' -f $Permission
        Add-ConditionalFormatting -Address $WorkSheet.Cells["B:B"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $BackgroundColor
    }

    }
}

# PrincipalDisplayName (Stats)
$PrincipalDisplayNames = ($Data | Select-Object PrincipalDisplayName | Where-Object {$_.PrincipalDisplayName -ne '' } | Where-Object { $null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Select-Object PrincipalDisplayName -Unique | Sort-Object PrincipalDisplayName).PrincipalDisplayName

$Stats = [Collections.Generic.List[PSObject]]::new()
ForEach($PrincipalDisplayName in $PrincipalDisplayNames)
{
    $Permissions  = ($Data | Where-Object {$_.PrincipalDisplayName -eq "$PrincipalDisplayName"} | Select-Object Permissions | Measure-Object).Count
    $Applications = ($Data | Where-Object {$_.PrincipalDisplayName -eq "$PrincipalDisplayName"} | Select-Object AppId -Unique | Measure-Object).Count

    $Line = [PSCustomObject]@{
        "PrincipalDisplayName" = $PrincipalDisplayName
        "Applications"         = $Applications
        "Permissions"          = $Permissions
    }

    $Stats.Add($Line)
}

# XLSX
$Stats | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\PrincipalDisplayName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "PrincipalDisplayName" -CellStyleSB {
param($WorkSheet)
# BackgroundColor and FontColor for specific cells of TopRow
$BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
# HorizontalAlignment "Left" of column A
$WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Left"
# HorizontalAlignment "Center" of columns B-C
$WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
}

# PublisherDisplayName (Stats)
# Note: Permissions Count
$Total = ($Data | Select-Object PublisherDisplayName | Measure-Object).Count
$PublisherNames = ($Data | Where-Object {$_.PublisherDisplayName -ne '' } | Select-Object PublisherDisplayName | Sort-Object PublisherDisplayName -Unique | Measure-Object).Count
$Count = ($Data | Select-Object AppId -Unique | Measure-Object).Count
Write-Output "[Info]  $PublisherNames Publisher Name(s) found ($Count)"

if ($Total -ge "1")
{
    $Stats = $Data | Select-Object PublisherDisplayName | Where-Object {$_.PublisherDisplayName -ne '' } | Where-Object { $null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object PublisherDisplayName | Select-Object @{Name='PublisherDisplayName'; Expression={ $_.Values[0] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\PublisherDisplayName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "PublisherDisplayName" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    # ConditionalFormatting - PublisherDisplayName 
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("eM Client s.r.o.",$A1)))' -BackgroundColor Red # eM Client
    }
}

# PublisherDisplayName / AppDisplayName (Stats)
$Total = ($Data | Select-Object PublisherDisplayName | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Data | Group-Object PublisherDisplayName,AppDisplayName | Select-Object @{Name='PublisherDisplayName'; Expression={if($_.Values[0]){$_.Values[0]}else{'N/A'}}},@{Name='AppDisplayName'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\PublisherDisplayName-AppDisplayName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "PublisherDisplayName" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-D
    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
    
    # ConditionalFormatting - AppDisplayName 
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Invictus Cloud Insights",$B1)))' -BackgroundColor $Green
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("LethalForensics_IR-App",$B1)))' -BackgroundColor $Green
    
    foreach ($AppDisplayName in $RegEx01) 
    {
        $ConditionValue = 'EXACT("{0}",$B1)' -f $AppDisplayName
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx01
    }

    foreach ($AppDisplayName in $RegEx03) 
    {
        $ConditionValue = 'EXACT("{0}",$B1)' -f $AppDisplayName
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx03
    }

    foreach ($AppDisplayName in $RegEx04) 
    {
        $ConditionValue = 'EXACT("{0}",$B1)' -f $AppDisplayName
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx04
    }

    foreach ($PrincipalDisplayName in $PrincipalDisplayNames)
    {
        $ConditionValue = 'EXACT("{0}",$B1)' -f $PrincipalDisplayName
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # PrincipalDisplayName
    }
    
    # ConditionalFormatting - PublisherName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("N/A",$A1)))' -BackgroundColor Yellow
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("eM Client s.r.o.",$A1)))' -BackgroundColor Red # eM Client

    }

    # Not Provided
    $Total = ($Data | Select-Object AppId -Unique | Measure-Object).Count
    $Count = ($Stats | Where-Object {$_.PublisherDisplayName -eq 'N/A' } | Select-Object PublisherDisplayName | Measure-Object).Count
    if ($Count -ge "1")
    {
        Write-Host "[Info]  $Count Publisher Name(s) not provided ($Total)" -ForegroundColor Yellow
    }
}

# ResourceDisplayName (Stats)
$Total = ($Data | Select-Object ResourceDisplayName | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Data | Select-Object ResourceDisplayName | Where-Object {$_.ResourceDisplayName -ne '' } | Where-Object { $null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object ResourceDisplayName | Select-Object @{Name='ResourceDisplayName'; Expression={ $_.Values[0] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\ResourceDisplayName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ResourceDisplayName" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# SignInAudience (Stats)
$Total = ($Data | Select-Object SignInAudience | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\OAuthPermissions\OAuthPermissions.csv" -Delimiter "," -Encoding UTF8 | Group-Object SignInAudience | Select-Object @{Name='SignInAudience'; Expression={ $_.Values[0] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\SignInAudience.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SignInAudience" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# App Registrations per day
$Apps = ($Data | Select-Object AppId -Unique | Measure-Object).Count
$Import = $Data | Sort-Object AppId -Unique | Select-Object @{Name="CreatedDateTime";Expression={($_.CreatedDateTime | ForEach-Object{($_ -split " ")[0]})}} | Group-Object{($_.CreatedDateTime)} | Select-Object @{Name='CreatedDateTime'; Expression={ $_.Values[0] }},Count | Sort-Object { $_.CreatedDateTime -as [datetime] }
$Count = ($Import | Measure-Object).Count
if ($Count -gt 0)
{
    Write-Output "[Info]  $Count App Registration Date(s) found ($Apps)"
}

}

Start-Processing

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
Start-Sleep -Milliseconds 500

# MessageBox UI
$MessageBody = "Status: OAuth Permissions Analysis completed."
$MessageTitle = "OAuthPermissions-Analyzer.ps1 (https://lethal-forensics.com/)"
$ButtonType = "OK"
$MessageIcon = "Information"
$Result = [System.Windows.Forms.MessageBox]::Show($MessageBody, $MessageTitle, $ButtonType, $MessageIcon)

if ($Result -eq "OK" ) 
{
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

#endregion Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# SIG # Begin signature block
# MIIrywYJKoZIhvcNAQcCoIIrvDCCK7gCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU8ZSXfCXImFSpDRl5bUpUWxZz
# JnaggiUEMIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
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
# MCMGCSqGSIb3DQEJBDEWBBR+zBw0RFRI7SymiT/G6o42cyCHvzANBgkqhkiG9w0B
# AQEFAASCAgAJfx+vUmv+/i3I7tXGzZGX5ERsQCaSZnMp06UU9v9VPPBSWpNDQbsu
# HxLDNw8VFd0iQtaRlE+3pUnjA9t+jArr1U5bqPj6x4QxWShYDNOC+RQfSl73dkYp
# bdgrycV4Ilbf+stMLX0yNAurUPKuS08/LZClhtyK1aGzh9Npkaz9p6L1oQZ0Sr5R
# iaa49N91JyXgOx0wtgz5laP0FDvlVnS+iCpNDo8WPGimYeiqkSdpIeG4zcGW8FwZ
# 3zLw8Sf8xBkpmlrdmPvBhjOfoA872SJQZxbRyyvCmlf6vgcTObEX1Dzh1DBbpWg5
# IIg9ujl5EOAvkiz7uC0KRV0lPVXLf3YX5fbz5xHCyxUTtqKYYWxzOY5XOlXEWDAh
# 7m+Ypp0yQR1horMndD68Q2GrBb6JTWXn+UjVgxP5KJAD+0TbPy8Q5ofbfSJocSCP
# 6NJeRWQ+oaPdJ7H+QujKAAGjJXHewTztS2C/JAnB3slT5h9s8sDUnMpOpDBIiYPg
# KroFa8RJ/Lw0ot/0bp+MbdqPYFcdaxxzBaWDdXenunjOchwuXgloiDxxbTKm+XaD
# cr+3m8LP1gXLDVqFaUhDgxEBPIUR9ixjHjqvoFNxMHmzsHDmDO6/RspNMZOKpjjG
# qSbzH5hsHw9rSErd9wXdVJO7eE6IeZXia6JuaN2p+tdADWhmSMiqQaGCAyMwggMf
# BgkqhkiG9w0BCQYxggMQMIIDDAIBATBqMFUxCzAJBgNVBAYTAkdCMRgwFgYDVQQK
# Ew9TZWN0aWdvIExpbWl0ZWQxLDAqBgNVBAMTI1NlY3RpZ28gUHVibGljIFRpbWUg
# U3RhbXBpbmcgQ0EgUjM2AhEApCk7bh7d16c0CIetek63JDANBglghkgBZQMEAgIF
# AKB5MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MDUxNTA0NDcyNFowPwYJKoZIhvcNAQkEMTIEMNLnZTNQGbtehg9zJKOL4lphvNyi
# zKBEKKeSDH0n7cFwxNtGaSpeZxgWh2MV4f7XnzANBgkqhkiG9w0BAQEFAASCAgCu
# 9Z2FoEAAbo5qsT50ccTZED5lnqbpSjy7Bl753gA+B3ZPqGtM/d2ABMny4AFaAB+9
# 5Y0RBmhA2FGleBW3dmOiv5ilFxF9DMex0AdG2lMbE7cQSZWX/ncRxO7q17R7Hsx4
# LATYM5WBYzqDLkuBPmC4cu/vRnh260WkwOEBvxAczVotLyP17PYBr5fMFeX6FBku
# Cqs66rElclIFNFd52sRNwLOHWxQHZITgdOpLnffrmGraKeKgVCyfNXmUOA6LQ5Qh
# gT873crxp/SLsVRzj3hl7YbZtgYC+ZJ6rXJQHMCCBhZSyHSFZfl/jGJp7h16hqd9
# 8+gXU1TNL2FrWd0+E7nX4Ha9ojIbgtCYzOxyeZceb2ej23QCHHZnQruF5uhsdRao
# adK2FDzJZjFvAaae4BRCEGJT3GSEWSZRm5GlcpIwhiO2lIFt/IFPs7QDbx3x1iyQ
# 2OcOva/KtMhj3rsJlp9Qb9HXVeEpZdkLFQXCKIC6PjsNGM8ym6iqJFMo9mpJfpfQ
# XAz4to5X4sjhUt++zAo04qwZViQkDASAWmzzo6yyRfTPC7Hzgffc6la4/L9EN26y
# ll9RQ+I8zUx+X2mW5CHUeALRNKBa/UslGUQB/rhgmfpPzT55Loj/FPnlITksbcij
# uDKRNKKQugxfxRUBuym0AsLMfjW36EJUxwBaheuH0g==
# SIG # End signature block
