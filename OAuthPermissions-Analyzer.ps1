# OAuthPermissions-Analyzer
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
  OAuthPermissions-Analyzer - Automated Processing of M365 OAuth Permissions for DFIR

.DESCRIPTION
  OAuthPermissions-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of M365 OAuth Permissions extracted via "Microsoft Extractor Suite" by Invictus Incident Response.

  List delegated permissions (OAuth2PermissionGrants) and application permissions (AppRoleAssignments) using Microsoft Graph API.

  https://github.com/invictus-ir/Microsoft-Extractor-Suite (Microsoft-Extractor-Suite v4.1.0)

  https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/Azure/OAuthPermissions.html#id2

  OAuth applications in Microsoft Entra ID are a common persistence and privilege escalation mechanism used by attackers.

.PARAMETER OutputDir
  Specifies the output directory. Default is "$env:USERPROFILE\Desktop\OAuthPermissions-Analyzer".

  Note: The subdirectory 'OAuthPermissions-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the CSV-based input file (*-OAuthPermissions.csv).

  Note: *-AppRegistrations.csv and *-ServicePrincipals.csv are automatically detected.

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

# Create HashTable and import 'ApplicationPermission-Blacklist.csv'
$script:ApplicationPermissionBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\ApplicationPermission-Blacklist.csv")
{
    if ((Get-Content "$SCRIPT_DIR\Blacklists\ApplicationPermission-Blacklist.csv" -TotalCount 2).Count -gt 1)
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
    if ((Get-Content "$SCRIPT_DIR\Blacklists\DelegatedPermission-Blacklist.csv" -TotalCount 2).Count -gt 1)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\DelegatedPermission-Blacklist.csv" -Delimiter "," | ForEach-Object { $DelegatedPermissionBlacklist_HashTable[$_.Permission] = $_.DisplayText,$_.Severity }

        # Count Ingested Properties
        $Count = $DelegatedPermissionBlacklist_HashTable.Count
        Write-Output "[Info]  Initializing 'DelegatedPermission-Blacklist.csv' Lookup Table ($Count) ..."
    }
}

# Download OAuthSentry Feed
$RawUrl    = "https://raw.githubusercontent.com/OAuthSentry/oauthsentry.github.io/refs/heads/main/feeds/entra/entra_all.json"
$LocalPath = "$SCRIPT_DIR\Blacklists\OAuthSentry\entra_all.json"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

try {

    $Response = Invoke-WebRequest -Uri $RawUrl -Method Head -ErrorAction Stop -TimeoutSec 10

    if ([int]$Response.StatusCode -eq 200)
    {
        New-Item "$SCRIPT_DIR\Blacklists\OAuthSentry" -ItemType Directory -Force | Out-Null
        Invoke-WebRequest -Uri $RawUrl -OutFile $LocalPath

        # Create Hash Table and import 'entra_all.json'
        if (Test-Path "$LocalPath")
        {
            $EntraFeed = Get-Content "$LocalPath" -Raw | ConvertFrom-Json
            $Count = $EntraFeed.count
            $OAuthSentry = $EntraFeed.items
            if ($Count -ge 1)
            {
                Write-Output "[Info]  Initializing 'OAuthSentry' Lookup Table ($Count) ..."
                $script:OAuthSentry_HashTable = [ordered]@{}
                $OAuthSentry | ForEach-Object { $script:OAuthSentry_HashTable[$_.appid] = $_.appname,$_.metadata_category,$_.metadata_severity,$_.metadata_comment,$_.metadata_reference,$_._provenance }
            }
        }
    }
}
catch {

    Write-Host "[Error] OAuthSentry Feed NOT found or unreachable." -ForegroundColor Red
    Write-Host "        $_" -ForegroundColor Red

    # Create Hash Table and import 'entra_all.json' (Fallback)
    if (Test-Path "$LocalPath")
    {
        $EntraFeed = Get-Content "$LocalPath" -Raw | ConvertFrom-Json
        $Count = $EntraFeed.count
        $OAuthSentry = $EntraFeed.items
        if ($Count -ge 1)
        {
            Write-Output "[Info]  Initializing local 'OAuthSentry' Lookup Table ($Count) ..."
            $script:OAuthSentry_HashTable = [ordered]@{}
            $OAuthSentry | ForEach-Object { $script:OAuthSentry_HashTable[$_.appid] = $_.appname,$_.metadata_category,$_.metadata_severity,$_.metadata_comment,$_.metadata_reference,$_._provenance }
        }
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
while($null -ne $Reader.ReadLine()){ $TotalLines++ }
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
    "CreatedDateTime"        = $Record | Select-Object -ExpandProperty CreatedDateTime | ForEach-Object {$_ -replace 'T',' '} | ForEach-Object {$_ -replace 'Z'} # The time when the app role assignment was created. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time.
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

$Results | Export-Csv -Path "$OUTPUT_FOLDER\OAuthPermissions\OAuthPermissions.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Test-Path "$OUTPUT_FOLDER\OAuthPermissions\OAuthPermissions.csv")
{
    if ((Get-Content "$OUTPUT_FOLDER\OAuthPermissions\OAuthPermissions.csv" -TotalCount 2).Count -gt 1)
    {
        $OAuthPermissions = Import-Csv -Path "$OUTPUT_FOLDER\OAuthPermissions\OAuthPermissions.csv" -Delimiter "," -Encoding UTF8 | Select-Object -Property * -ExcludeProperty IsEnabled

        # LETHAL-001: AppDisplayName with only non-alphanumeric characters
        [array]$RegEx01 = $OAuthPermissions | Where-Object { $_.AppDisplayName -match "^[^a-zA-Z0-9]+$" } | Select-Object -ExpandProperty AppDisplayName
        $Count = ($RegEx01 | Select-Object AppId -Unique | Measure-Object).Count
        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious OAuth Application detected: AppDisplayName w/ only non-alphanumeric characters ($Count)" -ForegroundColor Red
        }

        # LETHAL-002: Anomalous ReplyUrls including a local loopback URL
        [array]$RegEx02 = $OAuthPermissions | Where-Object { $_.ReplyUrls -match "http://localhost:\d+/access/?" } | Select-Object -ExpandProperty ReplyUrls
        $Count = ($RegEx02 | Select-Object AppId -Unique | Measure-Object).Count
        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious OAuth Application detected: Anomalous ReplyUrl including a local loopback URL ($Count)" -ForegroundColor Red
        }

        # LETHAL-003: Common Naming Patterns of Malicious OAuth Applications
        [array]$RegEx03 = $OAuthPermissions | Where-Object { $_.AppDisplayName -match "^(test|test app|app test|apptest)$" } | Select-Object -ExpandProperty AppDisplayName
        $Count = ($RegEx03 | Select-Object AppId -Unique | Measure-Object).Count
        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious OAuth Application detected: Common Naming Pattern of Malicious OAuth Applications ($Count)" -ForegroundColor Red
        }

        # LETHAL-004: UPN Naming Pattern (incl. B2B Collaboration User)
        [array]$RegEx04 = $OAuthPermissions | Where-Object { $_.AppDisplayName -match "^([\w-\.]+)(#EXT#)?@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([\w-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$" } | Select-Object -ExpandProperty AppDisplayName
        $Count = ($RegEx04 | Select-Object AppId -Unique | Measure-Object).Count
        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious OAuth Application detected: UPN Naming Pattern ($Count)" -ForegroundColor Red
        }

        # LETHAL-005: User Naming Pattern (PrincipalDisplayName)
        [array]$PrincipalDisplayNames = $OAuthPermissions | Where-Object {$_.PrincipalDisplayName -ne ""} | Select-Object -ExpandProperty PrincipalDisplayName -Unique
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

        $OAuthPermissions | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\OAuthPermissions.xlsx" -NoHyperLinkConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "OAuthPermissions" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:Z1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-Y
        $WorkSheet.Cells["A:Y"].Style.HorizontalAlignment="Center"

        # Font Style "Underline" of column I (Link)
        Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Link",$I1)))' -Underline

        # ConditionalFormatting - AppDisplayName
        Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("LethalForensics_IR-App",$C1)))' -BackgroundColor $Green
        Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("CANCOM_IR-App",$C1)))' -BackgroundColor $Green
        Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("ConnectSyncProvisioning_",$C1)))' -BackgroundColor Yellow

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
            $Count = ($OAuthPermissions | Where-Object { $_.AppId -eq "$AppId" } | Measure-Object).Count
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

        # LETHAL-007: Iterating over the OAuthSentry HashTable
        Write-Output "[Info]  Checking OAuthSentry - OAuth Application Intelligence Inventory ..."
        foreach ($AppId in $OAuthSentry_HashTable.Keys) 
        {
            $Count = ($OAuthPermissions | Where-Object { $_.AppId -eq "$AppId" } | Measure-Object).Count
            if ($Count -gt 0)
            {
                $AppDisplayName = $OAuthSentry_HashTable["$AppId"][0]

                $Category = $OAuthSentry_HashTable["$AppId"][1]
                $Category = $Category.Substring(0,1).ToUpper() + $Category.Substring(1)

                if ($Category -eq "Malicious")
                {
                    $CategoryColor = "Red"
                }
                elseif ($Category -eq "Risky")
                {
                    $CategoryColor = "Yellow"
                }
                elseif ($Category -eq "Compliance")
                {
                    $CategoryColor = "Gray"
                }
                else
                {
                    $Category = "Unknown"
                    $CategoryColor = "White"
                }
                
                $Severity = $OAuthSentry_HashTable["$AppId"][2]
                $Severity = $Severity.Substring(0,1).ToUpper() + $Severity.Substring(1)

                $Link = "https://oauthsentry.github.io/#/search?id=" + $AppId
                
                if ($Severity -eq "Info")
                {
                    Write-Host "[Info]  Name:      $AppDisplayName ($Count)" -ForegroundColor $CategoryColor
                    Write-Host "        Category:  $Category" -ForegroundColor $CategoryColor
                    Write-Host "        Severity:  $Severity" -ForegroundColor $CategoryColor
                    Write-Host "        Hyperlink: $Link" -ForegroundColor $CategoryColor
                }
                else
                {
                    Write-Host "[Alert] Name:      $AppDisplayName ($Count)" -ForegroundColor $CategoryColor
                    Write-Host "        Category:  $Category" -ForegroundColor $CategoryColor
                    Write-Host "        Severity:  $Severity" -ForegroundColor $CategoryColor
                    Write-Host "        Hyperlink: $Link" -ForegroundColor $CategoryColor
                }
            }
        }

        # Category     Description
        # Malicious    Confirmed in-the-wild malicious apps: consent phishing, AiTM lures, homoglyph impersonations, threat-actor redirect apps.
        # Risky        Legitimate apps that are repeatedly seen in attacker tradecraft - mailbox sync clients, cloud-storage sync tools, first-party apps abused via AADInternals/EvilProxy.
        # Compliance   Legitimate first-party or vetted third-party apps. Reference data for allowlists and hunt-tuning.

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
    $Stats = $Data | Group-Object AppOwnerOrganizationId | Select-Object @{Name='AppOwnerOrganizationId'; Expression={if($_.Values[0]){$_.Values[0]}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\AppOwnerOrganizationId.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AppOwnerOrganizationId" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
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
Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
# HorizontalAlignment "Center" of column B-C
$WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"

# ConditionalFormatting - AppDisplayName
Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Invictus Cloud Insights",$A1)))' -BackgroundColor $Green
Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("LethalForensics_IR-App",$A1)))' -BackgroundColor $Green
Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CANCOM_IR-App",$A1)))' -BackgroundColor $Green
Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("ConnectSyncProvisioning_",$A1)))' -BackgroundColor Yellow

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
Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
# HorizontalAlignment "Center" of column B-C
$WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"

# ConditionalFormatting - AppDisplayName 
Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("LethalForensics_IR-App",$A1)))' -BackgroundColor $Green
Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CANCOM_IR-App",$A1)))' -BackgroundColor $Green
Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("ConnectSyncProvisioning_",$A1)))' -BackgroundColor Yellow

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
    $Stats = $Data | Group-Object AppDisplayName,AppId,AppOwnerOrganizationId | Select-Object @{Name='AppDisplayName'; Expression={ $_.Values[0] }},@{Name='AppId'; Expression={ $_.Values[1] }},@{Name='AppOwnerOrganizationId'; Expression={if($_.Values[2]){$_.Values[2]}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}}
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\AppDisplayName-AppId-AppOwnerOrganizationId.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Applications" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of column B-E
    $WorkSheet.Cells["B:E"].Style.HorizontalAlignment="Center"

    # ConditionalFormatting - AppDisplayName 
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:E"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("LethalForensics_IR-App",$A1)))' -BackgroundColor $Green
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:E"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CANCOM_IR-App",$A1)))' -BackgroundColor $Green

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

    if (!($AppOwnerOrganizationId))
    {
        $AppOwnerOrganizationId = "N/A"
    }

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
Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
# HorizontalAlignment "Center" of column B-D
$WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"

# ConditionalFormatting - AppDisplayName 
Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("LethalForensics_IR-App",$A1)))' -BackgroundColor $Green
Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CANCOM_IR-App",$A1)))' -BackgroundColor $Green
 
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
Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
# HorizontalAlignment "Center" of column B-C
$WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"

# ConditionalFormatting - AppDisplayName 
Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Invictus Cloud Insights",$A1)))' -BackgroundColor $Green
Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("LethalForensics_IR-App",$A1)))' -BackgroundColor $Green
Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CANCOM_IR-App",$A1)))' -BackgroundColor $Green
    
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
Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
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
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
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
Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
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
    $Stats = $Data | Select-Object PublisherDisplayName | Group-Object PublisherDisplayName | Select-Object @{Name='PublisherDisplayName'; Expression={if($_.Values[0]){$_.Values[0]}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\PublisherDisplayName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "PublisherDisplayName" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
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
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-D
    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
    
    # ConditionalFormatting - AppDisplayName 
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Invictus Cloud Insights",$B1)))' -BackgroundColor $Green
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("LethalForensics_IR-App",$B1)))' -BackgroundColor $Green
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CANCOM_IR-App",$B1)))' -BackgroundColor $Green
    
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
        Write-Host "[Info]  $Count Publisher Name(s) were NOT provided ($Total)" -ForegroundColor Yellow
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
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
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
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
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

# Line Charts
New-Item "$OUTPUT_FOLDER\OAuthPermissions\Stats\LineCharts" -ItemType Directory -Force | Out-Null

# OAuth App Registrations (Line Chart) --> OAuth App Registrations per day
$Import = $Data | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Select-Object Count,@{Name='CreatedDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreatedDateTime -as [datetime] }
$ChartDefinition = New-ExcelChartDefinition -XRange CreatedDateTime -YRange Count -Title "App Registrations" -ChartType Line -NoLegend -Width 1200
$Import | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\LineCharts\App Registrations.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition

# Microsoft Entra Connect Sync (Entra Connect Sync v2.5.3.0 and newer) --> Application-Based Authentication (ABA)
$Count = ($Data | Where-Object { $_.AppDisplayName -match "^ConnectSyncProvisioning_" } | Sort-Object -Property AppId -Unique | Measure-Object).Count
if ($Count -gt 0)
{
    Write-Output "[Info]  $Count Microsoft Entra Connect Sync account(s) found"
    $ABA = $Data| Where-Object { $_.AppDisplayName -match "^ConnectSyncProvisioning_" } | Select-Object -ExpandProperty AppDisplayName -Unique
    $ABA | Out-File "$OUTPUT_FOLDER\OAuthPermissions\Microsoft-Entra-Connect-Sync.txt" -Encoding UTF8
    (Get-Content "$OUTPUT_FOLDER\OAuthPermissions\Microsoft-Entra-Connect-Sync.txt") -replace "^", "        "  | Write-Host
}
else
{
    Write-Output "[Info]  0 Microsoft Entra Connect Sync account(s) found"
}

#############################################################################################################################################################################################

# App Registrations
$FileObject  = Get-Item "$LogFile"
$TwoLevelsUp = Split-Path (Split-Path -Path $FileObject)
$AppRegistrations = (Get-ChildItem -Path $TwoLevelsUp -Recurse | Select-Object FullName | Where-Object {$_.FullName -like "*-AppRegistrations.csv"}).FullName

if (Test-Path "$AppRegistrations")
{
    if ((Get-Content "$AppRegistrations" -TotalCount 2).Count -gt 1)
    {
        $Import = Import-Csv -Path "$AppRegistrations" -Delimiter "," -Encoding UTF8 | Select-Object @{Name='AppDisplayName'; Expression={ $_.DisplayName }}, AppId, @{Name='CreatedDateTime'; Expression={(Get-Date $_.CreatedDateTime).ToString("yyyy-MM-dd HH:mm:ss")}}, Id | Sort-Object { $_.CreatedDateTime -as [datetime] } -Descending
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\AppRegistrations.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AppRegistrations" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns B-D
        $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"

        # ConditionalFormatting - AppDisplayName
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("LethalForensics_IR-App",$A1)))' -BackgroundColor $Green
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("CANCOM_IR-App",$A1)))' -BackgroundColor $Green
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("ConnectSyncProvisioning_",$A1)))' -BackgroundColor Yellow

        }
    }
}

# What are OAuth Applications and what is 'Consent'?

# A Microsoft Entra application starts with a single application object, which lives in the tenant where the app was originally registered (AppOwnerOrganizationId). 
# That application object acts as a blueprint: whenever the app is used in another tenant, Entra creates a corresponding service principal there.

# In other words, you can think of an OAuth application like a third-party contractor you hire to work on your house. 
# You wouldn't give them your master key (your password), instead, you give them a specific badge (set of permissions) that only lets them into the kitchen and the basement.

# In the world of Entra, 'Consent' is that badge. When you see a prompt asking for permission to access your profile or files, clicking 'Accept' is telling Entra: I trust this publisher enough to give them this specific set of permissions.

#############################################################################################################################################################################################

# Service Principals
$FileObject  = Get-Item "$LogFile"
$TwoLevelsUp = Split-Path (Split-Path -Path $FileObject)
$ServicePrincipals = (Get-ChildItem -Path $TwoLevelsUp -Recurse | Select-Object FullName | Where-Object {$_.FullName -like "*-ServicePrincipals.csv"}).FullName

if (Test-Path "$ServicePrincipals")
{
    if ((Get-Content "$ServicePrincipals" -TotalCount 2).Count -gt 1)
    {
        $Import = Import-Csv -Path "$ServicePrincipals" -Delimiter "," -Encoding UTF8 | Select-Object @{Name='AppDisplayName'; Expression = {if ([string]::IsNullOrEmpty($_.AppDisplayName)) {"N/A"} else {$_.AppDisplayName}}}, AppId, @{Name='AppOwnerOrganizationId'; Expression = {if ([string]::IsNullOrEmpty($_.AppOwnerOrganizationId)) {"N/A"} else {$_.AppOwnerOrganizationId}}}, AccountEnabled, AppDescription
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\ServicePrincipals.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ServicePrincipals" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns B-E
        $WorkSheet.Cells["B:E"].Style.HorizontalAlignment="Center"

        # ConditionalFormatting - AccountEnabled
        Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$D1)))' -BackgroundColor $Green
        Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("False",$D1)))' -BackgroundColor Red

        # ConditionalFormatting - AppOwnerOrganizationId
        Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("72f988bf-86f1-41af-91ab-2d7cd011db47",$C1)))' -BackgroundColor Yellow # Microsoft Application
        Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("f8cdef31-a31e-4b4a-93e4-5f571e91255a",$C1)))' -BackgroundColor Yellow # Microsoft Application
        
        }
    }
}

# From Global App to Local Identity

# Most of the apps you use, like Microsoft Teams, don’t actually "live" inside your cloud environment. They are hosted inside the Microsoft tenant of the publisher (i.e. Microsoft).
# But for Microsoft Teams to function within your specific company, your Microsoft tenant needs a way to recognize and manage it locally. 

# This creates a two-part relationship:
# 1. The Application Object: The global "blueprint" of the app that lives in the publishers's home tenant.
# 2. The Service Principal: Your local "instance" of that app.

# Note: There is only one global AppId for Microsoft Teams, every company that uses it has their own unique ServicePrincipalId.

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
# MIIs3gYJKoZIhvcNAQcCoIIszzCCLMsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUTgo4TPdvsjfIGQLxA5fKj5IG
# AtmggiYXMIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
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
# MRYEFDvfO0SG2QJpeUPiM0ux0tNgs3tRMA0GCSqGSIb3DQEBAQUABIICADMJLHeu
# enGu2SkGVNsX70Py3I3mRYGPtQSLAFc33+hb2A9l2xAuG/BBH9ZUIng59A8i+Olr
# M/GrgpiYI05/CObsikwgVGGvyrSs144M+DRRvBj5wvCH5X2OdWa1IuDvFyxfW5TJ
# mZdscRp6rV6woWom8GlDcfcIf2mEJD9eAFoWFEyr2Gf0S29N2lzE3MbN+5AQlkVk
# J6YNCP0DfdR3N8m8jI/c9uNCwRJK2j9fJRNVZ0uKz5pamnhg9IX3KUcfHsch6iS9
# U4Qo2Vq+/KeVmjF5rayPEZraKGN9NZdVwIO4yOVCx+nfx3VhPBc07ZX5ZiBneTKz
# Y6II103ySdOYFP379F8deptpbIHBaNlGdaPk6fESevEe35N8D7OQxjQOrCkIKObL
# div4EIIuLNczPYIdQ+tlAJEcUC/gQQ9hDI0mPSCo69ndES1kwUscpelI14F0hK56
# v5UgdZgOD/9b5sXAGcc53hizvWdbcKWs5cHleW7kLMd+G3D41X8FMELif7+RX44A
# I5v1tO+0621ekHGC/OJD5pfal18dzMhE23bxd8WXorm+ryd2mtg1uzmQRjIdJr0+
# RCLQwtaM4pC/XsBO7/UZi6PHLX8FfIrjsgdCWd2l9njTuFTBroJS746/Jxoa3Jj0
# BAVTZsBvadCobDgFpyl9Y855utPgdmY0NWaNoYIDIzCCAx8GCSqGSIb3DQEJBjGC
# AxAwggMMAgEBMGowVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGlt
# aXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBDQSBS
# NDECEQDnTvJVsFBP+tum3/f8i6MVMA0GCWCGSAFlAwQCAgUAoHkwGAYJKoZIhvcN
# AQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYwNzA2MTEzMTA4WjA/
# BgkqhkiG9w0BCQQxMgQwkBJXrrt/YfkGvong9TmMP5WK2poLxbx5/BsZmP4QIj7w
# jmfNuXOJJryQqC7yQ4aPMA0GCSqGSIb3DQEBAQUABIICAEYG2nlInGzAvdRNozyv
# BIlbnZbvbKZP9Q8T0+hYyPsDkuirCMVwuCog/zvrj5RVSqQRSH1suxTTjPCMcM1M
# kIa4qcuw3MYCBOIkypltPdiodehlTw/69S6U43kVlVcV0mMFOdhLj6pF8jSVEmZ/
# YjqgjhU98/fBeabZfcZQ+PrhuapNeNv28CqiNNDZoXkKIP3AE4v25OEDQJ1Y9NQC
# ZkdR02WW9an8ou2HBkpVRKA+2X0VfWN7yIfA+WnIsxH6ceWiLnoqRZVb2q8xUkIr
# 4bh+N1VDWLSLa8D5hhDEIpZ8kQz8DyiudEQyRTlSFKDPdB/4taG59akQzfj+Kjma
# lyCXjcOPGX71eQ2dwbwUBfb4rIrwF1IWrTtkLwsJ7D0NBFwaSPHZWc4MoJ8QRKtU
# 2n1t3rnZVjIBYLYewU/No7OWlNJXFT7i8LECy9M65o/LJlGlWz/jS1jdt5Z1eiE7
# 14gdtb5Ihw2UrQBWu7fHVyAEzwZV56FdqDpu/GtOGFgi+Sm4y8KxofPEBcLhrrb/
# Sknc8dbqLvjEYIa+w1QmA6ohLmNOpqdPY0mjLgZHmNRhLTnXvNlvvYwO/UmIsoVZ
# 0Z5ADW23wASzPjO0UzMBQ8lfXXb0ZzXiAsCmdWQZIn+pGU/c2BQO2aJ+DV7VICWh
# Esoi9+ZPgwycFahNMOrFYMmx
# SIG # End signature block
