# ServicePrincipal-Analyzer
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2025 Martin Willing. All rights reserved. Licensed under the MIT license.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2025-10-21
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
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.6456) and PowerShell 5.1 (5.1.19041.6456)
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.6456) and PowerShell 7.5.3
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  ServicePrincipal-Analyzer - Automated Processing of Microsoft Service Principal Sign-In Logs for DFIR

.DESCRIPTION
  ServicePrincipal-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of Microsoft Service Principal Sign-In Logs extracted via "Microsoft Extractor Suite" by Invictus Incident Response.

  https://github.com/invictus-ir/Microsoft-Extractor-Suite (Microsoft-Extractor-Suite v4.0.0)

  https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/Azure/AzureSignInLogsGraph.html

.PARAMETER OutputDir
  Specifies the output directory. Default is "$env:USERPROFILE\Desktop\ServicePrincipal-Analyzer".

  Note: The subdirectory 'ServicePrincipal-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the JSON-based input file (SignInLogs-servicePrincipal-Combined.json).

.EXAMPLE
  PS> .\ServicePrincipal-Analyzer.ps1

.EXAMPLE
  PS> .\ServicePrincipal-Analyzer.ps1 -Path "$env:USERPROFILE\Desktop\SignInLogs-servicePrincipal-Combined.json"

.EXAMPLE
  PS> .\ServicePrincipal-Analyzer.ps1 -Path "H:\Microsoft-Extractor-Suite\SignInLogs-servicePrincipal-Combined.json" -OutputDir "H:\Microsoft-Analyzer-Suite"

.NOTES
  Author - Martin Willing

.LINK
  https://lethal-forensics.com/
#>

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# How long does Microsoft Entra ID store the Sign-ins data?

# Microsoft Entra ID Free      7 days
# Microsoft Entra ID P1       30 days
# Microsoft Entra ID P2       30 days

# Note: You must have a Microsoft Entra ID P1 or P2 license to download sign-in logs using the Microsoft Graph API.

# Workload Identities
# Service principal sign-ins are the authentication events for a service principal, which is a type of workload identity used by an application to access resources.
# https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-overview
#
# - non-interactive sign-ins
# - Can’t perform multifactor authentication (MFA) --> Basic Authentication
# - Usually with high privileges
# - Conditional Access Policies (Microsoft Entra ID P1 or P2) do not cover service principal sign-ins (apply only to users when they access apps and services) --> Microsoft Entra Workload ID Premium required
# - Full risk details and risk-based access controls are available to Workload Identities Premium customers only. However, customers without the Workload Identities Premium licenses still receive all detections with limited reporting details.
#
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
$script:HighColor   = [System.Drawing.Color]::FromArgb(255,0,0) # Red
$script:MediumColor = [System.Drawing.Color]::FromArgb(255,192,0) # Orange
$script:LowColor    = [System.Drawing.Color]::FromArgb(255,255,0) # Yellow
$script:Green       = [System.Drawing.Color]::FromArgb(0,176,80) # Green

# Output Directory
if (!($OutputDir))
{
    $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\ServicePrincipal-Analyzer" # Default
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
        $script:OUTPUT_FOLDER = "$OutputDir\ServicePrincipal-Analyzer" # Custom
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
$Host.UI.RawUI.WindowTitle = "ServicePrincipal-Analyzer - Automated Processing of Microsoft Service Principal Sign-In Logs for DFIR"

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
        $OpenFileDialog.Filter = "Sign-In Logs|SignInLogs-servicePrincipal-Combined.json|All Files (*.*)|*.*"
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
Write-Output "ServicePrincipal-Analyzer - Automated Processing of Microsoft Service Principal Sign-In Logs for DFIR"
Write-Output "(c) 2025 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
Write-Output ""

# Analysis date (ISO 8601)
$script:AnalysisDate = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "Analysis date: $AnalysisDate UTC"
Write-Output ""

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
else
{
    Write-Host "[Error] 'Application-Blacklist.csv' NOT found." -ForegroundColor Red
}

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
else
{
    Write-Host "[Error] 'ASN-Blacklist.csv' NOT found." -ForegroundColor Red
}

# Create HashTable and import 'Country-Blacklist.csv'
$script:CountryBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\Country-Blacklist.csv")
{
    if(Test-Csv -Path "$SCRIPT_DIR\Blacklists\Country-Blacklist.csv" -MaxLines 2)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\Country-Blacklist.csv" -Delimiter "," | ForEach-Object { $CountryBlacklist_HashTable[$_."Country Name"] = $_.Country }

        # Count Ingested Properties
        $Count = $CountryBlacklist_HashTable.Count
        Write-Output "[Info]  Initializing 'Country-Blacklist.csv' Lookup Table ($Count) ..."
    }
}
else
{
    Write-Host "[Error] 'Country-Blacklist.csv' NOT found." -ForegroundColor Red
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
else
{
    Write-Host "[Error] 'UserAgent-Blacklist.csv' NOT found." -ForegroundColor Red
}

#endregion Header

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Analysis

# Microsoft Service Principal Sign-In Logs (App-Only Context)
# https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-service-principal-sign-ins

# What are service principal sign-ins in Microsoft Entra?
# Unlike interactive and non-interactive user sign-ins, service principal sign-ins don't involve a user. 
# Instead, they're sign-ins by any non-user account, such as apps or service principals (except managed identity sign-in, which are in included only in the managed identity sign-in log). 
# In these sign-ins, the app or service provides its own credential, such as a certificate or app secret to authenticate or access resources.

Function Start-Processing {

$StartTime_Processing = (Get-Date)

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

# Input Size
$InputSize = Get-FileSize((Get-Item "$LogFile").Length)
Write-Output "[Info]  Total Input Size: $InputSize"

# Count rows of JSON (w/ thousands separators)
$Count = 0
switch -File "$LogFile" { default { ++$Count } }
$Rows = '{0:N0}' -f $Count
Write-Output "[Info]  Total Lines: $Rows"

# Processing Microsoft Entra ID Sign-In Logs
Write-Output "[Info]  Processing Microsoft Service Principal Sign-In Logs ..."
New-Item "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\XLSX" -ItemType Directory -Force | Out-Null

# Import JSON
$Data = Get-Content -Path "$LogFile" -Raw | ConvertFrom-Json | Sort-Object { $_.createdDateTime -as [datetime] } -Descending

# Time Frame
$Last  = ($Data | Sort-Object { $_.createdDateTime -as [datetime] } -Descending | Select-Object -Last 1).createdDateTime
$First = ($Data | Sort-Object { $_.createdDateTime -as [datetime] } -Descending | Select-Object -First 1).createdDateTime
$StartDate = (Get-Date $Last).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
$EndDate = (Get-Date $First).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "[Info]  Log data from $StartDate UTC until $EndDate UTC"

# Untouched
# https://learn.microsoft.com/en-us/powershell/module/Microsoft.Graph.Beta.Reports/Get-MgBetaAuditLogSignIn?view=graph-powershell-beta
# https://learn.microsoft.com/nb-no/graph/api/resources/signin?view=graph-rest-beta

# CSV
$Results = [Collections.Generic.List[PSObject]]::new()
ForEach($Record in $Data)
{
    $CreatedDateTime = $Record | Select-Object -ExpandProperty createdDateTime
    $NetworkLocationDetails = $Record | Select-Object -ExpandProperty networkLocationDetails
    $NetworkNames    = ($NetworkLocationDetails | Select-Object -ExpandProperty networkNames) -join ", "
    $NetworkType     = ($NetworkLocationDetails | Select-Object -ExpandProperty networkType) -join "`r`n"

    # TrustedNamedLocation
    if ($NetworkType | Select-String -Pattern "trustedNamedLocation" -Quiet)
    {
        $TrustedNamedLocation = "Yes"
    }
    else
    {
        $TrustedNamedLocation = "No"
    }

    $Line = [PSCustomObject]@{
    "Id"                              = $Record.Id # The identifier representing the sign-in activity.
    "CreatedDateTime"                 = (Get-Date $CreatedDateTime).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
    "AppId"                           = $Record.appId # The application identifier in Microsoft Entra ID.
    "AppDisplayName"                  = $Record.appDisplayName # The application name displayed in the Microsoft Entra admin center.
    "AppOwnerTenantId"                = $Record.appOwnerTenantId # The identifier of the tenant that owns the client application.
    "ResourceOwnerTenantId"           = $Record.resourceOwnerTenantId # The identifier of the owner of the resource.
    "ServicePrincipalId"              = $Record.servicePrincipalId # The application identifier used for sign-in.
    "ServicePrincipalName"            = $Record.servicePrincipalName # The application name used for sign-in.
    "ClientAppUsed"                   = $Record.clientAppUsed # The legacy client used for sign-in activity.
    "UserAgent"                       = $Record.userAgent # The user agent information related to sign-in.
    "IPAddress"                       = $Record.ipAddress # The IP address of the client from where the sign-in occurred.
    "ASN"                             = $Record.AutonomousSystemNumber # The Autonomous System Number (ASN) of the network used by the actor.
    "City"                            = $Record | Select-Object -ExpandProperty location | Select-Object -ExpandProperty city # The city from where the sign-in occurred.
    "State"                           = $Record | Select-Object -ExpandProperty location | Select-Object -ExpandProperty state # The state from where the sign-in occurred.
    "CountryOrRegion"                 = $Record | Select-Object -ExpandProperty location | Select-Object -ExpandProperty countryOrRegion # The two letter country code from where the sign-in occurred.
    "Latitude"                        = $Record | Select-Object -ExpandProperty location | Select-Object -ExpandProperty geoCoordinates | Select-Object -ExpandProperty Latitude # The latitude, in decimal, for the item.
    "Longitude"                       = $Record | Select-Object -ExpandProperty location | Select-Object -ExpandProperty geoCoordinates | Select-Object -ExpandProperty Longitude # The longitude, in decimal, for the item.
    "AuthenticationRequirement"       = $Record.AuthenticationRequirement # This holds the highest level of authentication needed through all the sign-in steps, for sign-in to succeed.
    "SignInEventTypes"                = $Record | Select-Object -ExpandProperty SignInEventTypes # Indicates the category of sign in that the event represents.
    "AuthenticationMethodsUsed"       = $Record | Select-Object -ExpandProperty AuthenticationMethodsUsed # The authentication methods used.

    # Status - The sign-in status. Includes the error code and description of the error (for a sign-in failure).
    # https://learn.microsoft.com/nb-no/graph/api/resources/signinstatus?view=graph-rest-beta
    "ErrorCode"                       = $Record | Select-Object -ExpandProperty status | Select-Object -ExpandProperty errorCode # Provides the 5-6 digit error code that's generated during a sign-in failure.
    "FailureReason"                   = $Record | Select-Object -ExpandProperty status | Select-Object -ExpandProperty failureReason # Provides the error message or the reason for failure for the corresponding sign-in activity.
    "AdditionalDetails"               = $Record | Select-Object -ExpandProperty status | Select-Object -ExpandProperty additionalDetails # Provides additional details on the sign-in activity.

    # AuthenticationDetails - The result of the authentication attempt and more details on the authentication method.
    # https://learn.microsoft.com/nb-no/graph/api/resources/authenticationdetail?view=graph-rest-beta
    "AuthenticationMethod"            = $Record.AuthDetailsAuthenticationMethod # The type of authentication method used to perform this step of authentication.
    "AuthenticationMethodDetail"      = $Record.AuthDetailsAuthenticationMethodDetail # Details about the authentication method used to perform this authentication step.
    "AuthenticationStepDateTime"      = $Record.AuthDetailsAuthenticationStepDateTime # Represents date and time information using ISO 8601 format and is always in UTC time.
    "AuthenticationStepRequirement"   = $Record.AuthDetailsAuthenticationStepRequirement # The step of authentication that this satisfied. 
    "AuthenticationStepResultDetail"  = $Record.AuthDetailsAuthenticationStepResultDetail # Details about why the step succeeded or failed. 
    "Succeeded"                       = $Record.AuthDetailsSucceeded # Indicates the status of the authentication step.

    # AuthenticationProcessingDetails - More authentication processing details, such as the agent name for PTA and PHS, or a server or farm name for federated authentication.
    "Domain Hint Present"             = ($Record | Select-Object -ExpandProperty AuthenticationProcessingDetails | Where-Object {$_.Key -eq 'Domain Hint Present'}).Value
    "Is CAE Token"                    = ($Record | Select-Object -ExpandProperty AuthenticationProcessingDetails | Where-Object {$_.Key -eq 'Is CAE Token'}).Value
    "Login Hint Present"              = ($Record | Select-Object -ExpandProperty AuthenticationProcessingDetails | Where-Object {$_.Key -eq 'Login Hint Present'}).Value
    "Oauth Scope Info"                = ($Record | Select-Object -ExpandProperty AuthenticationProcessingDetails | Where-Object {$_.Key -eq 'Oauth Scope Info'}).Value
    "Root Key Type"                   = ($Record | Select-Object -ExpandProperty AuthenticationProcessingDetails | Where-Object {$_.Key -eq 'Root Key Type'}).Value

    "ClientCredentialType"            = $Record.ClientCredentialType # Describes the credential type that a user client or service principal provided to Microsoft Entra ID to authenticate itself. You can review this property to track and eliminate less secure credential types or to watch for clients and service principals using anomalous credential types.
    "CredentialKeyId"                 = $Record.servicePrincipalCredentialKeyId # The unique identifier of the key credential used by the service principal to authenticate.
    "CredentialThumbprint"            = $Record.servicePrincipalCredentialThumbprint # The certificate thumbprint of the certificate used by the service principal to authenticate.
    "ConditionalAccessStatus"         = $Record.ConditionalAccessStatus # The status of the conditional access policy triggered.
    "CorrelationId"                   = $Record.CorrelationId # The identifier that's sent from the client when sign-in is initiated.
    "IncomingTokenType"               = $Record.IncomingTokenType # Indicates the token types that were presented to Microsoft Entra ID to authenticate the actor in the sign in. 
    "OriginalRequestId"               = $Record.OriginalRequestId # The request identifier of the first request in the authentication sequence.
    "IsInteractive"                   = $Record.IsInteractive # Indicates whether a user sign in is interactive. In interactive sign in, the user provides an authentication factor to Microsoft Entra ID. These factors include passwords, responses to MFA challenges, biometric factors, or QR codes that a user provides to Microsoft Entra ID or an associated app. In non-interactive sign in, the user doesn't provide an authentication factor. Instead, the client app uses a token or code to authenticate or access a resource on behalf of a user. Non-interactive sign ins are commonly used for a client to sign in on a user's behalf in a process transparent to the user.
    "ProcessingTimeInMilliseconds"    = $Record.ProcessingTimeInMilliseconds # The request processing time in milliseconds in AD STS.
    "ResourceDisplayName"             = $Record.ResourceDisplayName # The name of the resource that the user signed in to.
    "ResourceId"                      = $Record.ResourceId # The identifier of the resource that the user signed in to.
    "ResourceServicePrincipalId"      = $Record.ResourceServicePrincipalId # The identifier of the service principal representing the target resource in the sign-in event.
    "ResourceTenantId"                = $Record.ResourceTenantId # The tenant identifier of the resource referenced in the sign in.
    "RiskDetail"                      = $Record.RiskDetail # The reason behind a specific state of a risky user, sign-in, or a risk event.
    "RiskEventTypesV2"                = $Record | Select-Object -ExpandProperty riskEventTypes_v2 # The list of risk event types associated with the sign-in. --> RiskEventTypesV2 (Old)
    "RiskLevelAggregated"             = $Record.RiskLevelAggregated # The aggregated risk level. The value hidden means the user or sign-in wasn't enabled for Microsoft Entra ID Protection.
    "RiskLevelDuringSignIn"           = $Record.RiskLevelDuringSignIn # The risk level during sign-in. The value hidden means the user or sign-in wasn't enabled for Microsoft Entra ID Protection.
    "RiskState"                       = $Record.RiskState # The risk state of a risky user, sign-in, or a risk event.
    "SignInTokenProtectionStatus"     = $Record.SignInTokenProtectionStatus # Token protection creates a cryptographically secure tie between the token and the device it is issued to. This field indicates whether the signin token was bound to the device or not.
    "TokenIssuerName"                 = $Record.TokenIssuerName # The name of the identity provider.
    "TokenIssuerType"                 = $Record.TokenIssuerType # The type of identity provider.
    "UniqueTokenIdentifier"           = $Record.UniqueTokenIdentifier # A unique base64 encoded request identifier used to track tokens issued by Microsoft Entra ID as they're redeemed at resource providers.
    "SessionId"                       = $Record.SessionId # Identifier of the session that was generated during the sign-in. 
    "UserType"                        = $Record | Select-Object -ExpandProperty UserType | ForEach-Object { $_.Replace("member","Member") } | ForEach-Object { $_.Replace("guest","Guest") } # Identifies whether the user is a member or guest in the tenant.
    "AuthenticationProtocol"          = $Record.AuthenticationProtocol # Lists the protocol type or grant type used in the authentication.
    "OriginalTransferMethod"          = $Record.OriginalTransferMethod # Transfer method used to initiate a session throughout all subsequent request.
    "CrossTenantAccessType"           = $Record.CrossTenantAccessType # Describes the type of cross-tenant access used by the actor to access the resource.

    # MfaDetail - This property is deprecated.
    "AuthMethod"                      = $Record | Select-Object -ExpandProperty MfaDetail | Select-Object -ExpandProperty AuthMethod
    "AuthDetail"                      = $Record | Select-Object -ExpandProperty MfaDetail | Select-Object -ExpandProperty AuthDetail

    # DeviceDetail - The device information from where the sign-in occurred. Includes information such as deviceId, OS, and browser.
    # https://learn.microsoft.com/nb-no/graph/api/resources/devicedetail?view=graph-rest-beta
    "DeviceId"                        = $Record | Select-Object -ExpandProperty DeviceDetail | Select-Object -ExpandProperty DeviceId # Refers to the UniqueID of the device used for signing-in.
    "DisplayName"                     = $Record | Select-Object -ExpandProperty DeviceDetail | Select-Object -ExpandProperty DisplayName # Refers to the name of the device used for signing-in.
    "OperatingSystem"                 = $Record | Select-Object -ExpandProperty DeviceDetail | Select-Object -ExpandProperty OperatingSystem # Indicates the OS name and version used for signing-in.
    "Browser"                         = $Record | Select-Object -ExpandProperty DeviceDetail | Select-Object -ExpandProperty Browser # Indicates the browser information of the used for signing-in.
    "IsCompliant"                     = $Record | Select-Object -ExpandProperty DeviceDetail | Select-Object -ExpandProperty IsCompliant # Indicates whether the device is compliant or not.
    "IsManaged"                       = $Record | Select-Object -ExpandProperty DeviceDetail | Select-Object -ExpandProperty IsManaged # Indicates if the device is managed or not.
    "TrustType"                       = $Record | Select-Object -ExpandProperty DeviceDetail | Select-Object -ExpandProperty TrustType # Indicates information on whether the signed-in device is Workplace Joined, AzureAD Joined, Domain Joined.
    
    # NetworkLocationDetails - The network location details including the type of network used and its names.
    # https://learn.microsoft.com/nb-no/graph/api/resources/networklocationdetail?view=graph-rest-beta
    "NetworkType"                     = $NetworkType # Provides the type of network used when signing in.
    "NetworkNames"                    = $NetworkNames # Provides the name of the network used when signing in.
    "TrustedNamedLocation"            = $TrustedNamedLocation

    # Agent - Represents details about the agentic sign-in.
    # https://learn.microsoft.com/nb-no/graph/api/resources/agentic-agentsignin?view=graph-rest-beta
    "AgentType"                       = $Record | Select-Object -ExpandProperty agent | Select-Object -ExpandProperty agentType # The type of agent for agentic sign-ins.
    "ParentAppId"                     = $Record | Select-Object -ExpandProperty agent | Select-Object -ExpandProperty parentAppId # The ID of the parent application for agentic instances.

    # IsAgent
    # notAgentic --> No
    # agenticAppBuilder --> Yes
    # agenticApp --> Yes
    # agenticAppInstance --> Yes
    # unknownFutureValue --> No

    }

    $Results.Add($Line)
}

$Results | Export-Csv -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\CSV\Untouched.csv" -NoTypeInformation -Encoding UTF8

# XLSX
$Results | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\XLSX\Untouched.xlsx" -NoNumberConversion * -NoHyperLinkConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SignInLogsGraph" -CellStyleSB {
param($WorkSheet)
# BackgroundColor and FontColor for specific cells of TopRow
Set-Format -Address $WorkSheet.Cells["A1:BW1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
# HorizontalAlignment "Center" of columns A-BW
$WorkSheet.Cells["A:BW"].Style.HorizontalAlignment="Center"
}

# Microsoft Entra Workload ID Premium
# https://learn.microsoft.com/en-us/entra/id-protection/concept-workload-identity-risk
$RiskLevelDuringSignIn = (Import-Csv -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object RiskLevelDuringSignIn -Unique).RiskLevelDuringSignIn
if ("$RiskLevelDuringSignIn" -eq "hidden")
{
    Write-Host "[Info]  No Microsoft Entra Workload ID Premium detected" -ForegroundColor Red
}
else
{
    Write-Host "[Info]  Microsoft Entra Workload ID Premium detected" -ForegroundColor Green
}

$EndTime_Processing = (Get-Date)
$Time_Processing = ($EndTime_Processing-$StartTime_Processing)
('ServicePrincipalSignInLogs Processing duration:      {0} h {1} min {2} sec' -f $Time_Processing.Hours, $Time_Processing.Minutes, $Time_Processing.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#############################################################################################################################################################################################
#############################################################################################################################################################################################

Function Get-IPLocation {

$StartTime_DataEnrichment = (Get-Date)

# Count IP addresses
Write-Output "[Info]  Data Enrichment w/ IPinfo ..."
New-Item "$OUTPUT_FOLDER\IPAddress" -ItemType Directory -Force | Out-Null
$Data = Import-Csv -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object -ExpandProperty IpAddress

$Unique = $Data | Sort-Object -Unique
$Unique | Out-File "$OUTPUT_FOLDER\IPAddress\IP-All.txt" -Encoding UTF8

$Count = ($Unique | Measure-Object).Count
$UniqueIP = '{0:N0}' -f $Count
$Total = ($Data | Measure-Object).Count
Write-Output "[Info]  $UniqueIP IP addresses found ($Total)"

# IPv4
# https://ipinfo.io/bogon
$IPv4 = "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
$Private = "^(192\.168|10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.)"
$Special = "^(0\.0\.0\.0|127\.0\.0\.1|169\.254\.|224\.0\.0)"
Get-Content "$OUTPUT_FOLDER\IPAddress\IP-All.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Out-File "$OUTPUT_FOLDER\IPAddress\IPv4-All.txt" -Encoding UTF8
Get-Content "$OUTPUT_FOLDER\IPAddress\IP-All.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Where-Object {$_ -notmatch $Private} | Where-Object {$_ -notmatch $Special} | Out-File "$OUTPUT_FOLDER\IPAddress\IPv4.txt" -Encoding UTF8

# Count
$Total = (Get-Content "$OUTPUT_FOLDER\IPAddress\IPv4-All.txt" | Measure-Object).Count # Public (Unique) + Private (Unique) --> Note: Extracts IPv4 addresses of IPv4-compatible IPv6 addresses.
$Public = (Get-Content "$OUTPUT_FOLDER\IPAddress\IPv4.txt" | Measure-Object).Count # Public (Unique)
$UniquePublic = '{0:N0}' -f $Public
Write-Output "[Info]  $UniquePublic Public IPv4 addresses found ($Total)"

# IPv6
# https://ipinfo.io/bogon
$IPv6 = ":(?::[a-f\d]{1,4}){0,5}(?:(?::[a-f\d]{1,4}){1,2}|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}|:)|(?::(?:[a-f\d]{1,4})?|(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[a-f\d]{1,4}(?::[a-f\d]{1,4})?|))|(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[a-f\d]{1,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){0,2})|:))|(?:(?::[a-f\d]{1,4}){0,2}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,3}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))"
$Bogon = "^(::1|::ffff:|100::|2001:10::|2001:db8::|fc00::|fd00::|fe80::|fec0::|ff00::)"
Get-Content "$OUTPUT_FOLDER\IPAddress\IP-All.txt" | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Out-File "$OUTPUT_FOLDER\IPAddress\IPv6-All.txt" -Encoding UTF8
Get-Content "$OUTPUT_FOLDER\IPAddress\IP-All.txt" | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Where-Object {$_ -notmatch $Bogon} | Out-File "$OUTPUT_FOLDER\IPAddress\IPv6.txt" -Encoding UTF8

# Count
$Total = (Get-Content "$OUTPUT_FOLDER\IPAddress\IPv6-All.txt" | Measure-Object).Count # including Bogus IPv6 addresses (e.g. IPv4-compatible IPv6 addresses)
$Public = (Get-Content "$OUTPUT_FOLDER\IPAddress\IPv6.txt" | Measure-Object).Count
Write-Output "[Info]  $Public Public IPv6 addresses found ($Total)"

# IP.txt
Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\IPAddress\IP.txt" -Encoding UTF8 # Header

# IPv4.txt
if (Test-Path "$OUTPUT_FOLDER\IPAddress\IPv4.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\IPAddress\IPv4.txt").Length -gt 0kb)
    {
        Get-Content -Path "$OUTPUT_FOLDER\IPAddress\IPv4.txt" | Out-File "$OUTPUT_FOLDER\IPAddress\IP.txt" -Encoding UTF8 -Append
    }
}

# IPv6.txt
if (Test-Path "$OUTPUT_FOLDER\IPAddress\IPv6.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\IPAddress\IPv6.txt").Length -gt 0kb)
    {
        Get-Content -Path "$OUTPUT_FOLDER\IPAddress\IPv6.txt" | Out-File "$OUTPUT_FOLDER\IPAddress\IP.txt" -Encoding UTF8 -Append
    }
}

# Check IPinfo Subscription Plan (https://ipinfo.io/pricing)
if (Test-Path "$($IPinfo)")
{
    $Quota = & $IPinfo quota
    if ($Quota -eq "err: please login first to check quota")
    {
        # IPinfo Login
        & $IPinfo init "$Token" > $null
        $Quota = & $IPinfo quota
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
        Write-output "[Info]  IPinfo Subscription: Free ($TotalMonth Requests/Month)"
        Write-Output "[Info]  $RemainingMonth Requests left this month"
    }
}

# IPinfo CLI
if (Test-Path "$($IPinfo)")
{
    if (Test-Path "$OUTPUT_FOLDER\IPAddress\IP.txt")
    {
        if ((Get-Item "$OUTPUT_FOLDER\IPAddress\IP.txt").Length -gt 0kb)
        {
            # Internet Connectivity Check (Vista+)
            $NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]'{DCB00C01-570F-4A9B-8D69-199FDBA5723B}')).IsConnectedToInternet

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
                    New-Item "$OUTPUT_FOLDER\IPAddress\IPinfo" -ItemType Directory -Force | Out-Null
                    Get-Content "$OUTPUT_FOLDER\IPAddress\IP.txt" | & $IPinfo map | Out-File "$OUTPUT_FOLDER\IPAddress\IPinfo\Map.txt" -Encoding UTF8

                    # Access Token
                    # https://ipinfo.io/signup?ref=cli
                    if (!("$Token" -eq "access_token"))
                    {
                        # Summarize IPs
                        # https://ipinfo.io/summarize-ips

                        # TXT --> Top Privacy Services
                        [int]$Count = (Get-Content "$OUTPUT_FOLDER\IPAddress\IP.txt" | Measure-Object).Count
                        if ($Count -ge 10)
                        {
                            Get-Content -Path "$OUTPUT_FOLDER\IPAddress\IP.txt" | & $IPinfo summarize --token "$Token" | Out-File "$OUTPUT_FOLDER\IPAddress\IPinfo\Summary.txt"
                        }

                        # CSV
                        Get-Content "$OUTPUT_FOLDER\IPAddress\IP.txt" | & $IPinfo --csv --token "$Token" | Out-File "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo.csv" -Encoding UTF8

                        # Custom CSV (Free)
                        if ($PrivacyDetection -eq "False")
                        {
                            if (Test-Path "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo.csv")
                            {
                                if(Test-Csv -Path "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo.csv" -MaxLines 2)
                                {
                                    $IPinfoRecords = Import-Csv "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo.csv" -Delimiter "," -Encoding UTF8

                                    $Results = [Collections.Generic.List[PSObject]]::new()
                                    ForEach($IPinfoRecord in $IPinfoRecords)
                                    {
                                        $Line = [PSCustomObject]@{
                                            "IP"           = $IPinfoRecord.ip
                                            "City"         = $IPinfoRecord.city
                                            "Region"       = $IPinfoRecord.region
                                            "Country"      = $IPinfoRecord.country
                                            "Country Name" = $IPinfoRecord.country_name
                                            "EU"           = $IPinfoRecord.isEU
                                            "Location"     = $IPinfoRecord.loc
                                            "ASN"          = $IPinfoRecord | Select-Object -ExpandProperty org | ForEach-Object{($_ -split "\s+")[0]}
                                            "OrgName"      = $IPinfoRecord | Select-Object -ExpandProperty org | ForEach-Object {$_ -replace "^AS[0-9]+ "}
                                            "Postal Code"  = $IPinfoRecord.postal
                                            "Timezone"     = $IPinfoRecord.timezone
                                        }

                                        $Results.Add($Line)
                                    }

                                    $Results | Sort-Object {$_.IP -as [Version]} | Export-Csv -Path "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo-Custom.csv" -NoTypeInformation -Encoding UTF8
                                }
                            }

                            # Custom XLSX (Free)
                            if (Test-Path "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo-Custom.csv")
                            {
                                if(Test-Csv -Path "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo-Custom.csv" -MaxLines 2)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo-Custom.csv" -Delimiter "," | Sort-Object {$_.ip -as [Version]}
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo-Custom.xlsx" -NoNumberConversion * -NoHyperLinkConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -PivotRows "Country Name" -PivotData @{"IP"="Count"} -WorkSheetname "IPinfo (Free)" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
                                    # HorizontalAlignment "Center" of columns A-K
                                    $WorkSheet.Cells["A:K"].Style.HorizontalAlignment="Center"
                                    }
                                }
                            }
                        }

                        # Create HashTable and import 'IPinfo-Custom.csv'
                        $script:IPinfo_HashTable = @{}
                        if (Test-Path "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo-Custom.csv")
                        {
                            if(Test-Csv -Path "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo-Custom.csv" -MaxLines 2)
                            {
                                # Free
                                if ($PrivacyDetection -eq "False")
                                {
                                    Import-Csv -Path "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo-Custom.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $IPinfo_HashTable[$_.IP] = $_.City,$_.Region,$_.Country,$_."Country Name",$_.Location,$_.ASN,$_.OrgName,$_."Postal Code",$_.Timezone }
                                }

                                # Count Ingested Properties
                                $Count = $IPinfo_HashTable.Count
                                Write-Output "[Info]  Initializing 'IPinfo-Custom.csv' Lookup Table ($Count) ..."
                            }
                        }

                        # Create HashTable and import 'Status.csv'
                        $Status_HashTable = @{}
                        if (Test-Path "$SCRIPT_DIR\Config\Status.csv")
                        {
                            if(Test-Csv -Path "$SCRIPT_DIR\Config\Status.csv" -MaxLines 2)
                            {
                                Import-Csv "$SCRIPT_DIR\Config\Status.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $Status_HashTable[$_.ErrorCode] = $_.Status, $_.Message }
                            }
                        }
                        else
                        {
                            Write-Output "Status.csv NOT found."
                        }

                        # Hunt

                        # IPinfo Subscription: Free
                        if ($PrivacyDetection -eq "False")
                        {
                            if (Test-Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\CSV\Untouched.csv")
                            {
                                if(Test-Csv -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\CSV\Untouched.csv" -MaxLines 2)
                                {
                                    $Records = Import-Csv -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8

                                    # CSV
                                    $Results = [Collections.Generic.List[PSObject]]::new()

                                    ForEach($Record in $Records)
                                    {
                                        # ApplicationType
                                        if ($Record.AppOwnerTenantId -eq "72f988bf-86f1-41af-91ab-2d7cd011db47" -or $Record.AppOwnerTenantId -eq "f8cdef31-a31e-4b4a-93e4-5f571e91255a")
                                        {
                                            $ApplicationType = "First-Party Application" # Microsoft Application --> Traitorware?
                                        }
                                        else
                                        {
                                            $ApplicationType = "Third-Party Application" # Malware?
                                        }

                                        # Status
                                        [int]$ErrorCode = $Record | Select-Object -ExpandProperty ErrorCode

                                        # Check if HashTable contains IP
                                        if($Status_HashTable.ContainsKey("$ErrorCode"))
                                        {
                                            $Status = $Status_HashTable["$ErrorCode"][0]
                                        }
                                        else
                                        {
                                            $Status = "Failure"
                                        }

                                        # Authorization Error Codes (AADSTS) aka Entra ID Sign-in Error Codes
                                        # https://learn.microsoft.com/en-us/azure/active-directory/develop/reference-error-codes
                                        # https://login.microsoftonline.com/error
                                        # https://blog.icewolf.ch/archive/2021/02/04/hunting-for-basic-authentication-in-azuread/

                                        # IpAddress
                                        $IP = $Record.IpAddress

                                        # Check if HashTable contains IP
                                        if($IPinfo_HashTable.ContainsKey("$IP"))
                                        {
                                            $City        = $IPinfo_HashTable["$IP"][0]
                                            $Region      = $IPinfo_HashTable["$IP"][1]
                                            $Country     = $IPinfo_HashTable["$IP"][2]
                                            $CountryName = $IPinfo_HashTable["$IP"][3]
                                            $Location    = $IPinfo_HashTable["$IP"][4]
                                            $ASN         = $IPinfo_HashTable["$IP"][5] | ForEach-Object {$_ -replace "^AS"}
                                            $OrgName     = $IPinfo_HashTable["$IP"][6]
                                            $PostalCode  = $IPinfo_HashTable["$IP"][7]
                                            $Timezone    = $IPinfo_HashTable["$IP"][8]
                                        }
                                        else
                                        {
                                            $City        = ""
                                            $Region      = ""
                                            $Country     = ""
                                            $CountryName = ""
                                            $Location    = ""
                                            $ASN         = ""
                                            $OrgName     = ""
                                            $PostalCode  = ""
                                            $Timezone    = ""
                                        }

                                        $Line = [PSCustomObject]@{
                                            "Id"                           = $Record.Id
                                            "CreatedDateTime"              = $Record.CreatedDateTime
                                            "AppId"                        = $Record.AppId
                                            "AppDisplayName"               = $Record.AppDisplayName
                                            "AppOwnerTenantId"             = $Record.AppOwnerTenantId
                                            "ApplicationType"              = $ApplicationType
                                            "ResourceOwnerTenantId"        = $Record.ResourceOwnerTenantId
                                            "ServicePrincipalId"           = $Record.ServicePrincipalId
                                            "ServicePrincipalName"         = $Record.ServicePrincipalName
                                            "ClientCredentialType"         = $Record.ClientCredentialType
                                            "CredentialKeyId"              = $Record.CredentialKeyId
                                            "CredentialThumbprint"         = $Record.CredentialThumbprint
                                            "ConditionalAccessStatus"      = $Record.ConditionalAccessStatus
                                            "OriginalRequestId"            = $Record.OriginalRequestId
                                            "SignInEventType"              = $Record.SignInEventTypes
                                            "TokenIssuerName"              = $Record.TokenIssuerName
                                            "TokenIssuerType"              = $Record.TokenIssuerType
                                            "ProcessingTimeInMilliseconds" = $Record.ProcessingTimeInMilliseconds
                                            "RiskLevelAggregated"          = $Record.RiskLevelAggregated
                                            "RiskLevelDuringSignIn"        = $Record.RiskLevelDuringSignIn
                                            "RiskState"                    = $Record.RiskState
                                            "RiskDetail"                   = $Record.RiskDetail
                                            "RiskEventTypesV2"             = $Record.RiskEventTypesV2
                                            "ResourceDisplayName"          = $Record.ResourceDisplayName
                                            "ResourceId"                   = $Record.ResourceId
                                            "AuthenticationMethodsUsed"    = $Record.AuthenticationMethodsUsed
                                            "ErrorCode"                    = $Record.ErrorCode
                                            "FailureReason"                = $Record.FailureReason
                                            "AdditionalDetails"            = $Record.AdditionalDetails
                                            "Status"                       = $Status
                                            "DeviceId"                     = $Record.DeviceId
                                            "DisplayName"                  = $Record.DisplayName
                                            "OperatingSystem"              = $Record.OperatingSystem
                                            "Browser"                      = $Record.Browser
                                            "IsCompliant"                  = $Record.IsCompliant
                                            "IsManaged"                    = $Record.IsManaged
                                            "TrustType"                    = $Record.TrustType
                                            "AuthMethod"                   = $Record.AuthMethod
                                            "AuthDetail"                   = $Record.AuthDetail
                                            "AuthenticationProtocol"       = $Record.AuthenticationProtocol
                                            "OriginalTransferMethod"       = $Record.OriginalTransferMethod
                                            "IPAddress"                    = $IP
                                            "City"                         = $City
                                            "Region"                       = $Region
                                            "Country"                      = $Country
                                            "Country Name"                 = $CountryName
                                            "Location"                     = $Location
                                            "ASN"                          = $ASN
                                            "OrgName"                      = $OrgName
                                            "Postal Code"                  = $PostalCode
                                            "Timezone"                     = $Timezone
                                            "UserAgent"                    = $Record.UserAgent
                                            "TrustedNamedLocation"         = $Record.TrustedNamedLocation
                                            "UniqueTokenIdentifier"        = $Record.UniqueTokenIdentifier
                                            "SessionId"                    = $Record.SessionId
                                            "CorrelationId"                = $Record.CorrelationId
                                            "IncomingTokenType"            = $Record.IncomingTokenType
                                            "SignInTokenProtectionStatus"  = $Record.SignInTokenProtectionStatus
                                            "CrossTenantAccessType"        = $Record.CrossTenantAccessType
                                            "AgentType"                    = $Record.AgentType
                                            "ParentAppId"                  = $Record.ParentAppId
                                        }

                                        $Results.Add($Line)
                                    }

                                    $Results | Sort-Object {$_.IP -as [Version]} | Export-Csv -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\CSV\Hunt.csv" -NoTypeInformation -Encoding UTF8
                                }
                            }

                            # XLSX
                            if (Test-Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\CSV\Hunt.csv")
                            {
                                if(Test-Csv -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\CSV\Hunt.csv" -MaxLines 2)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\CSV\Hunt.csv" -Delimiter "," | Sort-Object { $_.CreatedDateTime -as [datetime] } -Descending
                                    
                                    # AppDisplayName with only non-alphanumeric characters
                                    [array]$RegEx01 = $Import | Where-Object { $_.AppDisplayName -match "^[^a-zA-Z0-9]+$" } | Select-Object -ExpandProperty AppDisplayName
                                    $Count = ($RegEx01 | Select-Object AppId -Unique | Measure-Object).Count
                                    if ($Count -gt 0)
                                    {
                                        Write-Host "[Alert] Suspicious OAuth Application detected: AppDisplayName w/ only non-alphanumeric characters ($Count)" -ForegroundColor Red
                                    }


                                    # Common Naming Patterns of Malicious OAuth Applications
                                    [array]$RegEx02 = $Import | Where-Object { $_.AppDisplayName -match "^(test|test app|app test|apptest)$" } | Select-Object -ExpandProperty AppDisplayName
                                    $Count = ($RegEx02 | Select-Object AppId -Unique | Measure-Object).Count
                                    if ($Count -gt 0)
                                    {
                                        Write-Host "[Alert] Suspicious OAuth Application detected: Common Naming Pattern of Malicious OAuth Applications ($Count)" -ForegroundColor Red
                                    }

                                    # UPN Naming Pattern (incl. B2B Collaboration User)
                                    [array]$RegEx03 = $Import | Where-Object { $_.AppDisplayName -match "^([\w-\.]+)(#EXT#)?@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([\w-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$" } | Select-Object -ExpandProperty AppDisplayName
                                    $Count = ($RegEx03 | Select-Object AppId -Unique | Measure-Object).Count
                                    if ($Count -gt 0)
                                    {
                                        Write-Host "[Alert] Suspicious OAuth Application detected: UPN Naming Pattern ($Count)" -ForegroundColor Red
                                    }
                                    
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\XLSX\Hunt.xlsx" -NoNumberConversion * -NoHyperLinkConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -WorkSheetname "Hunt" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    Set-Format -Address $WorkSheet.Cells["A1:BI1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
                                    # HorizontalAlignment "Center" of columns A-AY and BA-BI
                                    $WorkSheet.Cells["A:AY"].Style.HorizontalAlignment="Center"
                                    $WorkSheet.Cells["BA:BI"].Style.HorizontalAlignment="Center"

                                    # ConditionalFormatting - AppDisplayName
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("LethalForensics_IR-App",$D1)))' -BackgroundColor $Green

                                    foreach ($AppDisplayName in $RegEx01) 
                                    {
                                        $ConditionValue = 'EXACT("{0}",$D1)' -f $AppDisplayName
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx01
                                    }

                                    foreach ($AppDisplayName in $RegEx02) 
                                    {
                                        $ConditionValue = 'EXACT("{0}",$D1)' -f $AppDisplayName
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx03
                                    }

                                    foreach ($AppDisplayName in $RegEx03) 
                                    {
                                        $ConditionValue = 'EXACT("{0}",$D1)' -f $AppDisplayName
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx04
                                    }
                                    
                                    # ConditionalFormatting - AppId
                                    $Cells = "C:D"
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("29d9ed98-a469-4536-ade2-f981bc1d605e",$C1)))' -BackgroundColor Red # Microsoft Authentication Broker
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("2793995e-0a7d-40d7-bd35-6968ba142197",$C1)))' -BackgroundColor Yellow # 'My Apps' portal --> Threat Actor may checks how many other third party services they can access from that compromised account.
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("aebc6443-996d-45c2-90f0-388ff96faa56",$C1)))' -BackgroundColor Yellow # Visual Studio Code
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("fb4c470b-9133-42c7-8db0-f786adc04715",$C1)))' -BackgroundColor $Green # Invictus Cloud Insights

                                    # ConditionalFormatting - AppOwnerTenantId
                                    $Cells = "E:F"
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("72f988bf-86f1-41af-91ab-2d7cd011db4",$E1)))' -BackgroundColor Red # Microsoft Application
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("f8cdef31-a31e-4b4a-93e4-5f571e91255a",$E1)))' -BackgroundColor Red # Microsoft Application

                                    # ConditionalFormatting - RiskState
                                    # https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-remediate-unblock
                                    # https://learn.microsoft.com/en-us/entra/id-protection/concept-workload-identity-risk
                                    $Cells = "U:U"
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("atRisk",$U1)))' -BackgroundColor Red
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("confirmedCompromised",$U1)))' -BackgroundColor Red
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("confirmedSafe",$U1)))' -BackgroundColor $Green
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("dismissed",$U1)))' -BackgroundColor $Orange # System-based Remediation of risky workload identities --> Check 'RiskDetail' for more information.
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("remediated",$U1)))' -BackgroundColor Yellow # Remediation of risky workload identities (e.g. rotating or removing of compromised credentials, rotating associated secrets) --> Check 'RiskDetail' for more information.

                                    # ConditionalFormatting - RiskLevelAggregated
                                    $Cells = "S:S"
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("high",$S1)))' -BackgroundColor Red
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("medium",$S1)))' -BackgroundColor $Orange
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("low",$S1)))' -BackgroundColor Yellow

                                    # ConditionalFormatting - RiskLevelDuringSignIn
                                    $Cells = "T:T"
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("high",$T1)))' -BackgroundColor Red
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("medium",$T1)))' -BackgroundColor $Orange
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("low",$T1)))' -BackgroundColor Yellow

                                    # ConditionalFormatting - RiskEventTypesV2
                                    $Cells = "W:W"
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("leakedCredentials",$W1)))' -BackgroundColor Red

                                    # ConditionalFormatting - ErrorCode
                                    $Cells = "AA:AB"
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("50053",$AA1)))' -BackgroundColor Red # Sign-in was blocked because it came from an IP address with malicious activity
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("90095",$AA1)))' -BackgroundColor Red # Admin consent is required for the permissions requested by this application. An admin consent request may be sent to the admin.
                                    
                                    # ConditionalFormatting - TrustedNamedLocation
                                    $Cells = "BA:BA"
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Yes",$BA1)))' -BackgroundColor $Green # Trusted IP Ranges
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("No",$BA1)))' -BackgroundColor Red # Untrusted Location

                                    # Iterating over the Application-Blacklist HashTable
                                    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
                                    {
                                        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$C1)))' -f $AppId
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
                                    }

                                    # Iterating over the ASN-Blacklist HashTable
                                    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AV1)))' -f $ASN
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["AV:AW"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red

                                        $ConditionValue = '=AND(NOT(ISERROR(FIND("{0}",$AV1))),$BC1<>"")' -f $ASN
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["BC:BC"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # Colorize also the corresponding SessionId
                                    }

                                    # Iterating over the Country-Blacklist HashTable
                                    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AT1)))' -f $Country
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["AS:AT"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }

                                    # Iterating over the UserAgent-Blacklist HashTable
                                    foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
                                    {
                                        $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AZ1)))' -f $UserAgent
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["AZ:AZ"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
                                    }

                                    }
                                }
                            }
                        }

                        # File Size (XLSX)
                        if (Test-Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\XLSX\Hunt.xlsx")
                        {
                            $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\XLSX\Hunt.xlsx").Length)
                            Write-Output "[Info]  File Size (XLSX): $Size"
                        }
                    }
                    else
                    {
                        Write-Output "[Info]  IPinfo Access Token NOT found. Please sign up for free."
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

$EndTime_DataEnrichment = (Get-Date)
$Time_DataEnrichment = ($EndTime_DataEnrichment-$StartTime_DataEnrichment)
('ServicePrincipalSignInLogs Data Enrichment duration: {0} h {1} min {2} sec' -f $Time_DataEnrichment.Hours, $Time_DataEnrichment.Minutes, $Time_DataEnrichment.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Stats

Function Get-Stats {

$StartTime_Stats = (Get-Date)

# Stats
Write-Output "[Info]  Creating Hunting Stats ..."
New-Item "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats" -ItemType Directory -Force | Out-Null

# Data Import
$script:Hunt      = Import-Csv "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8
$script:Untouched = Import-Csv -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8

# AgentType (Stats)
$Total = ($Untouched | Select-Object AgentType | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object AgentType | Select-Object @{Name='AgentType'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\AgentType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "NetworkNames" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# AppDisplayName (Stats)
$Count = ($Untouched | Select-Object ServicePrincipalId -Unique | Measure-Object).Count
$WorkloadIdentity = '{0:N0}' -f $Count
Write-Output "[Info]  $WorkloadIdentity Workload Identities found"

$Total = ($Untouched | Select-Object AppDisplayName | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object AppDisplayName,AppId,AppOwnerTenantId | Select-Object @{Name='AppDisplayName'; Expression={ $_.Values[0] }},@{Name='AppId'; Expression={ $_.Values[1] }},@{Name='AppOwnerTenantId'; Expression={ $_.Values[2] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\AppDisplayName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AppDisplayName" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns B-E
    $WorkSheet.Cells["B:E"].Style.HorizontalAlignment="Center"

    # ConditionalFormatting - AppDisplayName 
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("LethalForensics_IR-App",$A1)))' -BackgroundColor $Green

    foreach ($AppDisplayName in $RegEx01) 
    {
        $ConditionValue = 'EXACT("{0}",$A1)' -f $AppDisplayName
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx01
    }

    foreach ($AppDisplayName in $RegEx02) 
    {
        $ConditionValue = 'EXACT("{0}",$A1)' -f $AppDisplayName
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx03
    }

    foreach ($AppDisplayName in $RegEx03) 
    {
        $ConditionValue = 'EXACT("{0}",$A1)' -f $AppDisplayName
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx04
    }

    # ConditionalFormatting - AppId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["B:B"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("fb4c470b-9133-42c7-8db0-f786adc04715",$B1)))' -BackgroundColor $Green # Invictus Cloud Insights

    # ConditionalFormatting - AppOwnerTenantId
    $Cells = "C:C"
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("72f988bf-86f1-41af-91ab-2d7cd011db4",$C1)))' -BackgroundColor Red # Microsoft Application
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("f8cdef31-a31e-4b4a-93e4-5f571e91255a",$C1)))' -BackgroundColor Red # Microsoft Application
    
    # Iterating over the Application-Blacklist HashTable
    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
    {
        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$B1)))' -f $AppId
        Add-ConditionalFormatting -Address $WorkSheet.Cells["B:B"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
    }

    }
}

# AppDisplayName / AppId / AppOwnerTenantId / ApplicationType (Stats)
$Applications = ($Untouched | Select-Object AppId -Unique | Sort-Object AppId).AppId
$Stats = [Collections.Generic.List[PSObject]]::new()
ForEach($AppId in $Applications)
{
    $AppDisplayName = $Untouched | Where-Object {$_.AppId -eq "$AppId"} | Select-Object -ExpandProperty AppDisplayName -Unique
    $AppOwnerTenantId = $Untouched  | Where-Object {$_.AppId -eq "$AppId"} | Select-Object -ExpandProperty AppOwnerTenantId -Unique

    if ($AppOwnerTenantId -eq "72f988bf-86f1-41af-91ab-2d7cd011db47" -or $AppOwnerTenantId -eq "f8cdef31-a31e-4b4a-93e4-5f571e91255a")
    {
        $ApplicationType = "First-Party Application" # Microsoft Application --> Traitorware?
    }
    else
    {
        $ApplicationType = "Third-Party Application" # Malware?
    }

    $Line = [PSCustomObject]@{
        "AppDisplayName"   = $AppDisplayName
        "AppId"            = $AppId
        "AppOwnerTenantId" = $AppOwnerTenantId
        "ApplicationType"  = $ApplicationType
    }

    $Stats.Add($Line)
}

$Total = ($Stats | Select-Object AppId -Unique | Measure-Object).Count
$FirstPartyAppCount = ($Stats | Where-Object { $_.ApplicationType -eq "First-Party Application" } | Measure-Object).Count
$ThirdPartyAppCount = ($Stats | Where-Object { $_.ApplicationType -eq "Third-Party Application" } | Measure-Object).Count
$FirstPartyApps = '{0:N0}' -f $FirstPartyAppCount
$ThirdPartyApps = '{0:N0}' -f $ThirdPartyAppCount
Write-Output "[Info]  $FirstPartyApps First-Party Application(s) found ($Total)"
Write-Output "[Info]  $ThirdPartyApps Third-Party Application(s) found ($Total)"

# XLSX
$Stats | Sort-Object AppDisplayName | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\AppDisplayName-ApplicationType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Applications" -CellStyleSB {
param($WorkSheet)
# BackgroundColor and FontColor for specific cells of TopRow
$BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
# HorizontalAlignment "Center" of column B-D
$WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"

# ConditionalFormatting - AppDisplayName 
Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("LethalForensics_IR-App",$A1)))' -BackgroundColor $Green

foreach ($AppDisplayName in $RegEx01) 
{
    $ConditionValue = 'EXACT("{0}",$A1)' -f $AppDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx01
}

foreach ($AppDisplayName in $RegEx02) 
{
    $ConditionValue = 'EXACT("{0}",$A1)' -f $AppDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx03
}

foreach ($AppDisplayName in $RegEx03) 
{
    $ConditionValue = 'EXACT("{0}",$A1)' -f $AppDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # RegEx04
}

# ConditionalFormatting - AppId
Add-ConditionalFormatting -Address $WorkSheet.Cells["B:B"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("fb4c470b-9133-42c7-8db0-f786adc04715",$B1)))' -BackgroundColor $Green # Invictus Cloud Insights

# Iterating over the Application-Blacklist HashTable
foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
{
    $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
    $ConditionValue = 'NOT(ISERROR(FIND("{0}",$B1)))' -f $AppId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["B:B"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
}

}

# ASN / Status (Stats)
$Total = ($Hunt | Select-Object ASN | Where-Object {$_.ASN -ne '' } | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Hunt | Select-Object ASN,OrgName,Status | Where-Object {$_.ASN -ne '' } | Where-Object { $null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value}) } | Group-Object ASN,OrgName,Status | Select-Object @{Name='ASN'; Expression={ $_.Values[0] }},@{Name='OrgName'; Expression={ $_.Values[1] }},@{Name='Status'; Expression={ $_.Values[2] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\ASN.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ASN" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-E
    $WorkSheet.Cells["A:E"].Style.HorizontalAlignment="Center"

    # Iterating over the ASN-Blacklist HashTable
    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$A1)))' -f $ASN
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:E"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    }
}

# ClientCredentialType (Stats)
# Note: Describes the credential type that a user client or service principal provided to Microsoft Entra ID to authenticate itself.
$Total = ($Untouched | Select-Object ClientCredentialType | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object ClientCredentialType | Select-Object @{Name='ClientCredentialType';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\ClientCredentialType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ClientCredentialType" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# CredentialKeyId / ClientCredentialType (Stats)
$Count = ($Untouched | Select-Object CredentialKeyId -Unique | Measure-Object).Count
$CredentialKeyId = '{0:N0}' -f $Count
Write-Output "[Info]  $CredentialKeyId Credential Key Identifier found"

$Total = ($Untouched | Select-Object CredentialKeyId | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object CredentialKeyId,ClientCredentialType | Select-Object @{Name='CredentialKeyId'; Expression={ $_.Values[0] }},@{Name='ClientCredentialType'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\CredentialKeyId.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "CredentialKeyId" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-D
    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
    }
}

# Possible Values:
# certificate
# clientAssertion - In OAuth 2.0, client assertion is a efficient and secure method for client authentication. Compared to the traditional client ID and secret, client assertion uses JSON Web Tokens (JWT) to enhance security and flexibility, making the authentication process more reliable and informative.
# clientSecret
# federatedIdentityCredential
# managedIdentity
# none
# unknownFutureValue

# ConditionalAccessStatus (Stats)
$Total = ($Untouched | Select-Object ConditionalAccessStatus | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object ConditionalAccessStatus | Select-Object @{Name='ConditionalAccessStatus'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\ConditionalAccessStatus.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ConditionalAccessStatus" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }

    # Workload Identities Premium
    $ConditionalAccessStatus = ($Stats | Where-Object { $_.ConditionalAccessStatus -eq "notApplied" } | Select-Object PercentUse).PercentUse
    if ($ConditionalAccessStatus -eq "100,00 %")
    {
        Write-Host "[Alert] No Conditional Access Policy for Workload Identities applied" -ForegroundColor Red
    }
}

# Conditional Access Status (Investigating Sign-Ins with CA applied)
# notApplied: No policy applied to the user and application during sign-in.
# success:    One or more conditional access policies applied to the user and application (but not necessarily the other conditions) during sign-in.
# failure:    The sign-in satisfied the user and application condition of at least one Conditional Access policy and grant controls are either not satisfied or set to block access.

# Note: Conditional Access policies are enforced after first-factor authentication is completed. Conditional Access isn't intended to be an organization's first line of defense for scenarios like denial-of-service (DoS) attacks, but it can use signals from these events to determine access.

# Country / Country Name (Stats)
$Total = ($Hunt | Select-Object Country | Where-Object {$_.Country -ne '' } | Measure-Object).Count
if ($Total -ge "1")
{       
    $Stats = $Hunt | Select-Object Country,"Country Name" | Where-Object {$_.Country -ne '' } | Where-Object { $null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value}) } | Group-Object Country,"Country Name" | Select-Object @{Name='Country'; Expression={ $_.Values[0] }},@{Name='Country Name'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\Country.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Countries" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-D
    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"

    # Iterating over the Country-Blacklist HashTable
    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$B1)))' -f $Country
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    }

    $Countries = ($Hunt | Select-Object Country -Unique | Where-Object { $_.Country -ne '' } | Measure-Object).Count
    $Cities = ($Hunt | Select-Object City -Unique | Where-Object { $_.City -ne '' } | Measure-Object).Count
    Write-Output "[Info]  $Countries Countries and $Cities Cities found"
}

# ErrorCode / Status (Stats)
$Total = ($Hunt | Select-Object ErrorCode | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Hunt | Select-Object Status,ErrorCode,FailureReason,AdditionalDetails | Group-Object Status,ErrorCode,FailureReason,AdditionalDetails | Select-Object @{Name='Status'; Expression={ $_.Values[0] }},@{Name='ErrorCode'; Expression={ $_.Values[1] }},@{Name='FailureReason'; Expression={ $_.Values[2] }},@{Name='AdditionalDetails'; Expression={ $_.Values[3] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\ErrorCode.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ErrorCode" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-B and E-F
    $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
    $WorkSheet.Cells["E:F"].Style.HorizontalAlignment="Center"
    # ConditionalFormatting - Suspicious Error Codes
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("50034",$B1)))' -BackgroundColor Red # "The user account does not exist in the tenant directory." --> involving non-existent user accounts
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("50053",$B1)))' -BackgroundColor Red # Sign-in was blocked because it came from an IP address with malicious activity or The account is locked, you've tried to sign in too many times with an incorrect user ID or password.
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("50126",$B1)))' -BackgroundColor Red # "Error validating credentials due to invalid username or password." --> Failed authentication attempts (Password Spraying Attack): Identify a traditional password spraying attack where a high number of users fail to authenticate from one single source IP in a short period of time.
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("90094",$B1)))' -BackgroundColor Red # Admin consent is required for the permissions requested by this application.
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("90095",$B1)))' -BackgroundColor Red # Admin consent is required for the permissions requested by this application. An admin consent request may be sent to the admin.
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("500121",$B1)))' -BackgroundColor Red # "Authentication failed during strong authentication request." --> MFA Fatigue aka MFA Prompt Bombing
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("530032",$B1)))' -BackgroundColor Red # User blocked due to risk on home tenant.
    }
}

# IPAddress / Country Name (Stats)
$Total = ($Hunt | Select-Object IPAddress,"Country Name" | Where-Object {$_."Country Name" -ne '' } | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Hunt | Select-Object IPAddress,Country,"Country Name",ASN,OrgName | Where-Object {$_.IPAddress -ne '' } | Where-Object {$_."Country Name" -ne '' } | Where-Object { $null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value}) } | Group-Object IPAddress,Country,"Country Name",ASN,OrgName | Select-Object @{Name='IPAddress'; Expression={ $_.Values[0] }},@{Name='Country'; Expression={ $_.Values[1] }},@{Name='Country Name'; Expression={ $_.Values[2] }},@{Name='ASN'; Expression={ $_.Values[3] }},@{Name='OrgName'; Expression={ $_.Values[4] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\IPAddress.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "IPAddress" -CellStyleSB {
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
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$C1)))' -f $Country
        Add-ConditionalFormatting -Address $WorkSheet.Cells["B:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    }
}

# NetworkNames (Stats)
$Total = ($Untouched | Select-Object NetworkNames | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object NetworkNames | Select-Object @{Name='NetworkNames'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\NetworkNames.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "NetworkNames" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# ResourceDisplayName (Stats)
$Count = ($Untouched | Select-Object ResourceId | Sort-Object ResourceId -Unique | Measure-Object).Count
$ResourceId = '{0:N0}' -f $Count
Write-Output "[Info]  $ResourceId Resource(s) found"

$Total = ($Untouched | Select-Object ResourceId | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Select-Object @{Name='ResourceDisplayName'; Expression={if($_.ResourceDisplayName){$_.ResourceDisplayName}else{'N/A'}}},ResourceId | Group-Object ResourceDisplayName,ResourceId | Select-Object @{Name='ResourceDisplayName'; Expression={ $_.Values[0] }},@{Name='ResourceId'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\ResourceDisplayName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ResourceDisplayName" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns B-D
    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
    }
}

# RiskDetail (Stats)
$Total = ($Untouched | Select-Object RiskDetail | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object RiskDetail | Select-Object @{Name='RiskDetail';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\RiskDetail.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskDetail" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# RiskEventTypesV2 (Stats)
$Total = ($Untouched | Select-Object RiskEventTypesV2 | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object RiskEventTypesV2 | Select-Object @{Name='RiskEventTypesV2';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\RiskEventTypesV2.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskEventTypesV2" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# RiskLevelDuringSignIn (Stats)
$Total = ($Untouched | Select-Object RiskLevelDuringSignIn | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object RiskLevelDuringSignIn | Select-Object @{Name='RiskLevelDuringSignIn';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\RiskLevelDuringSignIn.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskLevelDuringSignIn" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# ServicePrincipalName (Stats)
$Total = ($Untouched | Select-Object CredentialKeyId | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object ServicePrincipalName,ServicePrincipalId,CredentialKeyId,ClientCredentialType | Select-Object @{Name='ServicePrincipalName'; Expression={ $_.Values[0] }},@{Name='ServicePrincipalId'; Expression={ $_.Values[1] }},@{Name='CredentialKeyId'; Expression={ $_.Values[2] }},@{Name='ClientCredentialType'; Expression={ $_.Values[3] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\ServicePrincipalName.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ServicePrincipalName" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-F
    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"

    # ConditionalFormatting - ServicePrincipalName 
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("LethalForensics_IR-App",$A1)))' -BackgroundColor $Green

    # ConditionalFormatting - ServicePrincipalId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["B:B"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("fb4c470b-9133-42c7-8db0-f786adc04715",$B1)))' -BackgroundColor $Green # Invictus Cloud Insights

    # Iterating over the Application-Blacklist HashTable
    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
    {
        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$B1)))' -f $AppId
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:F"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
    }

    }
}

# ServicePrincipalName / CredentialKeyId (Stats)
$ServicePrincipalIds = ($Untouched | Select-Object ServicePrincipalId -Unique | Sort-Object ServicePrincipalId).ServicePrincipalId

$Stats = [Collections.Generic.List[PSObject]]::new()
ForEach($ServicePrincipalId in $ServicePrincipalIds)
{
    $Count = ($Untouched | Where-Object {$_.ServicePrincipalId -eq "$ServicePrincipalId"} | Select-Object CredentialKeyId -Unique | Measure-Object).Count
    $ServicePrincipalName = $Untouched | Where-Object {$_.ServicePrincipalId -eq "$ServicePrincipalId"} | Select-Object ServicePrincipalName -Unique

    $Line = [PSCustomObject]@{
        "ServicePrincipalName" = $ServicePrincipalName.ServicePrincipalName
        "ServicePrincipalId"   = $ServicePrincipalId
        "Count"                = $Count
    }

    $Stats.Add($Line)
}

# XLSX
$Stats | Sort-Object ServicePrincipalName | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\ServicePrincipalName-CredentialKeyId.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Number of Credentials" -CellStyleSB {
param($WorkSheet)
# BackgroundColor and FontColor for specific cells of TopRow
$BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
# HorizontalAlignment "Center" of column B-C
$WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"

# ConditionalFormatting - ServicePrincipalName 
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("LethalForensics_IR-App",$A1)))' -BackgroundColor $Green

    # ConditionalFormatting - ServicePrincipalId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["B:B"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("fb4c470b-9133-42c7-8db0-f786adc04715",$B1)))' -BackgroundColor $Green # Invictus Cloud Insights

# Iterating over the Application-Blacklist HashTable
foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
{
    $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
    $ConditionValue = 'NOT(ISERROR(FIND("{0}",$B1)))' -f $AppId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
}

}

# SignInTokenProtectionStatus (Stats)
$Total = ($Untouched | Select-Object SignInTokenProtectionStatus | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object SignInTokenProtectionStatus | Select-Object @{Name='SignInTokenProtectionStatus';Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\SignInTokenProtectionStatus.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SignInTokenProtectionStatus" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# Status (Stats)
$Total = ($Hunt | Select-Object Status | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Hunt | Group-Object Status | Select-Object @{Name='Status'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\Status.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Status" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# TrustedNamedLocation (Stats)
$Total = ($Hunt | Select-Object TrustedNamedLocation | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Hunt | Group-Object TrustedNamedLocation | Select-Object @{Name='TrustedNamedLocation'; Expression={ $_.Values[0] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\TrustedNamedLocation.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "TrustedNamedLocation" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"

    # ConditionalFormatting - TrustedNamedLocation
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Yes",$A1)))' -BackgroundColor $Green # Trusted IP Ranges
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("No",$A1)))' -BackgroundColor Red # Untrusted Location

    }
}

# UserAgent (Stats)
$Total = ($Untouched | Select-Object UserAgent | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object UserAgent | Select-Object @{Name='UserAgent';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\UserAgent.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserAgent" -CellStyleSB {
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

#############################################################################################################################################################################################

# Line Charts
New-Item "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\LineCharts" -ItemType Directory -Force | Out-Null

# Success (Sign-Ins)
$Total = ($Hunt | Where-Object { $_.Status -eq 'Success' } | Select-Object IPAddress | Measure-Object).Count
$Count = ($Hunt | Where-Object { $_.Status -eq 'Success' } | Select-Object IPAddress -Unique | Measure-Object).Count
$UniqueSuccesses = '{0:N0}' -f $Count
Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\IPAddress\Success.txt" -Encoding UTF8 # Header
$Hunt | Where-Object { $_.Status -eq 'Success' } | Select-Object -ExpandProperty IPAddress -Unique | Out-File "$OUTPUT_FOLDER\IPAddress\Success.txt" -Append
if ($Count -ge 1)
{
    Write-Output "[Info]  $UniqueSuccesses successful Sign-Ins found ($Total)"
}
else
{
    Write-Output "[Info]  0 successful Sign-Ins found"
}

# Authentication: Success (Line Chart) --> Successful Sign-Ins per day (Sign-In Frequency)
$Import = $Hunt | Where-Object { $_.Status -eq 'Success' } | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Select-Object Count,@{Name='CreatedDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreatedDateTime -as [datetime] }
$Count = ($Import | Measure-Object).Count
if ($Count -gt 5)
{
    $ChartDefinition = New-ExcelChartDefinition -XRange CreatedDateTime -YRange Count -Title "Successful Sign-Ins" -ChartType Line -NoLegend -Width 1200
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\LineCharts\Success.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
}

# Success (Map)
if (Test-Path "$OUTPUT_FOLDER\IPAddress\Success.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\IPAddress\Success.txt").Length -gt 0kb)
    {
        # Internet Connectivity Check (Vista+)
        $NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]'{DCB00C01-570F-4A9B-8D69-199FDBA5723B}')).IsConnectedToInternet

        if (!($NetworkListManager -eq "True"))
        {
            Write-Host "[Error] Your computer is NOT connected to the Internet. IP addresses cannot be checked via IPinfo API." -ForegroundColor Red
        }
        else
        {
            # Check if IPinfo.io is reachable
            if (!(Test-Connection -ComputerName ipinfo.io -Count 1 -Quiet))
            {
                Write-Host "[Error] ipinfo.io is NOT reachable. IP addresses cannot be checked via IPinfo API." -ForegroundColor Red
            }
            else
            {
                # Map IPs
                Get-Content "$OUTPUT_FOLDER\IPAddress\Success.txt" | & $IPinfo map | Out-File "$OUTPUT_FOLDER\IPAddress\IPinfo\Map_Success.txt"
            }
        }
    }
}

# Failure (Sign-Ins)
$Total = ($Hunt | Where-Object { $_.Status -eq 'Failure' } | Select-Object IPAddress | Measure-Object).Count
$Count = ($Hunt | Where-Object { $_.Status -eq 'Failure' } | Select-Object IPAddress -Unique | Measure-Object).Count
$UniqueFailures = '{0:N0}' -f $Count
Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\IPAddress\Failure.txt" -Encoding UTF8 # Header
$Hunt | Where-Object { $_.Status -eq 'Failure' } | Select-Object -ExpandProperty IPAddress -Unique | Out-File "$OUTPUT_FOLDER\IPAddress\Failure.txt" -Append
if ($Count -ge 1)
{
    Write-Output "[Info]  $UniqueFailures failed Sign-Ins found ($Total)"
}
else
{
    Write-Output "[Info]  0 failed Sign-Ins found"
}

# Authentication: Failure (Line Chart) --> Failed Sign-Ins per day
$Import = $Hunt | Where-Object { $_.Status -eq 'Failure' } | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Select-Object Count,@{Name='CreatedDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreatedDateTime -as [datetime] }
if ($Count -gt 5)
{
    $ChartDefinition = New-ExcelChartDefinition -XRange CreatedDateTime -YRange Count -Title "Failed Sign-Ins" -ChartType Line -NoLegend -Width 1200
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\LineCharts\Failure.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
}

# Failure (Map)
if (Test-Path "$($IPinfo)")
{
    if (Test-Path "$OUTPUT_FOLDER\IPAddress\Failure.txt")
    {
        if ((Get-Item "$OUTPUT_FOLDER\IPAddress\Failure.txt").Length -gt 0kb)
        {
            # Internet Connectivity Check (Vista+)
            $NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]'{DCB00C01-570F-4A9B-8D69-199FDBA5723B}')).IsConnectedToInternet

            if (!($NetworkListManager -eq "True"))
            {
                Write-Host "[Error] Your computer is NOT connected to the Internet. IP addresses cannot be checked via IPinfo API." -ForegroundColor Red
            }
            else
            {
                # Check if IPinfo.io is reachable
                if (!(Test-Connection -ComputerName ipinfo.io -Count 1 -Quiet))
                {
                    Write-Host "[Error] ipinfo.io is NOT reachable. IP addresses cannot be checked via IPinfo API." -ForegroundColor Red
                }
                else
                {
                    # Map IPs
                    Get-Content "$OUTPUT_FOLDER\IPAddress\Failure.txt" | & $IPinfo map | Out-File "$OUTPUT_FOLDER\IPAddress\IPinfo\Map_Failure.txt"
                }
            }
        }
    }
}

# Interrupted (Sign-Ins)
Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\IPAddress\Interrupted.txt" -Encoding UTF8 # Header
$Hunt | Where-Object { $_.Status -eq 'Interrupted' } | Select-Object -ExpandProperty IPAddress -Unique | Out-File "$OUTPUT_FOLDER\IPAddress\Interrupted.txt" -Append

# Authentication: Interrupted (Line Chart) --> Interrupted Sign-Ins per day
$Count = ($Hunt | Where-Object { $_.Status -eq 'Interrupted' } | Measure-Object).Count

if ($Count -ge 5)
{
    $Import = $Hunt | Where-Object { $_.Status -eq 'Interrupted' } | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Select-Object Count,@{Name='CreatedDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreatedDateTime -as [datetime] }
    $ChartDefinition = New-ExcelChartDefinition -XRange CreatedDateTime -YRange Count -Title "Interrupted Sign-Ins" -ChartType Line -NoLegend -Width 1200
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\LineCharts\Interrupted.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
}

#############################################################################################################################################################################################

# Conditional Access

# Conditional Access Result: Success (Line Chart)
$Count = ($Hunt | Where-Object { $_.ConditionalAccessStatus -eq 'Success' } | Measure-Object).Count

if ($Count -ge 10)
{
    $Import = $Hunt | Where-Object { $_.ConditionalAccessStatus -eq 'Success' } | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Select-Object Count,@{Name='CreatedDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreatedDateTime -as [datetime] }
    $ChartDefinition = New-ExcelChartDefinition -XRange CreatedDateTime -YRange Count -Title "Conditional Access Result: Success" -ChartType Line -NoLegend -Width 1200
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\LineCharts\ConditionalAccessResult-Success.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
}

# Conditional Access Result: Failure (Line Chart)
$Count = ($Hunt | Where-Object { $_.ConditionalAccessStatus -eq 'Failure' } | Measure-Object).Count

if ($Count -ge 10)
{
    $Import = $Hunt | Where-Object { $_.ConditionalAccessStatus -eq 'Failure' } | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Select-Object Count,@{Name='CreatedDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreatedDateTime -as [datetime] }
    $ChartDefinition = New-ExcelChartDefinition -XRange CreatedDateTime -YRange Count -Title "Conditional Access Result: Failure" -ChartType Line -NoLegend -Width 1200
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\LineCharts\ConditionalAccessResult-Failure.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
}

# Conditional Access Result: Not applied (Line Chart)
$Count = ($Hunt | Where-Object { $_.ConditionalAccessStatus -eq 'notApplied' } | Measure-Object).Count

if ($Count -ge 10)
{
    $Import = $Hunt | Where-Object { $_.ConditionalAccessStatus -eq 'notApplied' } | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Select-Object Count,@{Name='CreatedDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreatedDateTime -as [datetime] }
    $ChartDefinition = New-ExcelChartDefinition -XRange CreatedDateTime -YRange Count -Title "Conditional Access Result: Not applied" -ChartType Line -NoLegend -Width 1200
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\LineCharts\ConditionalAccessResult-NotApplied.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
}

# Conditional Access (NOT Blocked)
Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\IPAddress\ConditionalAccess.txt" -Encoding UTF8 # Header
Import-Csv -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.Status -eq 'Success' } | Where-Object { $_.ConditionalAccessStatus -eq "notApplied" -or $_.ConditionalAccessStatus -eq "success" } | Select-Object -ExpandProperty IPAddress -Unique | & $IPinfo grepip -o | Out-File "$OUTPUT_FOLDER\IPAddress\ConditionalAccess.txt" -Append

# Conditional Access (Map)
if (Test-Path "$OUTPUT_FOLDER\IPAddress\ConditionalAccess.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\IPAddress\ConditionalAccess.txt").Length -gt 0kb)
    {
        # Internet Connectivity Check (Vista+)
        $NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]'{DCB00C01-570F-4A9B-8D69-199FDBA5723B}')).IsConnectedToInternet

        if (!($NetworkListManager -eq "True"))
        {
            Write-Host "[Error] Your computer is NOT connected to the Internet. IP addresses cannot be checked via IPinfo API." -ForegroundColor Red
        }
        else
        {
            # Check if IPinfo.io is reachable
            if (!(Test-Connection -ComputerName ipinfo.io -Count 1 -Quiet))
            {
                Write-Host "[Error] ipinfo.io is NOT reachable. IP addresses cannot be checked via IPinfo API." -ForegroundColor Red
            }
            else
            {
                # Map IPs
                Get-Content "$OUTPUT_FOLDER\IPAddress\ConditionalAccess.txt" | & $IPinfo map | Out-File "$OUTPUT_FOLDER\IPAddress\IPinfo\Map_ConditionalAccess.txt"
            }
        }
    }
}

# Conditional Access Status (Investigating Sign-Ins with CA applied)
# notApplied: No policy applied to the user and application during sign-in.
# success:    One or more conditional access policies applied to the user and application (but not necessarily the other conditions) during sign-in.
# failure:    The sign-in satisfied the user and application condition of at least one Conditional Access policy and grant controls are either not satisfied or set to block access.

# Note: Conditional Access policies are enforced after first-factor authentication is completed. Conditional Access isn't intended to be an organization's first line of defense for scenarios like denial-of-service (DoS) attacks, but it can use signals from these events to determine access.

# Impact Summary
# Total: The number of users or sign-ins during the time period where at least one of the selected policies was evaluated.
# Success: The number of users or sign-ins during the time period where the combined result of the selected policies was “Success” or “Report-only: Success”.
# Failure: The number of users or sign-ins during the time period where the result of at least one of the selected policies was “Failure” or “Report-only: Failure”.
# Not applied: The number of users or sign-ins during the time period where none of the selected policies applied.

#############################################################################################################################################################################################

# Stats per Application (Audit)
$ServicePrincipalIds = ($Hunt | Select-Object ServicePrincipalId -Unique | Sort-Object ServicePrincipalId).ServicePrincipalId

$Stats = [Collections.Generic.List[PSObject]]::new()
ForEach($ServicePrincipalId in $ServicePrincipalIds)
{
    $ServicePrincipalName = ($Hunt | Where-Object {$_.ServicePrincipalId -eq "$ServicePrincipalId"} | Select-Object ServicePrincipalName -Unique).ServicePrincipalName
    New-Item "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\Enterprise Applications\$ServicePrincipalName" -ItemType Directory -Force | Out-Null

    # ASN / Status (Stats)
    $Total = ($Hunt | Where-Object {$_.ServicePrincipalId -eq "$ServicePrincipalId"} | Select-Object ASN | Where-Object {$_.ASN -ne '' } | Measure-Object).Count
    if ($Total -ge "1")
    {
        $Stats = $Hunt | Where-Object {$_.ServicePrincipalId -eq "$ServicePrincipalId"} | Select-Object ASN,OrgName,Status | Where-Object {$_.ASN -ne '' } | Where-Object { $null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value}) } | Group-Object ASN,OrgName,Status | Select-Object @{Name='ASN'; Expression={ $_.Values[0] }},@{Name='OrgName'; Expression={ $_.Values[1] }},@{Name='Status'; Expression={ $_.Values[2] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\Enterprise Applications\$ServicePrincipalName\ASN.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ASN" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-E
        $WorkSheet.Cells["A:E"].Style.HorizontalAlignment="Center"

        # Iterating over the ASN-Blacklist HashTable
        foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$A1)))' -f $ASN
            Add-ConditionalFormatting -Address $WorkSheet.Cells["A:E"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        }
    }

    # Country / Country Name (Stats)
    $Total = ($Hunt | Where-Object {$_.ServicePrincipalId -eq "$ServicePrincipalId"} | Select-Object Country | Where-Object {$_.Country -ne '' } | Measure-Object).Count
    if ($Total -ge "1")
    {       
        $Stats = $Hunt | Where-Object {$_.ServicePrincipalId -eq "$ServicePrincipalId"} | Select-Object Country,"Country Name" | Where-Object {$_.Country -ne '' } | Where-Object { $null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value}) } | Group-Object Country,"Country Name" | Select-Object @{Name='Country'; Expression={ $_.Values[0] }},@{Name='Country Name'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\Enterprise Applications\$ServicePrincipalName\Country.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Countries" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-D
        $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"

        # Iterating over the Country-Blacklist HashTable
        foreach ($Country in $CountryBlacklist_HashTable.Keys) 
        {
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$B1)))' -f $Country
            Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        }
    }

    # IPAddress / Country Name (Stats)
    $Total = ($Hunt | Where-Object {$_.ServicePrincipalId -eq "$ServicePrincipalId"} | Select-Object IPAddress,"Country Name" | Where-Object {$_."Country Name" -ne '' } | Measure-Object).Count
    if ($Total -ge "1")
    {
        $Stats = $Hunt | Where-Object {$_.ServicePrincipalId -eq "$ServicePrincipalId"} | Select-Object IPAddress,Country,"Country Name",ASN,OrgName | Where-Object {$_.IPAddress -ne '' } | Where-Object {$_."Country Name" -ne '' } | Where-Object { $null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value}) } | Group-Object IPAddress,Country,"Country Name",ASN,OrgName | Select-Object @{Name='IPAddress'; Expression={ $_.Values[0] }},@{Name='Country'; Expression={ $_.Values[1] }},@{Name='Country Name'; Expression={ $_.Values[2] }},@{Name='ASN'; Expression={ $_.Values[3] }},@{Name='OrgName'; Expression={ $_.Values[4] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\Enterprise Applications\$ServicePrincipalName\IPAddress.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "IPAddress" -CellStyleSB {
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
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$C1)))' -f $Country
            Add-ConditionalFormatting -Address $WorkSheet.Cells["B:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
        }

        }
    }

    # UserAgent (Stats)
    $Total = ($Hunt | Where-Object {$_.ServicePrincipalId -eq "$ServicePrincipalId"} | Select-Object UserAgent | Measure-Object).Count
    if ($Total -ge "1")
    {
        $Stats = $Hunt | Where-Object {$_.ServicePrincipalId -eq "$ServicePrincipalId"} | Group-Object UserAgent | Select-Object @{Name='UserAgent';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\Enterprise Applications\$ServicePrincipalName\UserAgent.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserAgent" -CellStyleSB {
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
    New-Item "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\Enterprise Applications\$ServicePrincipalName\LineCharts" -ItemType Directory -Force | Out-Null

    # Authentication: Success (Line Chart) --> Successful Sign-Ins per day (Sign-In Frequency)
    $Import = $Hunt | Where-Object {$_.ServicePrincipalId -eq "$ServicePrincipalId"} | Where-Object { $_.Status -eq 'Success' } | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Select-Object Count,@{Name='CreatedDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreatedDateTime -as [datetime] }
    $Count = ($Import | Measure-Object).Count
    if ($Count -gt "5")
    {
        $ChartDefinition = New-ExcelChartDefinition -XRange CreatedDateTime -YRange Count -Title "Successful Sign-Ins" -ChartType Line -NoLegend -Width 1200
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\Enterprise Applications\$ServicePrincipalName\LineCharts\Success.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
    }

    # Authentication: Failure (Line Chart) --> Failed Sign-Ins per day
    $Import = $Hunt | Where-Object {$_.ServicePrincipalId -eq "$ServicePrincipalId"} | Where-Object { $_.Status -eq 'Failure' } | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Select-Object Count,@{Name='CreatedDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreatedDateTime -as [datetime] }
    $Count = ($Import | Measure-Object).Count
    if ($Count -gt "5")
    {
        $ChartDefinition = New-ExcelChartDefinition -XRange CreatedDateTime -YRange Count -Title "Failed Sign-Ins" -ChartType Line -NoLegend -Width 1200
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\ServicePrincipalSignInLogs\Stats\Enterprise Applications\$ServicePrincipalName\LineCharts\Failure.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
    }
}

$EndTime_Stats = (Get-Date)
$Time_Stats = ($EndTime_Stats-$StartTime_Stats)
('ServicePrincipalSignInLogs Stats duration:           {0} h {1} min {2} sec' -f $Time_Stats.Hours, $Time_Stats.Minutes, $Time_Stats.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#endregion Stats

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# Main
Start-Processing
Get-IPLocation
Get-Stats

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

# IPinfo Logout
& $IPinfo logout > $null

# IPinfo Clear Cache (Optional)
#& $IPinfo cache clear > $null

# Cleaning up
Clear-Variable Token

# MessageBox UI
$MessageBody = "Status: Sign-In Logs Analysis completed."
$MessageTitle = "ServicePrincipal-Analyzer.ps1 (https://lethal-forensics.com/)"
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
# MIIrywYJKoZIhvcNAQcCoIIrvDCCK7gCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUBB+ik5WQCsKTEiejeMstanA3
# GAuggiUEMIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
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
# MCMGCSqGSIb3DQEJBDEWBBSbx2/Sjcz7WF5pQJa3mQqWo+fuwDANBgkqhkiG9w0B
# AQEFAASCAgDF/9yZR50chaSdoCDEsObQ5rb9b80Xwm3JmjgKcaPK4aFnVIUjHQAi
# Gx/NLz3z5FuB72w1qgX7d4VSGm051kQS80gAO2dOAqC731WzKI/S32RVeRk/+QFO
# oX0W5I6s1RoHBH+XQBgQ1ra24wsP7iELTBglQe5m6blAyNLMIz/ROdljMpVt+jUa
# OUl7ZjIkxCsxr6wDgws4ufUf7ReE0on3lgz2GokZBjVZZtjv8rVSfaFJptKOMXsq
# lWkg77NIWtcJJNY240sZgu4QlSThltYK3adbBPRkCLZhM8WImderC8szqP6vd+06
# SOacnCzu4uVp6ZNq+DfsFeX1PIpFmvcKT0qTMCVXWMZxGBExhOUBFnWarW7tH8iW
# 7QtQ3wEyBlOqEoU5/1gnZYiJ/+AoRQJ4ojsG0qs5pgVL0dCGQsWfxwonoPtBKcQi
# r/F5JfjpYswJuuEC4x2x5lqNsUBwxgvC2DN90tuJ72POewZeYnvtTStzydBn/ltz
# X8uxuDuUoh0BPrObyKKQfKV/NfIjhPdGMTJ3uTMwrjaIfKu+qVvpMIIzN3YpXa3b
# 79aihuRO0pMSaMAkv4GY5YAO4clc6sZ1AWxyocJS7z2s3tsHI10jfoGtiCrq1mAH
# 7J/XJS+9llFLO/EHlUYrTX0AsTZXqRchkEydYp46HB2UfgjVx7Iy7qGCAyMwggMf
# BgkqhkiG9w0BCQYxggMQMIIDDAIBATBqMFUxCzAJBgNVBAYTAkdCMRgwFgYDVQQK
# Ew9TZWN0aWdvIExpbWl0ZWQxLDAqBgNVBAMTI1NlY3RpZ28gUHVibGljIFRpbWUg
# U3RhbXBpbmcgQ0EgUjM2AhEApCk7bh7d16c0CIetek63JDANBglghkgBZQMEAgIF
# AKB5MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MTAyMTA1MzE0N1owPwYJKoZIhvcNAQkEMTIEMOBOe4HBW4n7CHNGjESyvB4lKPps
# Z8Q6ZisF91KdYevvFPXOoJTzSpYLYgDdn/GCnzANBgkqhkiG9w0BAQEFAASCAgAr
# zbW7KiB/Ew4Rc/ZXPcWeePc2vvsjH3T7p4TnMIqDLM1ZF0INvVLQO4syp5LTM7oz
# VOW38DUI+6eFB/WqcWf0nzFVONwEG5PfSinS0Xo1J/1uSXZqpGQxf67qSrkHGYuo
# MktVJYLzQdEYIdvCrePyW51oh+qPiApRl1QB4U9IIiXKKwB9LqpruNDSfCctVxsC
# tNEU9RP/2BBDg8kDX77vwiA6gjvh/WvaV0Hmx7URa/rRsoTkS72W4782xI1KaY0n
# xK8Urh3hXpF9kqs3K/p8XYXGu6EKYYgqLu8pg0MURJmkI2hDNYK2pg/1ozhDB0OG
# g4x0d4r4QfHTXA9Uq6bKRy0taHYsWuYuj4KUa5ulPu2pLAmPkBRFDjg1cOlEMqNa
# t5C9Afgluy7SwYH9T/QxhoMksNcvJtXoO9nZ8pGJU4J3fDqdGyFnInnimlYyVnzH
# 0Oh2p4QUu9WBcodLO/tz/Y9bb7IsSg1AbE4PnmaPFc1ZRTV6C0OlydU2jRsbvX5e
# 8rGG/0aGDR24VM6m0SFBfDByJAknpvablmsL3FLhQVe68n3Bw44y3Rat6yrySfAd
# 2e/M3cIgPf5E3Z/3aLXH5GcEK9NULn0vNpYqhKHaxeAXTgl5BwfyfBXONGHLDntm
# nFGeV2Y0+khUaXnTwva3s15j4dKbbWBpa6DPcb++9w==
# SIG # End signature block
