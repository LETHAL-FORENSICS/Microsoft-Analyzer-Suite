# EntraSignInLogs-Analyzer
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2025 Martin Willing. All rights reserved. Licensed under the MIT license.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2025-09-18
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
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.6332) and PowerShell 5.1 (5.1.19041.6328)
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.6332) and PowerShell 7.5.3
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  EntraSignInLogs-Analyzer - Automated Processing of Microsoft Entra ID Sign-In Logs for DFIR

.DESCRIPTION
  EntraSignInLogs-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of Microsoft Entra ID Sign-In Logs extracted via "Microsoft Extractor Suite" by Invictus Incident Response.

  https://github.com/invictus-ir/Microsoft-Extractor-Suite (Microsoft-Extractor-Suite v4.0.0)

  https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/Azure/AzureActiveDirectorysign-inlogs.html

.PARAMETER OutputDir
  Specifies the output directory. Default is "$env:USERPROFILE\Desktop\EntraSignInLogs-Analyzer".

  Note: The subdirectory 'EntraSignInLogs-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the JSON-based input file (SignInLogs-interactiveUser-nonInteractiveUser-Combined.json).

.EXAMPLE
  PS> .\EntraSignInLogs-Analyzer.ps1

.EXAMPLE
  PS> .\EntraSignInLogs-Analyzer.ps1 -Path "$env:USERPROFILE\Desktop\SignInLogs-interactiveUser-nonInteractiveUser-Combined.json"

.EXAMPLE
  PS> .\EntraSignInLogs-Analyzer.ps1 -Path "H:\Microsoft-Extractor-Suite\SignInLogs-interactiveUser-nonInteractiveUser-Combined.json" -OutputDir "H:\Microsoft-Analyzer-Suite"

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
    $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\EntraSignInLogs-Analyzer" # Default
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
        $script:OUTPUT_FOLDER = "$OutputDir\EntraSignInLogs-Analyzer" # Custom
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
$Host.UI.RawUI.WindowTitle = "EntraSignInLogs-Analyzer - Automated Processing of Microsoft Entra ID Sign-In Logs for DFIR"

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
        $OpenFileDialog.Filter = "Sign-In Logs|SignInLogs-interactiveUser-nonInteractiveUser-Combined.json|All Files (*.*)|*.*"
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
Write-Output "EntraSignInLogs-Analyzer - Automated Processing of Microsoft Entra ID Sign-In Logs for DFIR"
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
        Import-Csv "$SCRIPT_DIR\Blacklists\Country-Blacklist.csv" -Delimiter "," | ForEach-Object { $CountryBlacklist_HashTable[$_."Country Name"] = $_.Country }

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

# Microsoft Entra ID Sign-In Logs

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
Write-Output "[Info]  Processing Microsoft Entra ID Sign-In Logs ..."
New-Item "$OUTPUT_FOLDER\EntraSignInLogs\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\EntraSignInLogs\XLSX" -ItemType Directory -Force | Out-Null

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
    "Id"                             = $Record.Id # The identifier representing the sign-in activity.
    "CreatedDateTime"                = (Get-Date $CreatedDateTime).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
    "UserDisplayName"                = $Record.userDisplayName # The display name of the user.
    "UserPrincipalName"              = $Record.userPrincipalName # The UPN of the user.
    "UserId"                         = $Record.userId # The identifier of the user.
    "AppDisplayName"                 = $Record.appDisplayName # The application name displayed in the Microsoft Entra admin center.
    "AppId"                          = $Record.appId # The application identifier in Microsoft Entra ID.
    "ClientAppUsed"                  = $Record.clientAppUsed # The legacy client used for sign-in activity.
    "IpAddress"                      = $Record.ipAddress # The IP address of the client from where the sign-in occurred.
    "ASN"                            = $Record.AutonomousSystemNumber # The Autonomous System Number (ASN) of the network used by the actor.
    "IPAddressFromResourceProvider"  = $Record.IPAddressFromResourceProvider # The IP address a user used to reach a resource provider, used to determine Conditional Access compliance for some policies. For example, when a user interacts with Exchange Online, the IP address that Microsoft Exchange receives from the user can be recorded here. This value is often null.
    "City"                           = $Record | Select-Object -ExpandProperty location | Select-Object -ExpandProperty city # The city from where the sign-in occurred.
    "State"                          = $Record | Select-Object -ExpandProperty location | Select-Object -ExpandProperty state # The state from where the sign-in occurred.
    "CountryOrRegion"                = $Record | Select-Object -ExpandProperty location | Select-Object -ExpandProperty countryOrRegion # The two letter country code from where the sign-in occurred.
    "Latitude"                       = $Record | Select-Object -ExpandProperty location | Select-Object -ExpandProperty geoCoordinates | Select-Object -ExpandProperty Latitude
    "Longitude"                      = $Record | Select-Object -ExpandProperty location | Select-Object -ExpandProperty geoCoordinates | Select-Object -ExpandProperty Longitude
    "AuthenticationRequirement"      = $Record.AuthenticationRequirement # This holds the highest level of authentication needed through all the sign-in steps, for sign-in to succeed.
    "SignInEventTypes"               = $Record | Select-Object -ExpandProperty SignInEventTypes # Indicates the category of sign in that the event represents.
    "AuthenticationMethodsUsed"      = $Record | Select-Object -ExpandProperty AuthenticationMethodsUsed # The authentication methods used.

    # Status - The sign-in status. Includes the error code and description of the error (for a sign-in failure).
    # https://learn.microsoft.com/nb-no/graph/api/resources/signinstatus?view=graph-rest-beta
    "ErrorCode"                      = $Record | Select-Object -ExpandProperty status | Select-Object -ExpandProperty errorCode # Provides the 5-6 digit error code that's generated during a sign-in failure.
    "FailureReason"                  = $Record | Select-Object -ExpandProperty status | Select-Object -ExpandProperty failureReason # Provides the error message or the reason for failure for the corresponding sign-in activity.
    "AdditionalDetails"              = $Record | Select-Object -ExpandProperty status | Select-Object -ExpandProperty additionalDetails # Provides additional details on the sign-in activity.

    # AuthenticationDetails - The result of the authentication attempt and more details on the authentication method.
    # https://learn.microsoft.com/nb-no/graph/api/resources/authenticationdetail?view=graph-rest-beta
    "AuthenticationMethod"           = $Record.AuthDetailsAuthenticationMethod # The type of authentication method used to perform this step of authentication.
    "AuthenticationMethodDetail"     = $Record.AuthDetailsAuthenticationMethodDetail # Details about the authentication method used to perform this authentication step.
    "AuthenticationStepDateTime"     = $Record.AuthDetailsAuthenticationStepDateTime # Represents date and time information using ISO 8601 format and is always in UTC time.
    "AuthenticationStepRequirement"  = $Record.AuthDetailsAuthenticationStepRequirement # The step of authentication that this satisfied. 
    "AuthenticationStepResultDetail" = $Record.AuthDetailsAuthenticationStepResultDetail # Details about why the step succeeded or failed. 
    "Succeeded"                      = $Record.AuthDetailsSucceeded # Indicates the status of the authentication step.

    # AuthenticationProcessingDetails - More authentication processing details, such as the agent name for PTA and PHS, or a server or farm name for federated authentication.
    "Domain Hint Present"            = ($Record | Select-Object -ExpandProperty AuthenticationProcessingDetails | Where-Object {$_.Key -eq 'Domain Hint Present'}).Value
    "Is CAE Token"                   = ($Record | Select-Object -ExpandProperty AuthenticationProcessingDetails | Where-Object {$_.Key -eq 'Is CAE Token'}).Value
    "Login Hint Present"             = ($Record | Select-Object -ExpandProperty AuthenticationProcessingDetails | Where-Object {$_.Key -eq 'Login Hint Present'}).Value
    "Oauth Scope Info"               = ($Record | Select-Object -ExpandProperty AuthenticationProcessingDetails | Where-Object {$_.Key -eq 'Oauth Scope Info'}).Value
    "Root Key Type"                  = ($Record | Select-Object -ExpandProperty AuthenticationProcessingDetails | Where-Object {$_.Key -eq 'Root Key Type'}).Value

    "ClientCredentialType"           = $Record.ClientCredentialType # Describes the credential type that a user client or service principal provided to Microsoft Entra ID to authenticate itself. You can review this property to track and eliminate less secure credential types or to watch for clients and service principals using anomalous credential types.
    "ConditionalAccessStatus"        = $Record.ConditionalAccessStatus # The status of the conditional access policy triggered.
    "CorrelationId"                  = $Record.CorrelationId # The identifier that's sent from the client when sign-in is initiated.
    "IncomingTokenType"              = $Record.IncomingTokenType # Indicates the token types that were presented to Microsoft Entra ID to authenticate the actor in the sign in. 
    "OriginalRequestId"              = $Record.OriginalRequestId # The request identifier of the first request in the authentication sequence.
    "IsInteractive"                  = $Record.IsInteractive # Indicates whether a user sign in is interactive. In interactive sign in, the user provides an authentication factor to Microsoft Entra ID. These factors include passwords, responses to MFA challenges, biometric factors, or QR codes that a user provides to Microsoft Entra ID or an associated app. In non-interactive sign in, the user doesn't provide an authentication factor. Instead, the client app uses a token or code to authenticate or access a resource on behalf of a user. Non-interactive sign ins are commonly used for a client to sign in on a user's behalf in a process transparent to the user.
    "ProcessingTimeInMilliseconds"   = $Record.ProcessingTimeInMilliseconds # The request processing time in milliseconds in AD STS.
    "ResourceDisplayName"            = $Record.ResourceDisplayName # The name of the resource that the user signed in to.
    "ResourceId"                     = $Record.ResourceId # The identifier of the resource that the user signed in to.
    "ResourceServicePrincipalId"     = $Record.ResourceServicePrincipalId # The identifier of the service principal representing the target resource in the sign-in event.
    "ResourceTenantId"               = $Record.ResourceTenantId # The tenant identifier of the resource referenced in the sign in.
    "RiskDetail"                     = $Record.RiskDetail # The reason behind a specific state of a risky user, sign-in, or a risk event.
    "RiskEventTypesV2"               = $Record | Select-Object -ExpandProperty riskEventTypes_v2 # The list of risk event types associated with the sign-in. --> RiskEventTypesV2 (Old)
    "RiskLevelAggregated"            = $Record.RiskLevelAggregated # The aggregated risk level. The value hidden means the user or sign-in wasn't enabled for Microsoft Entra ID Protection.
    "RiskLevelDuringSignIn"          = $Record.RiskLevelDuringSignIn # The risk level during sign-in. The value hidden means the user or sign-in wasn't enabled for Microsoft Entra ID Protection.
    "RiskState"                      = $Record.RiskState # The risk state of a risky user, sign-in, or a risk event.
    "SignInTokenProtectionStatus"    = $Record.SignInTokenProtectionStatus # Token protection creates a cryptographically secure tie between the token and the device it is issued to. This field indicates whether the signin token was bound to the device or not.
    "TokenIssuerName"                = $Record.TokenIssuerName # The name of the identity provider.
    "TokenIssuerType"                = $Record.TokenIssuerType # The type of identity provider.
    "UniqueTokenIdentifier"          = $Record.UniqueTokenIdentifier # A unique base64 encoded request identifier used to track tokens issued by Microsoft Entra ID as they're redeemed at resource providers.
    "SessionId"                      = $Record.SessionId # Identifier of the session that was generated during the sign-in.
    "UserAgent"                      = $Record.UserAgent # The user agent information related to sign-in.
    "UserType"                       = $Record | Select-Object -ExpandProperty UserType | ForEach-Object { $_.Replace("member","Member") } | ForEach-Object { $_.Replace("guest","Guest") } # Identifies whether the user is a member or guest in the tenant.
    "AuthenticationProtocol"         = $Record.AuthenticationProtocol # Lists the protocol type or grant type used in the authentication.
    "OriginalTransferMethod"         = $Record.OriginalTransferMethod # Transfer method used to initiate a session throughout all subsequent request.
    "CrossTenantAccessType"          = $Record.CrossTenantAccessType # Describes the type of cross-tenant access used by the actor to access the resource.

    # MfaDetail - This property is deprecated.
    "AuthMethod"                     = $Record | Select-Object -ExpandProperty MfaDetail | Select-Object -ExpandProperty AuthMethod
    "AuthDetail"                     = $Record | Select-Object -ExpandProperty MfaDetail | Select-Object -ExpandProperty AuthDetail

    # DeviceDetail - The device information from where the sign-in occurred. Includes information such as deviceId, OS, and browser.
    # https://learn.microsoft.com/nb-no/graph/api/resources/devicedetail?view=graph-rest-beta
    "DeviceId"                       = $Record | Select-Object -ExpandProperty DeviceDetail | Select-Object -ExpandProperty DeviceId # Refers to the UniqueID of the device used for signing-in.
    "DisplayName"                    = $Record | Select-Object -ExpandProperty DeviceDetail | Select-Object -ExpandProperty DisplayName # Refers to the name of the device used for signing-in.
    "OperatingSystem"                = $Record | Select-Object -ExpandProperty DeviceDetail | Select-Object -ExpandProperty OperatingSystem # Indicates the OS name and version used for signing-in.
    "Browser"                        = $Record | Select-Object -ExpandProperty DeviceDetail | Select-Object -ExpandProperty Browser # Indicates the browser information of the used for signing-in.
    "IsCompliant"                    = $Record | Select-Object -ExpandProperty DeviceDetail | Select-Object -ExpandProperty IsCompliant # Indicates whether the device is compliant or not.
    "IsManaged"                      = $Record | Select-Object -ExpandProperty DeviceDetail | Select-Object -ExpandProperty IsManaged # Indicates if the device is managed or not.
    "TrustType"                      = $Record | Select-Object -ExpandProperty DeviceDetail | Select-Object -ExpandProperty TrustType # Indicates information on whether the signed-in device is Workplace Joined, AzureAD Joined, Domain Joined.
    
    # NetworkLocationDetails - The network location details including the type of network used and its names.
    # https://learn.microsoft.com/nb-no/graph/api/resources/networklocationdetail?view=graph-rest-beta
    "NetworkType"                    = $NetworkType # Provides the type of network used when signing in.
    "NetworkNames"                   = $NetworkNames # Provides the name of the network used when signing in.
    "TrustedNamedLocation"           = $TrustedNamedLocation
    }

    $Results.Add($Line)
}

$Results | Export-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -NoTypeInformation -Encoding UTF8

# XLSX
$Results | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\XLSX\Untouched.xlsx" -NoNumberConversion * -NoHyperLinkConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SignInLogsGraph" -CellStyleSB {
param($WorkSheet)
# BackgroundColor and FontColor for specific cells of TopRow
$BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
Set-Format -Address $WorkSheet.Cells["A1:BS1"] -BackgroundColor $BackgroundColor -FontColor White
# HorizontalAlignment "Center" of columns A-BS
$WorkSheet.Cells["A:BS"].Style.HorizontalAlignment="Center"
}

# UserId
$UserId = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object UserId -Unique | Measure-Object).Count
Write-Output "[Info]  $UserId UserId(s) found"

# Member
$Member = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Where-Object { $_.UserType -eq 'Member' } | Select-Object UserId -Unique  | Measure-Object).Count

# Guest
$Guest = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Where-Object { $_.UserType -eq 'Guest' } | Select-Object UserId -Unique  | Measure-Object).Count
Write-Output "[Info]  $Member Member(s) and $Guest Guest(s) found"

# DeviceId
$DeviceId = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object DeviceId -Unique | Measure-Object).Count
Write-Output "[Info]  $DeviceId DeviceId(s) found"

# Microsoft Entra ID P2
# https://www.microsoft.com/en-us/security/business/microsoft-entra-pricing
$RiskLevelDuringSignIn = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object RiskLevelDuringSignIn -Unique).RiskLevelDuringSignIn
if (!("$RiskLevelDuringSignIn" -eq "hidden"))
{
    Write-Output "[Info]  Microsoft Entra ID P2 detected"
}

# Identity Protection
# - Risk-based Conditional Access (sign-in risk, user risk)
# - Authentication context (step-up authentication)
# - Device and application filters for Conditional Access
# - Token protection
# - Vulnerabilities and risky accounts
# - Risk event investigation

$EndTime_Processing = (Get-Date)
$Time_Processing = ($EndTime_Processing-$StartTime_Processing)
('EntraSignInLogs Processing duration:      {0} h {1} min {2} sec' -f $Time_Processing.Hours, $Time_Processing.Minutes, $Time_Processing.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#############################################################################################################################################################################################
#############################################################################################################################################################################################

Function Get-IPLocation {

$StartTime_DataEnrichment = (Get-Date)

# Count IP addresses
Write-Output "[Info]  Data Enrichment w/ IPinfo ..."
New-Item "$OUTPUT_FOLDER\IpAddress" -ItemType Directory -Force | Out-Null
$Data = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object -ExpandProperty IpAddress

$Unique = $Data | Sort-Object -Unique
$Unique | Out-File "$OUTPUT_FOLDER\IpAddress\IP-All.txt" -Encoding UTF8

$Count = ($Unique | Measure-Object).Count
$UniqueIP = '{0:N0}' -f $Count
$Total = ($Data | Measure-Object).Count
Write-Output "[Info]  $UniqueIP IP addresses found ($Total)"

# IPv4
# https://ipinfo.io/bogon
$IPv4 = "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
$Private = "^(192\.168|10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.)"
$Special = "^(0\.0\.0\.0|127\.0\.0\.1|169\.254\.|224\.0\.0)"
Get-Content "$OUTPUT_FOLDER\IpAddress\IP-All.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Out-File "$OUTPUT_FOLDER\IpAddress\IPv4-All.txt" -Encoding UTF8
Get-Content "$OUTPUT_FOLDER\IpAddress\IP-All.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Where-Object {$_ -notmatch $Private} | Where-Object {$_ -notmatch $Special} | Out-File "$OUTPUT_FOLDER\IpAddress\IPv4.txt" -Encoding UTF8

# Count
$Total = (Get-Content "$OUTPUT_FOLDER\IpAddress\IPv4-All.txt" | Measure-Object).Count # Public (Unique) + Private (Unique) --> Note: Extracts IPv4 addresses of IPv4-compatible IPv6 addresses.
$Public = (Get-Content "$OUTPUT_FOLDER\IpAddress\IPv4.txt" | Measure-Object).Count # Public (Unique)
$UniquePublic = '{0:N0}' -f $Public
Write-Output "[Info]  $UniquePublic Public IPv4 addresses found ($Total)"

# IPv6
# https://ipinfo.io/bogon
$IPv6 = ":(?::[a-f\d]{1,4}){0,5}(?:(?::[a-f\d]{1,4}){1,2}|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}|:)|(?::(?:[a-f\d]{1,4})?|(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[a-f\d]{1,4}(?::[a-f\d]{1,4})?|))|(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[a-f\d]{1,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){0,2})|:))|(?:(?::[a-f\d]{1,4}){0,2}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,3}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))"
$Bogon = "^(::1|::ffff:|100::|2001:10::|2001:db8::|fc00::|fe80::|fec0::|ff00::)"
Get-Content "$OUTPUT_FOLDER\IpAddress\IP-All.txt" | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Out-File "$OUTPUT_FOLDER\IpAddress\IPv6-All.txt" -Encoding UTF8
Get-Content "$OUTPUT_FOLDER\IpAddress\IP-All.txt" | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Where-Object {$_ -notmatch $Bogon} | Out-File "$OUTPUT_FOLDER\IpAddress\IPv6.txt" -Encoding UTF8

# Count
$Total = (Get-Content "$OUTPUT_FOLDER\IpAddress\IPv6-All.txt" | Measure-Object).Count # including Bogus IPv6 addresses (e.g. IPv4-compatible IPv6 addresses)
$Public = (Get-Content "$OUTPUT_FOLDER\IpAddress\IPv6.txt" | Measure-Object).Count
Write-Output "[Info]  $Public Public IPv6 addresses found ($Total)"

# IP.txt
Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\IpAddress\IP.txt" -Encoding UTF8 # Header

# IPv4.txt
if (Test-Path "$OUTPUT_FOLDER\IpAddress\IPv4.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\IpAddress\IPv4.txt").Length -gt 0kb)
    {
        Get-Content -Path "$OUTPUT_FOLDER\IpAddress\IPv4.txt" | Out-File "$OUTPUT_FOLDER\IpAddress\IP.txt" -Encoding UTF8 -Append
    }
}

# IPv6.txt
if (Test-Path "$OUTPUT_FOLDER\IpAddress\IPv6.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\IpAddress\IPv6.txt").Length -gt 0kb)
    {
        Get-Content -Path "$OUTPUT_FOLDER\IpAddress\IPv6.txt" | Out-File "$OUTPUT_FOLDER\IpAddress\IP.txt" -Encoding UTF8 -Append
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
    if (Test-Path "$OUTPUT_FOLDER\IpAddress\IP.txt")
    {
        if ((Get-Item "$OUTPUT_FOLDER\IpAddress\IP.txt").Length -gt 0kb)
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
                    New-Item "$OUTPUT_FOLDER\IpAddress\IPinfo" -ItemType Directory -Force | Out-Null
                    Get-Content "$OUTPUT_FOLDER\IpAddress\IP.txt" | & $IPinfo map | Out-File "$OUTPUT_FOLDER\IpAddress\IPinfo\Map.txt" -Encoding UTF8

                    # Access Token
                    # https://ipinfo.io/signup?ref=cli
                    if (!("$Token" -eq "access_token"))
                    {
                        # Summarize IPs
                        # https://ipinfo.io/summarize-ips

                        # TXT --> Top Privacy Services
                        Get-Content "$OUTPUT_FOLDER\IpAddress\IP.txt" | & $IPinfo summarize --token "$Token" | Out-File "$OUTPUT_FOLDER\IpAddress\IPinfo\Summary.txt" -Encoding UTF8

                        # CSV
                        Get-Content "$OUTPUT_FOLDER\IpAddress\IP.txt" | & $IPinfo --csv --token "$Token" | Out-File "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo.csv" -Encoding UTF8

                        # Custom CSV (Free)
                        if ($PrivacyDetection -eq "False")
                        {
                            if (Test-Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo.csv")
                            {
                                if(Test-Csv -Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo.csv" -MaxLines 2)
                                {
                                    $IPinfoRecords = Import-Csv "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo.csv" -Delimiter "," -Encoding UTF8

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

                                    $Results | Sort-Object {$_.IP -as [Version]} | Export-Csv -Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv" -NoTypeInformation -Encoding UTF8
                                }
                            }

                            # Custom XLSX (Free)
                            if (Test-Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv")
                            {
                                if(Test-Csv -Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv" -MaxLines 2)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv" -Delimiter "," | Sort-Object {$_.ip -as [Version]}
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -PivotRows "Country Name" -PivotData @{"IP"="Count"} -WorkSheetname "IPinfo (Free)" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of columns A-K
                                    $WorkSheet.Cells["A:K"].Style.HorizontalAlignment="Center"
                                    }
                                }
                            }
                        }

                        # Custom CSV (Privacy Detection)
                        if ($PrivacyDetection -eq "True")
                        {
                            if (Test-Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo.csv")
                            {
                                if(Test-Csv -Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo.csv" -MaxLines 2)
                                {
                                    $IPinfoRecords = Import-Csv "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo.csv" -Delimiter "," -Encoding UTF8

                                    $Results = [Collections.Generic.List[PSObject]]::new()
                                    ForEach($IPinfoRecord in $IPinfoRecords)
                                    {
                                        $Line = [PSCustomObject]@{
                                            "IP"           = $IPinfoRecord.ip
                                            "City"         = $IPinfoRecord.city
                                            "Region"       = $IPinfoRecord.region
                                            "Country"      = $IPinfoRecord.country
                                            "Country Name" = $IPinfoRecord.country_name
                                            "Location"     = $IPinfoRecord.loc
                                            "ASN"          = $IPinfoRecord.asn_id
                                            "OrgName"      = $IPinfoRecord.asn_asn
                                            "Postal Code"  = $IPinfoRecord.postal
                                            "Timezone"     = $IPinfoRecord.timezone
                                            "VPN"          = $IPinfoRecord.privacy_vpn
                                            "Proxy"        = $IPinfoRecord.privacy_proxy
                                            "Tor"          = $IPinfoRecord.privacy_tor
                                            "Relay"        = $IPinfoRecord.privacy_relay
                                            "Hosting"      = $IPinfoRecord.privacy_hosting
                                            "Service"      = $IPinfoRecord.privacy_service
                                        }

                                        $Results.Add($Line)
                                    }

                                    $Results | Sort-Object {$_.IP -as [Version]} | Export-Csv -Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv" -NoTypeInformation -Encoding UTF8
                                }
                            }

                            # Custom XLSX (Privacy Detection)
                            if (Test-Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv")
                            {
                                if(Test-Csv -Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv" -MaxLines 2)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv" -Delimiter "," | Sort-Object {$_.ip -as [Version]}
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -PivotRows "Country Name" -PivotData @{"IP"="Count"} -WorkSheetname "IPinfo (Standard)" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of columns A-P
                                    $WorkSheet.Cells["A:P"].Style.HorizontalAlignment="Center"
                                    # ConditionalFormatting - VPN
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["K:K"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("true",$K1)))' -BackgroundColor Red
                                    # ConditionalFormatting - Proxy
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["L:L"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("true",$L1)))' -BackgroundColor Red
                                    # ConditionalFormatting - Tor
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["M:M"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("true",$M1)))' -BackgroundColor Red
                                    # ConditionalFormatting - Relay
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["N:N"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("true",$N1)))' -BackgroundColor Red
                                    # ConditionalFormatting - Service
                                    $LastRow = $WorkSheet.Dimension.End.Row
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["P2:P$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$P2<>""' -BackgroundColor Red
                                    
                                    # ConditionalFormatting - ASN
                                    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("AS{0}",$G1)))' -f $ASN
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }

                                    # ConditionalFormatting - Country
                                    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$E1)))' -f $Country
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["E:E"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }
                                    
                                    }
                                }
                            }
                        }

                        # Create HashTable and import 'IPinfo-Custom.csv'
                        $script:IPinfo_HashTable = @{}
                        if (Test-Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv")
                        {
                            if(Test-Csv -Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv" -MaxLines 2)
                            {
                                # Free
                                if ($PrivacyDetection -eq "False")
                                {
                                    Import-Csv -Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $IPinfo_HashTable[$_.IP] = $_.City,$_.Region,$_.Country,$_."Country Name",$_.Location,$_.ASN,$_.OrgName,$_."Postal Code",$_.Timezone }
                                }

                                # Privacy Detection
                                if ($PrivacyDetection -eq "True")
                                {
                                    Import-Csv -Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $IPinfo_HashTable[$_.IP] = $_.City,$_.Region,$_.Country,$_."Country Name",$_.Location,$_.ASN,$_.OrgName,$_."Postal Code",$_.Timezone,$_.VPN,$_.Proxy,$_.Tor,$_.Relay,$_.Hosting,$_.Service }
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
                            if (Test-Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv")
                            {
                                if(Test-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -MaxLines 2)
                                {
                                    $Records = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8

                                    # CSV
                                    $Results = [Collections.Generic.List[PSObject]]::new()

                                    ForEach($Record in $Records)
                                    {
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
                                            "UserDisplayName"              = $Record.UserDisplayName
                                            "UserPrincipalName"            = $Record.UserPrincipalName
                                            "UserId"                       = $Record.UserId
                                            "AppId"                        = $Record.AppId
                                            "AppDisplayName"               = $Record.AppDisplayName
                                            "ClientAppUsed"                = $Record.ClientAppUsed
                                            "CorrelationId"                = $Record.CorrelationId
                                            "ConditionalAccessStatus"      = $Record.ConditionalAccessStatus
                                            "OriginalRequestId"            = $Record.OriginalRequestId
                                            "SignInEventType"              = $Record.SignInEventTypes
                                            "TokenIssuerName"              = $Record.TokenIssuerName
                                            "TokenIssuerType"              = $Record.TokenIssuerType
                                            "ProcessingTimeInMilliseconds" = $Record.ProcessingTimeInMilliseconds
                                            "RiskDetail"                   = $Record.RiskDetail
                                            "RiskLevelAggregated"          = $Record.RiskLevelAggregated
                                            "RiskLevelDuringSignIn"        = $Record.RiskLevelDuringSignIn
                                            "RiskState"                    = $Record.RiskState
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
                                            "IpAddress"                    = $IP
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
                                            "UserType"                     = $Record.UserType
                                            "TrustedNamedLocation"         = $Record.TrustedNamedLocation
                                            "UniqueTokenIdentifier"        = $Record.UniqueTokenIdentifier
                                            "SessionId"                    = $Record.SessionId
                                            "IncomingTokenType"            = $Record.IncomingTokenType
                                            "SignInTokenProtectionStatus"  = $Record.SignInTokenProtectionStatus
                                            "CrossTenantAccessType"        = $Record.CrossTenantAccessType
                                            "Oauth Scope Info"             = $Record."Oauth Scope Info"
                                        }

                                        $Results.Add($Line)
                                    }

                                    $Results | Sort-Object {$_.IP -as [Version]} | Export-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -NoTypeInformation -Encoding UTF8
                                }
                            }

                            # XLSX
                            if (Test-Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv")
                            {
                                if(Test-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -MaxLines 2)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Sort-Object { $_.CreatedDateTime -as [datetime] } -Descending
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\XLSX\Hunt.xlsx" -NoNumberConversion * -NoHyperLinkConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -WorkSheetname "Hunt" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:BE1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of columns A-X and AA-BD
                                    $WorkSheet.Cells["A:X"].Style.HorizontalAlignment="Center"
                                    $WorkSheet.Cells["AA:BD"].Style.HorizontalAlignment="Center"
                                    
                                    # ConditionalFormatting - AppId
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["F:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("29d9ed98-a469-4536-ade2-f981bc1d605e",$F1)))' -BackgroundColor Red # Microsoft Authentication Broker
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["F:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("2793995e-0a7d-40d7-bd35-6968ba142197",$F1)))' -BackgroundColor Yellow # 'My Apps' portal --> Threat Actor may checks how many other third party services they can access from that compromised account.
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["F:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("aebc6443-996d-45c2-90f0-388ff96faa56",$F1)))' -BackgroundColor Yellow # Visual Studio Code

                                    # ConditionalFormatting - AuthenticationProtocol
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["AK:AK"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("deviceCode",$AK1)))' -BackgroundColor Red # Device Code Authentication
                                    
                                    # ConditionalFormatting - OriginalTransferMethod
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["AL:AL"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("deviceCodeFlow",$AL1)))' -BackgroundColor Red # Device Code Authentication

                                    # ConditionalFormatting - Browser
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["AE:AE"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Python Requests",$AE1)))' -BackgroundColor Red # Offensive Tool
                                    
                                    # ConditionalFormatting - ErrorCode
                                    $Cells = "X:Y"
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("50053",$X1)))' -BackgroundColor Red # Sign-in was blocked because it came from an IP address with malicious activity
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("90095",$X1)))' -BackgroundColor Red # Admin consent is required for the permissions requested by this application. An admin consent request may be sent to the admin.
                                    
                                    # ConditionalFormatting - TrustedNamedLocation
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["AY:AY"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Yes",$AY1)))' -BackgroundColor $Green # Trusted IP Ranges
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["AY:AY"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("No",$AY1)))' -BackgroundColor Red # Untrusted Location

                                    # ConditionalFormatting - ASN
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["AS:AS"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("13335",$AS1)))' -BackgroundColor Red # Phishing for Refresh Tokens via Cloudflare Workers (AiTM) --> AADNonInteractiveUserSignInLogs

                                    # Iterating over the Application-Blacklist HashTable
                                    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
                                    {
                                        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$F1)))' -f $AppId
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["F:G"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
                                    }

                                    # Iterating over the ASN-Blacklist HashTable
                                    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AS1)))' -f $ASN
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["AS:AT"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }

                                    # Iterating over the Country-Blacklist HashTable
                                    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AQ1)))' -f $Country
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["AP:AQ"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }

                                    # Iterating over the UserAgent-Blacklist HashTable
                                    foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
                                    {
                                        $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AW1)))' -f $UserAgent
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["AW:AW"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
                                    }

                                    }
                                }
                            }
                        }

                        # IPinfo Subscription Plan w/ Privacy Detection
                        if ($PrivacyDetection -eq "True")
                        {
                            if (Test-Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv")
                            {
                                if(Test-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -MaxLines 2)
                                {
                                    $Records = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8

                                    # CSV
                                    $Results = [Collections.Generic.List[PSObject]]::new()

                                    ForEach($Record in $Records)
                                    {
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
                                            $VPN         = $IPinfo_HashTable["$IP"][9]
                                            $Proxy       = $IPinfo_HashTable["$IP"][10]
                                            $Tor         = $IPinfo_HashTable["$IP"][11]
                                            $Relay       = $IPinfo_HashTable["$IP"][12]
                                            $Hosting     = $IPinfo_HashTable["$IP"][13]
                                            $Service     = $IPinfo_HashTable["$IP"][14]
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
                                            $VPN         = ""
                                            $Proxy       = ""
                                            $Tor         = ""
                                            $Relay       = ""
                                            $Hosting     = ""
                                            $Service     = ""
                                        }

                                        $Line = [PSCustomObject]@{
                                            "Id"                           = $Record.Id
                                            "CreatedDateTime"              = $Record.CreatedDateTime
                                            "UserDisplayName"              = $Record.UserDisplayName
                                            "UserPrincipalName"            = $Record.UserPrincipalName
                                            "UserId"                       = $Record.UserId
                                            "AppId"                        = $Record.AppId
                                            "AppDisplayName"               = $Record.AppDisplayName
                                            "ClientAppUsed"                = $Record.ClientAppUsed
                                            "CorrelationId"                = $Record.CorrelationId
                                            "ConditionalAccessStatus"      = $Record.ConditionalAccessStatus
                                            "OriginalRequestId"            = $Record.OriginalRequestId
                                            "SignInEventType"              = $Record.SignInEventTypes
                                            "TokenIssuerName"              = $Record.TokenIssuerName
                                            "TokenIssuerType"              = $Record.TokenIssuerType
                                            "ProcessingTimeInMilliseconds" = $Record.ProcessingTimeInMilliseconds
                                            "RiskDetail"                   = $Record.RiskDetail
                                            "RiskLevelAggregated"          = $Record.RiskLevelAggregated
                                            "RiskLevelDuringSignIn"        = $Record.RiskLevelDuringSignIn
                                            "RiskState"                    = $Record.RiskState
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
                                            "IpAddress"                    = $IP
                                            "City"                         = $City
                                            "Region"                       = $Region
                                            "Country"                      = $Country
                                            "Country Name"                 = $CountryName
                                            "Location"                     = $Location
                                            "ASN"                          = $ASN
                                            "OrgName"                      = $OrgName
                                            "Postal Code"                  = $PostalCode
                                            "Timezone"                     = $Timezone
                                            "VPN"                          = $VPN
                                            "Proxy"                        = $Proxy
                                            "Tor"                          = $Tor
                                            "Relay"                        = $Relay
                                            "Hosting"                      = $Hosting
                                            "Service"                      = $Service
                                            "UserAgent"                    = $Record.UserAgent
                                            "UserType"                     = $Record.UserType
                                            "TrustedNamedLocation"         = $Record.TrustedNamedLocation
                                            "UniqueTokenIdentifier"        = $Record.UniqueTokenIdentifier
                                            "SessionId"                    = $Record.SessionId
                                            "IncomingTokenType"            = $Record.IncomingTokenType
                                            "SignInTokenProtectionStatus"  = $Record.SignInTokenProtectionStatus
                                            "CrossTenantAccessType"        = $Record.CrossTenantAccessType
                                            "Oauth Scope Info"             = $Record."Oauth Scope Info"
                                        }

                                        $Results.Add($Line)
                                    }

                                    $Results | Sort-Object {$_.IP -as [Version]} | Export-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -NoTypeInformation -Encoding UTF8
                                }
                            }

                            # XLSX
                            $Results | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\XLSX\Hunt.xlsx" -NoNumberConversion * -NoHyperlinkConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -WorkSheetname "Hunt" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:BH1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns A-X and AA-BG
                            $WorkSheet.Cells["A:X"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["AA:BG"].Style.HorizontalAlignment="Center"
                            
                            # ConditionalFormatting - AppId
                            Add-ConditionalFormatting -Address $WorkSheet.Cells["F:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("29d9ed98-a469-4536-ade2-f981bc1d605e",$F1)))' -BackgroundColor Red # Microsoft Authentication Broker
                            Add-ConditionalFormatting -Address $WorkSheet.Cells["F:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("aebc6443-996d-45c2-90f0-388ff96faa56",$F1)))' -BackgroundColor Yellow # Visual Studio Code
                            
                            # ConditionalFormatting - AuthenticationProtocol
                            Add-ConditionalFormatting -Address $WorkSheet.Cells["AK:AK"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("deviceCode",$AK1)))' -BackgroundColor Red # Device Code Authentication
                            
                            # ConditionalFormatting - Browser
                            Add-ConditionalFormatting -Address $WorkSheet.Cells["AE:AE"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Python Requests",$AE1)))' -BackgroundColor Red # Offensive Tool
                            
                            # ConditionalFormatting - ErrorCode
                            $Cells = "X:Y"
                            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("50053",$X1)))' -BackgroundColor Red # Sign-in was blocked because it came from an IP address with malicious activity
                            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("90095",$X1)))' -BackgroundColor Red # Admin consent is required for the permissions requested by this application. An admin consent request may be sent to the admin.

                            # ConditionalFormatting - VPN
                            Add-ConditionalFormatting -Address $WorkSheet.Cells["AV:AV"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("true",$AV1)))' -BackgroundColor Red
                            
                            # ConditionalFormatting - Proxy
                            Add-ConditionalFormatting -Address $WorkSheet.Cells["AW:AW"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("true",$AW1)))' -BackgroundColor Red
                            
                            # ConditionalFormatting - Tor
                            Add-ConditionalFormatting -Address $WorkSheet.Cells["AX:AX"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("true",$AX1)))' -BackgroundColor Red
                            
                            # ConditionalFormatting - Relay
                            Add-ConditionalFormatting -Address $WorkSheet.Cells["AY:AY"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("true",$AY1)))' -BackgroundColor Red
                            
                            # ConditionalFormatting - Service
                            $LastRow = $WorkSheet.Dimension.End.Row
                            Add-ConditionalFormatting -Address $WorkSheet.Cells["BA2:BA$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$BA2<>""' -BackgroundColor Red

                            # Iterating over the Application-Blacklist HashTable
                            foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
                            {
                                $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$F1)))' -f $AppId
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["F:G"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
                            }

                            # Iterating over the ASN-Blacklist HashTable
                            foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                            {
                                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AR1)))' -f $ASN
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["AR:AS"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                            }

                            # Iterating over the Country-Blacklist HashTable
                            foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                            {
                                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AP1)))' -f $Country
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["AO:AP"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                            }

                            # Iterating over the UserAgent-Blacklist HashTable
                            foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
                            {
                                $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
                                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$BB1)))' -f $UserAgent
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["BB:BB"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
                            }

                            }
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
('EntraSignInLogs Data Enrichment duration: {0} h {1} min {2} sec' -f $Time_DataEnrichment.Hours, $Time_DataEnrichment.Minutes, $Time_DataEnrichment.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Stats

Function Get-Stats {

$StartTime_Stats = (Get-Date)

# Stats
Write-Output "[Info]  Creating Hunting Stats ..."
New-Item "$OUTPUT_FOLDER\EntraSignInLogs\Stats" -ItemType Directory -Force | Out-Null

# Data Import
$script:Hunt      = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8
$script:Untouched = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8

# AppDisplayName (Stats)
$Count = ($Untouched | Select-Object AppDisplayName -Unique | Measure-Object).Count
$AppDisplayName = '{0:N0}' -f $Count
Write-Output "[Info]  $AppDisplayName Applications found"

$Total = ($Untouched | Select-Object AppDisplayName | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object AppDisplayName,AppId | Select-Object @{Name='AppDisplayName'; Expression={ $_.Values[0] }},@{Name='AppId'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\AppDisplayName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AppDisplayName" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-D
    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
        
    # Iterating over the Application-Blacklist HashTable
    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
    {
        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$B1)))' -f $AppId
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
    }

    # ConditionalFormatting - AppId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("2793995e-0a7d-40d7-bd35-6968ba142197",$B1)))' -BackgroundColor Yellow # 'My Apps' portal --> Potential App Discovery by Threat Actor

    }
}

# ASN / Status (Stats)
$Total = ($Untouched | Select-Object ASN | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Hunt | Select-Object ASN,OrgName,Status | Where-Object {$_.ASN -ne '' } | Where-Object { $null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value}) } | Group-Object ASN,OrgName,Status | Select-Object @{Name='ASN'; Expression={ $_.Values[0] }},@{Name='OrgName'; Expression={ $_.Values[1] }},@{Name='Status'; Expression={ $_.Values[2] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\ASN.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ASN" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
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

# AuthenticationProtocol (Stats)
$Total = ($Untouched | Select-Object AuthenticationProtocol | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object AuthenticationProtocol | Select-Object @{Name='AuthenticationProtocol';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\AuthenticationProtocol.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AuthenticationProtocol" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    # ConditionalFormatting - AuthenticationProtocol
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("deviceCode",$A1)))' -BackgroundColor Red # Device Code Authentication
    }
}

# AuthenticationRequirement (Stats)
$Total = ($Untouched | Select-Object AuthenticationRequirement | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object AuthenticationRequirement | Select-Object @{Name='AuthenticationRequirement';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\AuthenticationRequirement.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AuthenticationRequirement" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# AuthMethod (Stats)
$Total = ($Untouched | Select-Object AuthMethod | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object AuthMethod | Select-Object @{Name='AuthMethod';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\AuthMethod.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AuthMethod" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# Browser (Stats)
$Total = ($Untouched | Select-Object Browser | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object Browser | Select-Object @{Name='Browser';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\Browser.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Browser" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    # ConditionalFormatting - Browser
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Python Requests",$A1)))' -BackgroundColor Red
    }
}

# ClientAppUsed (Stats)
$Total = ($Untouched | Select-Object ClientAppUsed | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object ClientAppUsed | Select-Object @{Name='ClientAppUsed';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\ClientAppUsed.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ClientAppUsed" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    
    # ConditionalFormatting - Modern Authentication Clients
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Browser",$A1)))' -BackgroundColor $Green
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Mobile Apps and Desktop clients",$A1)))' -BackgroundColor $Green
    
    # ConditionalFormatting - Legacy Authentication Clients
    # https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Authenticated SMTP",$A1)))' -BackgroundColor Red
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Other clients",$A1)))' -BackgroundColor Red
    }
}

# ClientAppUsed / Status (Stats)
$Total = ($Hunt | Select-Object ClientAppUsed | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Hunt | Select-Object @{Name='ClientAppUsed'; Expression={if($_.ClientAppUsed){$_.ClientAppUsed}else{'N/A'}}},Status | Group-Object ClientAppUsed,Status | Select-Object @{Name='ClientAppUsed'; Expression={ $_.Values[0] }},@{Name='Status'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\ClientAppUsed-Status.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ClientAppUsed" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-D
    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
    # ConditionalFormatting - Modern Authentication Clients
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Browser",$A1)))' -BackgroundColor $Green
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Mobile Apps and Desktop clients",$A1)))' -BackgroundColor $Green
    # ConditionalFormatting - Legacy Authentication Clients
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Authenticated SMTP",$A1)))' -BackgroundColor Red
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=AND($A1="Authenticated SMTP",$B1="Failure")' -BackGroundColor "Red"
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Other clients",$A1)))' -BackgroundColor Red
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=AND($A1="Other clients",$B1="Failure")' -BackGroundColor "Red"
    }
}

# ConditionalAccessStatus (Stats)
$Total = ($Untouched| Select-Object ConditionalAccessStatus | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object ConditionalAccessStatus | Select-Object @{Name='ConditionalAccessStatus'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\ConditionalAccessStatus.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ConditionalAccessStatus" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# Conditional Access Status (Investigating Sign-Ins with CA applied)
# notApplied: No policy applied to the user and application during sign-in.
# success:    One or more conditional access policies applied to the user and application (but not necessarily the other conditions) during sign-in.
# failure:    The sign-in satisfied the user and application condition of at least one Conditional Access policy and grant controls are either not satisfied or set to block access.

# Note: Conditional Access policies are enforced after first-factor authentication is completed. Conditional Access isn't intended to be an organization's first line of defense for scenarios like denial-of-service (DoS) attacks, but it can use signals from these events to determine access.

# Country / Country Name (Stats)
$Total = ($Hunt | Select-Object Country | Measure-Object).Count
if ($Total -ge "1")
{       
    $Stats = $Hunt | Select-Object Country,"Country Name" | Where-Object {$_.Country -ne '' } | Where-Object { $null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value}) } | Group-Object Country,"Country Name" | Select-Object @{Name='Country'; Expression={ $_.Values[0] }},@{Name='Country Name'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\Country.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Countries" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
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
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\ErrorCode.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ErrorCode" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
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

# IpAddress / Country Name (Stats)
$Total = ($Hunt | Select-Object IpAddress | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Hunt | Select-Object IpAddress,Country,"Country Name",ASN,OrgName | Where-Object {$_.IpAddress -ne '' } | Where-Object {$_."Country Name" -ne '' } | Where-Object { $null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value}) } | Group-Object IpAddress,Country,"Country Name",ASN,OrgName | Select-Object @{Name='IpAddress'; Expression={ $_.Values[0] }},@{Name='Country'; Expression={ $_.Values[1] }},@{Name='Country Name'; Expression={ $_.Values[2] }},@{Name='ASN'; Expression={ $_.Values[3] }},@{Name='OrgName'; Expression={ $_.Values[4] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\IpAddress.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "IpAddress" -CellStyleSB {
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
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\NetworkNames.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "NetworkNames" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# OperatingSystem (Stats)
$Total = ($Untouched | Select-Object OperatingSystem | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object OperatingSystem | Select-Object @{Name='OperatingSystem';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\OperatingSystem.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "OperatingSystem" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# OriginalTransferMethod (Stats)
$Total = ($Untouched | Select-Object OriginalTransferMethod | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object OriginalTransferMethod | Select-Object @{Name='OriginalTransferMethod';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\OriginalTransferMethod.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "OriginalTransferMethod" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# ResourceDisplayName (Stats)
$Count = ($Untouched | Select-Object ResourceDisplayName | Sort-Object ResourceDisplayName -Unique | Measure-Object).Count
$ResourceDisplayName = '{0:N0}' -f $Count
Write-Output "[Info]  $ResourceDisplayName Resources found"

$Total = ($Untouched | Select-Object ResourceDisplayName | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object ResourceDisplayName | Select-Object @{Name='ResourceDisplayName';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\ResourceDisplayName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ResourceDisplayName" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# RiskDetail (Stats)
$Total = ($Untouched | Select-Object RiskDetail | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object RiskDetail | Select-Object @{Name='RiskDetail';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\RiskDetail.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskDetail" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# RiskEventTypesV2 (Stats)
$Total = ($Untouched | Select-Object RiskEventTypesV2 | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object RiskEventTypesV2 | Select-Object @{Name='RiskEventTypesV2';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\RiskEventTypesV2.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskEventTypesV2" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# RiskLevelDuringSignIn (Stats)
$Total = ($Untouched | Select-Object RiskLevelDuringSignIn | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object RiskLevelDuringSignIn | Select-Object @{Name='RiskLevelDuringSignIn';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\RiskLevelDuringSignIn.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskLevelDuringSignIn" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# SignInEventTypes (Stats)
$Total = ($Untouched | Select-Object SignInEventTypes | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object SignInEventTypes | Select-Object @{Name='SignInEventTypes';Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\SignInEventTypes.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SignInEventTypes" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# SignInTokenProtectionStatus (Stats)
$Total = ($Untouched | Select-Object SignInTokenProtectionStatus | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object SignInTokenProtectionStatus | Select-Object @{Name='SignInTokenProtectionStatus';Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\SignInTokenProtectionStatus.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SignInTokenProtectionStatus" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# Status (Stats)
$Total = ($Hunt | Select-Object Status | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Hunt | Group-Object Status | Select-Object @{Name='Status'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\Status.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Status" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# UserAgent (Stats)
$Total = ($Untouched | Select-Object UserAgent | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = $Untouched | Group-Object UserAgent | Select-Object @{Name='UserAgent';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\UserAgent.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserAgent" -CellStyleSB {
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

# VPN Services (Stats)
if ($PrivacyDetection -eq "True")
{
    if (Test-Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv" -MaxLines 2)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv" -Delimiter "," | Sort-Object {$_.ip -as [Version]}
            $Count = ($Import | Where-Object {$_.VPN -eq "true"} | Measure-Object).Count

            if ($Count -ge 1)
            {
                $Total = ($Import | Measure-Object).Count
                $VPNServices = $Import | Where-Object {$_.VPN -eq "true"} | Where-Object {$_.Service -ne ""} | Group-Object Service | Select-Object @{Name='VPN Service';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending

                Write-Host "[Alert] Suspicious VPN Services found ($Count)" -ForegroundColor Red

                foreach ($VPNService in $VPNServices) 
                {
                    $Service = $VPNService."VPN Service"
                    $Count = $VPNService.Count
                    Write-Host "[Alert] Suspicious VPN Service detected: $Service ($Count)" -ForegroundColor Red
                }

                $VPNServices | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\VPN-Services.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "VPN" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns B-C
                $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
                # ConditionalFormatting - Service
                $LastRow = $WorkSheet.Dimension.End.Row
                Add-ConditionalFormatting -Address $WorkSheet.Cells["A2:C$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$A2<>""' -BackgroundColor Red
                }
            }
        }
    }
}

#############################################################################################################################################################################################

# Line Charts
New-Item "$OUTPUT_FOLDER\EntraSignInLogs\Stats\LineCharts" -ItemType Directory -Force | Out-Null

# Failure (Sign-Ins)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.Status -eq 'Failure' } | Select-Object IpAddress | Measure-Object).Count
$Count = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.Status -eq 'Failure' } | Select-Object IpAddress -Unique | Measure-Object).Count
$UniqueFailures = '{0:N0}' -f $Count
Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\IpAddress\Failure.txt" -Encoding UTF8 # Header
Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.Status -eq 'Failure' } | Select-Object -ExpandProperty IpAddress -Unique | Out-File "$OUTPUT_FOLDER\IpAddress\Failure.txt" -Append
Write-Output "[Info]  $UniqueFailures failed Sign-Ins found ($Total)"

# Authentication: Failure (Line Chart) --> Failed Sign-Ins per day
$Import = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.Status -eq 'Failure' } | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Select-Object Count,@{Name='CreatedDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreatedDateTime -as [datetime] }
if ($Count -gt 5)
{
    $ChartDefinition = New-ExcelChartDefinition -XRange CreatedDateTime -YRange Count -Title "Failed Sign-Ins" -ChartType Line -NoLegend -Width 1200
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\LineCharts\Failure.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
}

# Failure (Map)
if (Test-Path "$($IPinfo)")
{
    if (Test-Path "$OUTPUT_FOLDER\IpAddress\Failure.txt")
    {
        if ((Get-Item "$OUTPUT_FOLDER\IpAddress\Failure.txt").Length -gt 0kb)
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
                    Get-Content "$OUTPUT_FOLDER\IpAddress\Failure.txt" | & $IPinfo map | Out-File "$OUTPUT_FOLDER\IpAddress\IPinfo\Map_Failure.txt"
                }
            }
        }
    }
}

# Success (Sign-Ins)
Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\IpAddress\Success.txt" -Encoding UTF8 # Header
Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.Status -eq 'Success' } | Select-Object -ExpandProperty IpAddress -Unique | Out-File "$OUTPUT_FOLDER\IpAddress\Success.txt" -Append

# Authentication: Success (Line Chart) --> Successful Sign-Ins per day
$Import = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.Status -eq 'Success' } | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Select-Object Count,@{Name='CreatedDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreatedDateTime -as [datetime] }
$Count = ($Import | Measure-Object).Count
if ($Count -gt 5)
{
    $ChartDefinition = New-ExcelChartDefinition -XRange CreatedDateTime -YRange Count -Title "Successful Sign-Ins" -ChartType Line -NoLegend -Width 1200
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\LineCharts\Success.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
}

# Success (Map)
if (Test-Path "$OUTPUT_FOLDER\IpAddress\Success.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\IpAddress\Success.txt").Length -gt 0kb)
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
                Get-Content "$OUTPUT_FOLDER\IpAddress\Success.txt" | & $IPinfo map | Out-File "$OUTPUT_FOLDER\IpAddress\IPinfo\Map_Success.txt"
            }
        }
    }
}

# Interrupted (Sign-Ins)
Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\IpAddress\Interrupted.txt" -Encoding UTF8 # Header
Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.Status -eq 'Interrupted' } | Select-Object -ExpandProperty IpAddress -Unique | Out-File "$OUTPUT_FOLDER\IpAddress\Interrupted.txt" -Append

# Authentication: Interrupted (Line Chart) --> Interrupted Sign-Ins per day
$Count = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.Status -eq 'Interrupted' } | Measure-Object).Count

if ($Count -ge 5)
{
    $Import = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.Status -eq 'Interrupted' } | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Select-Object Count,@{Name='CreatedDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreatedDateTime -as [datetime] }
    $ChartDefinition = New-ExcelChartDefinition -XRange CreatedDateTime -YRange Count -Title "Interrupted Sign-Ins" -ChartType Line -NoLegend -Width 1200
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\LineCharts\Interrupted.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
}

#############################################################################################################################################################################################

# Conditional Access

# Conditional Access Result: Success (Line Chart)
$Count = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.ConditionalAccessStatus -eq 'Success' } | Measure-Object).Count

if ($Count -ge 10)
{
    $Import = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.ConditionalAccessStatus -eq 'Success' } | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Select-Object Count,@{Name='CreatedDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreatedDateTime -as [datetime] }
    $ChartDefinition = New-ExcelChartDefinition -XRange CreatedDateTime -YRange Count -Title "Conditional Access Result: Success" -ChartType Line -NoLegend -Width 1200
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\LineCharts\ConditionalAccessResult-Success.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
}

# Conditional Access Result: Failure (Line Chart)
$Count = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.ConditionalAccessStatus -eq 'Failure' } | Measure-Object).Count

if ($Count -ge 10)
{
    $Import = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.ConditionalAccessStatus -eq 'Failure' } | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Select-Object Count,@{Name='CreatedDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreatedDateTime -as [datetime] }
    $ChartDefinition = New-ExcelChartDefinition -XRange CreatedDateTime -YRange Count -Title "Conditional Access Result: Failure" -ChartType Line -NoLegend -Width 1200
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\LineCharts\ConditionalAccessResult-Failure.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
}

# Conditional Access Result: Not applied (Line Chart)
$Count = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.ConditionalAccessStatus -eq 'notApplied' } | Measure-Object).Count

if ($Count -ge 10)
{
    $Import = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.ConditionalAccessStatus -eq 'notApplied' } | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Select-Object Count,@{Name='CreatedDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreatedDateTime -as [datetime] }
    $ChartDefinition = New-ExcelChartDefinition -XRange CreatedDateTime -YRange Count -Title "Conditional Access Result: Not applied" -ChartType Line -NoLegend -Width 1200
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\LineCharts\ConditionalAccessResult-NotApplied.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
}

# Conditional Access (NOT Blocked)
Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\IpAddress\ConditionalAccess.txt" -Encoding UTF8 # Header
Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.Status -eq 'Success' } | Where-Object { $_.ConditionalAccessStatus -eq "notApplied" -or $_.ConditionalAccessStatus -eq "success" } | Select-Object -ExpandProperty IpAddress -Unique | & $IPinfo grepip -o | Out-File "$OUTPUT_FOLDER\IpAddress\ConditionalAccess.txt" -Append

# Conditional Access (Map)
if (Test-Path "$OUTPUT_FOLDER\IpAddress\ConditionalAccess.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\IpAddress\ConditionalAccess.txt").Length -gt 0kb)
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
                Get-Content "$OUTPUT_FOLDER\IpAddress\ConditionalAccess.txt" | & $IPinfo map | Out-File "$OUTPUT_FOLDER\IpAddress\IPinfo\Map_ConditionalAccess.txt"
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

$EndTime_Stats = (Get-Date)
$Time_Stats = ($EndTime_Stats-$StartTime_Stats)
('EntraSignInLogs Stats duration:           {0} h {1} min {2} sec' -f $Time_Stats.Hours, $Time_Stats.Minutes, $Time_Stats.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#endregion Stats

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Analytics

Function Get-Analytics {

$StartTime_Analytics = (Get-Date)

Write-Output "[Info]  Hunting for Suspicious Sign-In Activity ..."

# Detection Rules
$Detection = (Get-Content "$SCRIPT_DIR\EntraSignInLogs-Analyzer.ps1" | Select-String -Pattern "LETHAL-" -CaseSensitive).Count -1
Write-Output "[Info]  Running Detection Ruleset ($Detection Rules) ..."

# LETHAL-001: Brute-Force Detection - Excessive Authentication Failures
$Threshold = "1000"
$Import = $Hunt | Where-Object { $_.Status -eq 'Failure' }
$Count = ($Import | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Where-Object Count -ge $Threshold | Measure-Object).Count

if ($Count -ge 1)
{
    Write-Host "[Alert] Brute-Force Attack detected: 1000+ failed Sign-In events on a single day ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\Brute-Force-Attack\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\Brute-Force-Attack\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Where-Object Count -ge $Threshold | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\Brute-Force-Attack\CSV\Brute-Force-Attack-Overview.csv" -NoTypeInformation -Encoding UTF8
    $Import | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Where-Object Count -ge $Threshold | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\Brute-Force-Attack\CSV\Brute-Force-Attack.csv" -NoTypeInformation -Encoding UTF8

    # Brute-Force-Attack-Overview.xlsx
    if (Test-Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\Brute-Force-Attack\CSV\Brute-Force-Attack-Overview.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\Brute-Force-Attack\CSV\Brute-Force-Attack-Overview.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\Brute-Force-Attack\CSV\Brute-Force-Attack-Overview.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\Brute-Force-Attack\XLSX\Brute-Force-Attack-Overview.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Brute-Force Attack" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:B1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-B
            $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # Brute-Force-Attack.xlsx
    if (Test-Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\Brute-Force-Attack\CSV\Brute-Force-Attack.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\Brute-Force-Attack\CSV\Brute-Force-Attack.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\Brute-Force-Attack\CSV\Brute-Force-Attack.csv" -Delimiter "," -Encoding UTF8
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\Brute-Force-Attack\XLSX\Brute-Force-Attack.xlsx" -NoNumberConversion * -NoHyperLinkConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Brute-Force Attack" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:AZ1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-X, AA-AV and AX-AZ
            $WorkSheet.Cells["A:X"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["AA:AV"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["AX:AZ"].Style.HorizontalAlignment="Center"

            # Iterating over the ASN-Blacklist HashTable
            foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
            {
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AS1)))' -f $ASN
                Add-ConditionalFormatting -Address $WorkSheet.Cells["AS:AT"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
            }

            # Iterating over the Country-Blacklist HashTable
            foreach ($Country in $CountryBlacklist_HashTable.Keys) 
            {
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AP1)))' -f $Country
                Add-ConditionalFormatting -Address $WorkSheet.Cells["AP:AQ"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
            }

            # Iterating over the UserAgent-Blacklist HashTable
            foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
            {
                $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AW1)))' -f $UserAgent
                Add-ConditionalFormatting -Address $WorkSheet.Cells["AW:AW"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
            }

            # ConditionalFormatting - ClientAppUsed
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Authenticated SMTP",$H1)))' -BackgroundColor Red

            # ConditionalFormatting - Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["AA:AA"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Failure",$AA1)))' -BackgroundColor Red
            
            # ConditionalFormatting - TrustedNamedLocation
            Add-ConditionalFormatting -Address $WorkSheet.Cells["AY:AY"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Yes",$AY1)))' -BackgroundColor $Green # Trusted IP Ranges / Trusted Countries
            Add-ConditionalFormatting -Address $WorkSheet.Cells["AY:AY"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("No",$AY1)))' -BackgroundColor Red # Untrusted Location
                 
            }
        }
    }

    # Stats
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\Brute-Force-Attack\Stats" -ItemType Directory -Force | Out-Null

    $Failures = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\Brute-Force-Attack\CSV\Brute-Force-Attack.csv" -Delimiter "," -Encoding UTF8

    # AppDisplayName (Stats)
    $Total = ($Failures | Select-Object Failure | Measure-Object).Count
    if ($Total -ge "1")
    {
        $Stats = $Failures | Group-Object AppDisplayName,AppId | Select-Object @{Name='AppDisplayName'; Expression={ $_.Values[0] }},@{Name='AppId'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\Brute-Force-Attack\Stats\AppDisplayName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AppDisplayName" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
        # HorizontalAlignment "Center" of columns B-D
        $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
        }
    }

    # UserPrincipalName / Status (Stats)
    $Total = ($Failures | Select-Object Failure | Measure-Object).Count
    if ($Total -ge "1")
    {
        $Stats = $Failures | Select-Object UserPrincipalName,Status | Group-Object UserPrincipalName,Status | Select-Object @{Name='UserPrincipalName'; Expression={ $_.Values[0] }},@{Name='Status'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\Brute-Force-Attack\Stats\UserPrincipalName-Status.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserPrincipalName" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
        # HorizontalAlignment "Center" of columns A-D
        $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
        }
    }
}

# LETHAL-002: Potential Brute-Force Detection - Error Code
$Import = $Hunt | Where-Object {($_.ErrorCode -eq '50126' -or $_.ErrorCode -eq '50053')}
$Count = ($Import | Measure-Object).Count
if ($Count -ge 1)
{
    $Users = ($Import | Select-Object UserId -Unique | Measure-Object).Count
    Write-Host "[Alert] Potential Brute-Force Attack detected: Incorrect Credentials and/or Account has been locked ($Users Users, $Count Events)" -ForegroundColor Red
}

# 50126 - Error validating credentials due to invalid username or password.
# 50053 - The account is locked, you've tried to sign in too many times with an incorrect user ID or password.
# 50056 - Invalid or missing password: password does not exist in the directory for this user.

# LETHAL-003: Basic Authentication (Legacy Authentication Client) detected: Authenticated SMTP
$Count = ($Hunt | Where-Object { $_.ClientAppUsed -eq 'Authenticated SMTP' } | Measure-Object).Count
if ($Count -ge 1)
{
    $Failure = ($Hunt | Where-Object { $_.ClientAppUsed -eq 'Authenticated SMTP' } | Where-Object { $_.Status -eq 'Failure' } | Measure-Object).Count
    $Success = ($Hunt | Where-Object { $_.ClientAppUsed -eq 'Authenticated SMTP' } | Where-Object { $_.Status -eq 'Success' } | Measure-Object).Count
    $FailureCount = '{0:N0}' -f $Failure
    $SuccessCount = '{0:N0}' -f $Success
    Write-Host "[Alert] Basic Authentication (Legacy Authentication Client) detected: Authenticated SMTP ($Count)" -ForegroundColor Red
    Write-Host "[Alert] $FailureCount failed Sign-Ins via Legacy Authentication Client detected: Authenticated SMTP" -ForegroundColor Red
    Write-Host "[Alert] $SuccessCount successful Sign-Ins via Legacy Authentication Client detected: Authenticated SMTP" -ForegroundColor Red
}

# LETHAL-004: ROPC Authentication Flow (Legacy Authentication aka Basic Authentication): AuthenticationProtocol
$Count = ($Hunt | Where-Object { $_.AuthenticationProtocol -eq "ropc" } | Measure-Object).Count
if ($Count -ge 1)
{
    Write-Host "[Alert] $Count Legacy Authentication Flow(s) found - AuthenticationProtocol" -ForegroundColor Red
}

# LETHAL-005: ROPC Authentication Flow (Legacy Authentication aka Basic Authentication): UserAgent
$Count = ($Hunt | Where-Object {($_.UserAgent -eq "BAV2ROPC" -or $_.UserAgent -eq "AConsumerV2ROPC")} | Where-Object { $_.AuthenticationRequirement -eq "singleFactorAuthentication" } | Measure-Object).Count
if ($Count -ge 1)
{
    Write-Host "[Alert] $Count Legacy Authentication Flow(s) found - UserAgent" -ForegroundColor Red
}

# LETHAL-006: Intune Bypass / Device Compliance Bypass
$Import = Get-Content -Path "$LogFile" -Raw | ConvertFrom-Json 
$Data = $Import | Where-Object {$_.appId -eq "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223"} | Where-Object {($_.status.errorCode -eq "0" -or $_.status.errorCode -eq "50199")} | Where-Object { $_.deviceDetail.IsCompliant -eq $false } | Sort-Object { $_.createdDateTime -as [datetime] } -Descending
$SignIns = $Data | Where-Object {($_.appliedConditionalAccessPolicies.enforcedGrantControls -match "RequireCompliantDevice" -and $_.appliedConditionalAccessPolicies.result -eq "failure") -or ($_.appliedConditionalAccessPolicies.enforcedGrantControls -match "Block" -and $_.appliedConditionalAccessPolicies.result -eq "notApplied")}
$Count = ($SignIns | Measure-Object).Count

if ($Count -ge 1)
{
    Write-Host "[Alert] Device Compliance Bypass detected: Microsoft Intune Company Portal ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\IntuneBypass" -ItemType Directory -Force | Out-Null

    # JSON
    $SignIns | ConvertTo-Json -Depth 10 | Out-File "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\IntuneBypass\IntuneBypass.json" -Encoding UTF8

    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($SignIn in $SignIns)
    {
        $DeviceDetail = $SignIn | Select-Object -ExpandProperty deviceDetail
        $Status = $SignIn | Select-Object -ExpandProperty status
        $AuthenticationAppDeviceDetails = $SignIn | Select-Object -ExpandProperty authenticationAppDeviceDetails

        # IpAddress
        $IP = $SignIn.iPAddress

        # Check if HashTable contains IP
        if($IPinfo_HashTable.ContainsKey("$IP"))
        {
            $City        = $IPinfo_HashTable["$IP"][0]
            $Region      = $IPinfo_HashTable["$IP"][1]
            $Country     = $IPinfo_HashTable["$IP"][2]
            $CountryName = $IPinfo_HashTable["$IP"][3]
            $Location    = $IPinfo_HashTable["$IP"][5]
            $ASN         = $IPinfo_HashTable["$IP"][6] | ForEach-Object {$_ -replace "^AS"}
            $OrgName     = $IPinfo_HashTable["$IP"][7]
            $Timezone    = $IPinfo_HashTable["$IP"][9]
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
            $Timezone    = ""
        }

        $Line = [PSCustomObject]@{
        "Id"                               = $SignIn.id
        "CreatedDateTime"                  = (Get-Date $SignIn.createdDateTime).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
        "UserDisplayName"                  = $SignIn.userDisplayName
        "UserPrincipalName"                = $SignIn.userPrincipalName
        "UserId"                           = $SignIn.userId
        "AppId"                            = $SignIn.appId
        "AppDisplayName"                   = $SignIn.appDisplayName
        "ClientAppUsed"                    = $SignIn.clientAppUsed
        "CorrelationId"                    = $SignIn.correlationId
        "OriginalRequestId"                = $SignIn.originalRequestId
        "IPAddress"                        = $IP
        "City"                             = $City
        "Region"                           = $Region
        "Country"                          = $Country
        "Country Name"                     = $CountryName
        "Location"                         = $Location
        "ASN"                              = $ASN
        "OrgName"                          = $OrgName
        "Timezone"                         = $Timezone
        "UserAgent"                        = $SignIn.userAgent
        "Browser"                          = $DeviceDetail.browser
        "DeviceId"                         = $DeviceDetail.deviceId
        "DisplayName"                      = $DeviceDetail.displayName
        "ErrorCode"                        = $Status.ErrorCode
        "FailureReason"                    = $Status.FailureReason
        "AdditionalDetails"                = $Status.additionalDetails
        "SessionId"                        = $SignIn.sessionId
        "ResourceDisplayName"              = $SignIn.ResourceDisplayName
        "ResourceId"                       = $SignIn.ResourceId
        "IsCompliant"                      = $DeviceDetail.isCompliant
        "IsManaged"                        = $DeviceDetail.isManaged
        "OperatingSystem"                  = $DeviceDetail.operatingSystem
        "TrustType"                        = $DeviceDetail.trustType
        "ConditionalAccessStatus"          = $SignIn.conditionalAccessStatus | ForEach-Object { $_.Replace("success","Success") } 
        "IsInteractive"                    = $SignIn.isInteractive
        "AuthenticationProtocol"           = $SignIn.authenticationProtocol
        "AuthenticationRequirement"        = $SignIn.authenticationRequirement
        "SignInEventType"                  = $SignIn | Select-Object -ExpandProperty signInEventTypes
        "AuthenticationAppDeviceId"        = $AuthenticationAppDeviceDetails.deviceId
        "AuthenticationAppOperationSystem" = $AuthenticationAppDeviceDetails.operatingSystem
        "AuthenticationAppClientApp"       = $AuthenticationAppDeviceDetails.clientApp
        "AuthenticationAppAppVersion"      = $AuthenticationAppDeviceDetails.appVersion
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\IntuneBypass\IntuneBypass.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\IntuneBypass\IntuneBypass.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\IntuneBypass\IntuneBypass.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\IntuneBypass\IntuneBypass.csv" -Delimiter "," | Sort-Object { $_.CreatedDateTime -as [datetime] } -Descending
            $Results | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\IntuneBypass\IntuneBypass.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -WorkSheetname "Intune Bypass" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:AP1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-AP
            $WorkSheet.Cells["A:AP"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - AppId
            Add-ConditionalFormatting -Address $WorkSheet.Cells["F:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("9ba1a5c7-f17a-4de9-a1f1-6178c8d51223",$F1)))' -BackgroundColor Red # Microsoft Intune Company Portal
            # ConditionalFormatting - ErrorCode
            Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$X1="0"' -BackgroundColor Red # Success
            Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$X1="50199"' -BackgroundColor Red # Microsoft Intune Prompt: Are you trying to sign in to Microsoft Intune Company Portal?
            # ConditionalFormatting - IsCompliant
            Add-ConditionalFormatting -Address $WorkSheet.Cells["AD:AD"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$AD1="False"' -BackgroundColor Red
            # ConditionalFormatting - ResourceId
            Add-ConditionalFormatting -Address $WorkSheet.Cells["AC:AC"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$AC1="00000003-0000-0000-c000-000000000000"' -BackgroundColor Red # Microsoft Graph
            Add-ConditionalFormatting -Address $WorkSheet.Cells["AC:AC"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$AC1="00000002-0000-0000-c000-000000000000"' -BackgroundColor Red # Windows Azure Active Directory (Azure AD Graph API)
            # ConditionalFormatting - TrustType
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["AG2:AG$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("",$AG2)))' -BackgroundColor Red # Non-Joined Device / Non-Registered Device
            }
        }
    }
}

# Suspicious Error Codes
# https://login.microsoftonline.com/error

# LETHAL-007: ErrorCode 50199 - For security reasons, user confirmation is required for this request. Please repeat the request allowing user interaction.
# --> Microsoft Intune Prompt: Are you trying to sign in to Microsoft Intune Company Portal?
$Count = ($Hunt | Where-Object { $_.ErrorCode -eq '50199' } | Measure-Object).Count
if ($Count -ge 1)
{
    Write-Host "[Alert] Suspicious Error Code detected: 50199 - For security reasons, user confirmation is required for this request ($Count)" -ForegroundColor Yellow
}

# LETHAL-008: ErrorCode 90095 - Admin consent is required for the permissions requested by this application. An admin consent request may be sent to the admin.
$Count = ($Hunt | Where-Object { $_.ErrorCode -eq '90095' } | Measure-Object).Count
if ($Count -ge 1)
{
    Write-Host "[Alert] Suspicious Error Code detected: 90095 - Admin consent is required for the permissions requested by an application ($Count)" -ForegroundColor Red
}

# LETHAL-009: Very Risky Authentication (Microsoft Entra ID Premium P2 required)
$Count = ($Hunt| Where-Object { $_.RiskLevelDuringSignIn -eq "high" } | Where-Object { $_.RiskState -eq "atRisk" } | Where-Object {($_.RiskLevelAggregated -eq "medium" -or $_.RiskLevelAggregated -eq "high")} | Measure-Object).Count

if ($Count -ge 1)
{
    Write-Host "[Alert] Very Risky Authentication(s) detected ($Count)" -ForegroundColor Red
}

# LETHAL-010: Adversary-in-the-Middle (AitM) Phishing / MFA Attack [T1557]
# Note: "OfficeHome" is a pretty reliable application for detecting threat actors, in particular when the DeviceId is empty. --> Check for unusual IP address (outside the country, not typical for that user, etc.)
$Import = $Hunt | Where-Object { $_.AppDisplayName -eq "OfficeHome" } | Where-Object { $_.DeviceId -eq "" } | Where-Object {($_.ErrorCode -eq "0" -or $_.ErrorCode -eq "50074" -or $_.ErrorCode -eq "50140" -or $_.ErrorCode -eq "53000")}
$Count = ($Import | Measure-Object).Count
$Users = ($Import | Select-Object UserId -Unique | Measure-Object).Count

# ApplicationId = 4765445b-32c6-49b0-83e6-1d93765276ca
# ClientAppUsed = Browser
# IsInteractive = True

# 50074 - Strong Authentication is required
# 50140 - This occurred due to 'Keep me signed in' interrupt when the user was signing in.
# 53000 - Device is not in required device state: {state}. Conditional Access policy requires a compliant device, and the device is not compliant. The user must enroll their device with an approved MDM provider like Intune.

if ($Count -ge 1)
{
    Write-Host "[Alert] Potential Adversary-in-the-Middle (AitM) Phishing Attack(s) detected ($Users Users, $Count Events)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\AiTM\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\AiTM\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\AiTM\CSV\AiTM.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\AiTM\CSV\AiTM.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\AiTM\CSV\AiTM.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\AiTM\CSV\AiTM.csv" -Delimiter "," | Sort-Object { $_.CreatedDateTime -as [datetime] } -Descending
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\AiTM\XLSX\AiTM.xlsx" -NoNumberConversion * -FreezePane 2,4 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AiTM" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:AW1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-X and AA-AW
            $WorkSheet.Cells["A:X"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["AA:AW"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting
            Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("4765445b-32c6-49b0-83e6-1d93765276ca",$F1)))' -BackgroundColor Red # ApplicationId
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("OfficeHome",$G1)))' -BackgroundColor Red # AppDisplayName
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Browser",$H1)))' -BackgroundColor Red # ClientAppUsed
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("notApplied",$J1)))' -BackgroundColor Red # ConditionalAccessStatus
            Add-ConditionalFormatting -Address $WorkSheet.Cells["L:L"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$L1)))' -BackgroundColor Red # IsInteractive
            Add-ConditionalFormatting -Address $WorkSheet.Cells["S:S"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("atRisk",$S1)))' -BackgroundColor Red # RiskState
            Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("0",$X1)))' -BackgroundColor Red # ErrorCode
            Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("50074",$X1)))' -BackgroundColor Red # ErrorCode
            Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("50140",$X1)))' -BackgroundColor Red # ErrorCode
            Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("53000",$X1)))' -BackgroundColor Red # ErrorCode

            # Iterating over the ASN-Blacklist HashTable
            foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
            {
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AS1)))' -f $ASN
                Add-ConditionalFormatting -Address $WorkSheet.Cells["AS:AT"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
            }

            # Iterating over the Country-Blacklist HashTable
            foreach ($Country in $CountryBlacklist_HashTable.Keys) 
            {
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AP1)))' -f $Country
                Add-ConditionalFormatting -Address $WorkSheet.Cells["AO:AP"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
            }

            }
        }
    }

    # Hunt

    # CSV
    $Import | Group-Object UserId,UserPrincipalName,Country,"Country Name",ASN,OrgName,Region,City | Select-Object @{Name='UserId'; Expression={ $_.Values[0] }},@{Name='UserPrincipalName'; Expression={ $_.Values[1] }},@{Name='Country'; Expression={ $_.Values[2] }},@{Name='Country Name'; Expression={ $_.Values[3] }},@{Name='ASN'; Expression={ $_.Values[4] }},@{Name='OrgName'; Expression={ $_.Values[5] }},@{Name='Region'; Expression={ $_.Values[6] }},@{Name='City'; Expression={ $_.Values[7] }},Count | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\AiTM\CSV\AiTM_Hunt.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\AiTM\CSV\AiTM_Hunt.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\AiTM\CSV\AiTM_Hunt.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\AiTM\CSV\AiTM_Hunt.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\AiTM\XLSX\AiTM_Hunt.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AiTM_Hunt" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-I
            $WorkSheet.Cells["A:I"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - AuthenticationProtocol
            Add-ConditionalFormatting -Address $WorkSheet.Cells["AK:AK"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("deviceCode",$AK1)))' -BackgroundColor Red # Device Code Authentication

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
}

# Device Code Phishing --> Detect Malicious OAuth Device Code Phishing

# LETHAL-011: Device Code Authentication (Device Code Phishing Attack) - AuthenticationProtocol
$Import = $Hunt | Where-Object { $_.AuthenticationProtocol -eq "deviceCode" }
$Count = ($Import | Measure-Object).Count

if ($Count -ge 1)
{
    Write-Host "[Alert] $Count Device Code Authentication Flow(s) found - AuthenticationProtocol" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\DeviceCode" -ItemType Directory -Force | Out-Null

    # XLSX
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\DeviceCode\DeviceCode-AuthenticationProtocol.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Device Code" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:AZ1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-AZ
    $WorkSheet.Cells["A:AZ"].Style.HorizontalAlignment="Center"

    # ConditionalFormatting - AppId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("29d9ed98-a469-4536-ade2-f981bc1d605e",$F1)))' -BackgroundColor Red # Microsoft Authentication Broker

    # ConditionalFormatting - ResourceId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["V:V"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9",$V1)))' -BackgroundColor Red # Device Registration Service

    # ConditionalFormatting - AuthenticationProtocol
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AK:AK"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("deviceCode",$AK1)))' -BackgroundColor Red # Device Code Authentication

    # ConditionalFormatting - OriginalTransferMethod
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AL:AL"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("deviceCodeFlow",$AL1)))' -BackgroundColor Red # Device Code Authentication

    # ConditionalFormatting - TrustedNamedLocation
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AY:AY"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Yes",$AY1)))' -BackgroundColor $Green # Trusted IP Ranges
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AY:AY"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("No",$AY1)))' -BackgroundColor Red # Untrusted Location

    }
}

# LETHAL-012: Device Code Login to Microsoft Authenticator Broker Application (PRT Attack - Phishing for Primary Refresh Token)
$Import = $Hunt | Where-Object { $_.AuthenticationProtocol -eq "deviceCode" } | Where-Object { $_.AppId -eq "29d9ed98-a469-4536-ade2-f981bc1d605e" }
$Count = ($Import | Measure-Object).Count

if ($Count -ge 1)
{
    Write-Host "[Alert] $Count Device Code Login(s) to Microsoft Authenticator Broker Application detected" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\DeviceCode" -ItemType Directory -Force | Out-Null

    # XLSX
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\DeviceCode\DeviceCode-Login-to-Microsoft-Authenticator-Broker.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Device Code" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:AY1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-AY
    $WorkSheet.Cells["A:AY"].Style.HorizontalAlignment="Center"

    # ConditionalFormatting - AppId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("29d9ed98-a469-4536-ade2-f981bc1d605e",$F1)))' -BackgroundColor Red # Microsoft Authentication Broker

    # ConditionalFormatting - ResourceId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["V:V"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9",$V1)))' -BackgroundColor Red # Device Registration Service

    # ConditionalFormatting - AuthenticationProtocol
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AK:AK"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("deviceCode",$AK1)))' -BackgroundColor Red # Device Code Authentication

    # ConditionalFormatting - OriginalTransferMethod
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AL:AL"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("deviceCodeFlow",$AL1)))' -BackgroundColor Red # Device Code Authentication

    # ConditionalFormatting - TrustedNamedLocation
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AY:AY"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Yes",$AY1)))' -BackgroundColor $Green # Trusted IP Ranges
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AY:AY"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("No",$AY1)))' -BackgroundColor Red # Untrusted Location

    }
}

# LETHAL-013: Device Code Authentication from 'Untrusted Network'
$Import = $Hunt | Where-Object { $_.AuthenticationProtocol -eq "deviceCode" } | Where-Object { $_.TrustedNamedLocation -eq "No" }
$Count = ($Import | Measure-Object).Count

if ($Count -ge 1)
{
    Write-Host "[Alert] $Count Device Code Authentication(s) from 'Untrusted Network' detected" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\DeviceCode" -ItemType Directory -Force | Out-Null

    # XLSX
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\DeviceCode\DeviceCode-Untrusted-Network.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Device Code" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:AZ1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-AZ
    $WorkSheet.Cells["A:AZ"].Style.HorizontalAlignment="Center"

    # ConditionalFormatting - AppId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("29d9ed98-a469-4536-ade2-f981bc1d605e",$F1)))' -BackgroundColor Red # Microsoft Authentication Broker

    # ConditionalFormatting - ResourceId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["V:V"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9",$V1)))' -BackgroundColor Red # Device Registration Service

    # ConditionalFormatting - AuthenticationProtocol
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AK:AK"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("deviceCode",$AK1)))' -BackgroundColor Red # Device Code Authentication

    # ConditionalFormatting - OriginalTransferMethod
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AL:AL"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("deviceCodeFlow",$AL1)))' -BackgroundColor Red # Device Code Authentication

    # ConditionalFormatting - TrustedNamedLocation
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AY:AY"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Yes",$AY1)))' -BackgroundColor $Green # Trusted IP Ranges
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AY:AY"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("No",$AY1)))' -BackgroundColor Red # Untrusted Location

    }
}

# LETHAL-014: Device Code Authentication Flow followed by Device Registration (Device Registration Attack)
$Import = $Hunt | Where-Object { $_.AuthenticationProtocol -eq "deviceCode" } | Where-Object { $_.ResourceId -eq "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9" }
$Count = ($Import | Measure-Object).Count

if ($Count -ge 1)
{
    Write-Host "[Alert] $Count Device Code Authentication Flow(s) followed by Device Registration detected" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\DeviceCode" -ItemType Directory -Force | Out-Null

    # XLSX
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\DeviceCode\DeviceCode-Device-Registration.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Device Code" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:AY1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-AY
    $WorkSheet.Cells["A:AY"].Style.HorizontalAlignment="Center"

    # ConditionalFormatting - AppId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("29d9ed98-a469-4536-ade2-f981bc1d605e",$F1)))' -BackgroundColor Red # Microsoft Authentication Broker

    # ConditionalFormatting - ResourceId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["V:V"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9",$V1)))' -BackgroundColor Red # Device Registration Service

    # ConditionalFormatting - AuthenticationProtocol
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AK:AK"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("deviceCode",$AK1)))' -BackgroundColor Red # Device Code Authentication

    # ConditionalFormatting - OriginalTransferMethod
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AL:AL"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("deviceCodeFlow",$AL1)))' -BackgroundColor Red # Device Code Authentication

    # ConditionalFormatting - TrustedNamedLocation
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AY:AY"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Yes",$AY1)))' -BackgroundColor $Green # Trusted IP Ranges
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AY:AY"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("No",$AY1)))' -BackgroundColor Red # Untrusted Location

    }
}

# LETHAL-015: Device Code Authentication (Device Code Phishing Attack) - OriginalTransferMethod
$Import = $Hunt | Where-Object { $_.OriginalTransferMethod -eq "deviceCodeFlow" }
$Count = ($Import | Measure-Object).Count

if ($Count -ge 1)
{
    Write-Host "[Alert] $Count Device Code Authentication Flow(s) found - OriginalTransferMethod" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\DeviceCode" -ItemType Directory -Force | Out-Null

    # XLSX
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\DeviceCode\DeviceCode-OriginalTransferMethod.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Device Code" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:AZ1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-AZ
    $WorkSheet.Cells["A:AZ"].Style.HorizontalAlignment="Center"

    # ConditionalFormatting - AppId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("29d9ed98-a469-4536-ade2-f981bc1d605e",$F1)))' -BackgroundColor Red # Microsoft Authentication Broker

    # ConditionalFormatting - ResourceId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["V:V"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9",$V1)))' -BackgroundColor Red # Device Registration Service

    # ConditionalFormatting - AuthenticationProtocol
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AK:AK"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("deviceCode",$AK1)))' -BackgroundColor Red # Device Code Authentication

    # ConditionalFormatting - OriginalTransferMethod
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AL:AL"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("deviceCodeFlow",$AL1)))' -BackgroundColor Red # Device Code Authentication

    # ConditionalFormatting - TrustedNamedLocation
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AY:AY"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Yes",$AY1)))' -BackgroundColor $Green # Trusted IP Ranges
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AY:AY"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("No",$AY1)))' -BackgroundColor Red # Untrusted Location

    }
}

# AuthenticationProtocol vs. OriginalTransferMethod
# AuthenticationProtocol: Lists the protocol type or grant type used in the authentication. The possible values are: none, oAuth2, ropc, wsFederation, saml20, deviceCode.
# OriginalTransferMethod: Transfer method used to initiate a session throughout all subsequent requests.

# LETHAL-016: Suspicious Sign-Ins via Cross-Tenant Synchronization (CTS) --> Possible Lateral Movement
$Import = $Hunt | Where-Object { $_.CrossTenantAccessType -eq "b2bCollaboration" }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

if ($Count -ge 1)
{
    Write-Host "[Alert] $Count B2B Collaboration Sign-In(s) found" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\CrossTenantSynchronization" -ItemType Directory -Force | Out-Null

    # XLSX
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\CrossTenantSynchronization\b2bCollaboration.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "b2bCollaboration" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:BE1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-BD
    $WorkSheet.Cells["A:BD"].Style.HorizontalAlignment="Center"

    # ConditionalFormatting - CrossTenantAccessType
    Add-ConditionalFormatting -Address $WorkSheet.Cells["BC:BC"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("b2bCollaboration",$BC1)))' -BackgroundColor Red

    }
}

#############################################################################################################################################################################################

# Blacklisting

# LETHAL-017: Application Blacklist

# Create HashTable and import 'Application-Blacklist.csv'
$ApplicationBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\Application-Blacklist.csv")
{
    if(Test-Csv -Path "$SCRIPT_DIR\Blacklists\Application-Blacklist.csv" -MaxLines 2)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\Application-Blacklist.csv" -Delimiter "," | ForEach-Object { $ApplicationBlacklist_HashTable[$_.AppId] = $_.AppDisplayName,$_.Severity }

        # Iterating over the HashTable
        foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
        {
            $Import = $Hunt | Where-Object { $_.AppId -eq "$AppId" }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                $AppDisplayName = $ApplicationBlacklist_HashTable["$AppId"][0]
                $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                Write-Host "[Alert] Suspicious OAuth Application detected: $AppDisplayName ($Count)" -ForegroundColor $Severity
            }
        }
    }
}

# LETHAL-018: ASN Blacklist

# Create HashTable and import 'ASN-Blacklist.csv'
$AsnBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\ASN-Blacklist.csv")
{
    if(Test-Csv -Path "$SCRIPT_DIR\Blacklists\ASN-Blacklist.csv" -MaxLines 2)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\ASN-Blacklist.csv" -Delimiter "," | ForEach-Object { $AsnBlacklist_HashTable[$_.ASN] = $_.OrgName,$_.Info }

        # Iterating over the HashTable
        foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
        {
            $Import = $Hunt | Where-Object { $_.ASN -eq "$ASN" }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                $OrgName = $AsnBlacklist_HashTable["$ASN"][0]
                Write-Host "[Alert] Suspicious ASN detected: AS$ASN - $OrgName ($Count)" -ForegroundColor Red
            }
        }
    }
}

# LETHAL-019: Country Blacklist
foreach ($CountryName in $CountryBlacklist_HashTable.Keys) 
{
    $Import = $Hunt | Where-Object { $_."Country Name" -eq "$CountryName" }
    $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Country detected: $CountryName ($Count)" -ForegroundColor Red
    }
}

# LETHAL-020: User-Agent Blacklist
foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
{
    $Import = $Hunt | Where-Object { $_.UserAgent -eq "$UserAgent" }
    $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
    if ($Count -gt 0)
    {
        $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
        Write-Host "[Alert] Suspicious User-Agent detected: $UserAgent ($Count)" -ForegroundColor $Severity
    }
}

# LETHAL-021: Unusual PRT Usage and Registered Device for User Principal [T1098.005]
# This rule alerts when a user principal authenticates from a potential newly observed device, particularly if the session is unbound, which is characteristic of token replay or device spoofing.
# Adversaries trick users into authorizing access for the Microsoft Authentication Broker (MAB) targeting the Device Registration Service (DRS), obtain a RT, and then use a tool like ROADtx to silently register a fake Windows device and mint a PRT.
# https://www.elastic.co/security-labs/entra-id-oauth-phishing-detection
# https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/persistence_entra_id_user_signed_in_from_unusual_device.toml
# https://attack.mitre.org/techniques/T1098/005/
$Import = $Hunt`
| Where-Object { $_.AppId -eq "29d9ed98-a469-4536-ade2-f981bc1d605e" }`
| Where-Object { $_.UserType -eq "Member" }`
| Where-Object { $_.SignInTokenProtectionStatus -eq "unbound" }`
| Where-Object { $_.DeviceId -ne "" }`
| Where-Object { $_.IncomingTokenType -eq "primaryRefreshToken" }

$Count = ($Import | Measure-Object).Count

if ($Count -ge 1)
{
    Write-Host "[Alert] Possible Token Replay - Unusual PRT Usage and Registered Device found ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\Alerts" -ItemType Directory -Force | Out-Null

    # XLSX
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\Unusual-PRT-Usage-and-Registered-Device.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Unusual PRT Usage" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:BE1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-BD
    $WorkSheet.Cells["A:BD"].Style.HorizontalAlignment="Center"

    # ConditionalFormatting - AppId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("29d9ed98-a469-4536-ade2-f981bc1d605e",$F1)))' -BackgroundColor Red # Microsoft Authentication Broker

    # ConditionalFormatting - AppDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Microsoft Authentication Broker",$G1)))' -BackgroundColor Red

    # ConditionalFormatting - DeviceId --> Check if the device was registered the last 7 days! --> Devices-Analyzer.ps1
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AB:AB"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("-",$AB1)))' -BackgroundColor Red

    # ConditionalFormatting - UserType
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AX:AX"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Member",$AX1)))' -BackgroundColor Red # Microsoft Entra ID user

    # ConditionalFormatting - TrustedNamedLocation
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AY:AY"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Yes",$AY1)))' -BackgroundColor $Green # Trusted IP Ranges
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AY:AY"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("No",$AY1)))' -BackgroundColor Red # Untrusted Location

    # ConditionalFormatting - IncomingTokenType
    Add-ConditionalFormatting -Address $WorkSheet.Cells["BB:BB"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("primaryRefreshToken",$BB1)))' -BackgroundColor Red # Primary Refresh Token (PRT) --> Persistence

    # ConditionalFormatting - SignInTokenProtectionStatus
    Add-ConditionalFormatting -Address $WorkSheet.Cells["BC:BC"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("unbound",$BC1)))' -BackgroundColor Red # Session is unbound, which is characteristic of token replay or device spoofing.

    # Bound / Unbound
    # Token protection creates a cryptographically secure tie between the token and the device (client secret) it's issued to. Without the client secret, the bound token is useless. 
    # When a user registers a Windows 10 or newer device in Microsoft Entra ID, their primary identity is bound to the device. 
    # What this means: A policy can ensure that only bound sign-in session (or refresh) tokens, otherwise known as Primary Refresh Tokens (PRTs) are used by applications when requesting access to a resource.

    # ConditionalFormatting - ASN
    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AS1)))' -f $ASN
        Add-ConditionalFormatting -Address $WorkSheet.Cells["AS:AT"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    # ConditionalFormatting - Country
    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AP1)))' -f $Country
        Add-ConditionalFormatting -Address $WorkSheet.Cells["AP:AQ"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    # ConditionalFormatting - UserAgent
    foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
    {
        $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AW1)))' -f $UserAgent
        Add-ConditionalFormatting -Address $WorkSheet.Cells["AW:AW"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
    }

    }
}

# ResourceId
# 90a2e5d2-fd7a-4a2e-bc90-3dc50ae8e3ee - ???

# LETHAL-022: Suspicious Sign-Ins via Visual Studio Code Client --> Visual Studio Code Phishing (Abusing Legitimate Microsoft Workflow)
# https://www.elastic.co/security-labs/entra-id-oauth-phishing-detection
# https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/initial_access_entra_oauth_phishing_via_vscode_client.toml
$Import = $Hunt`
| Where-Object { $_.AppId -eq "aebc6443-996d-45c2-90f0-388ff96faa56" }`
| Where-Object { $_.ResourceId -eq "00000003-0000-0000-c000-000000000000" }`
| Where-Object { $_.UserType -eq "Member" }`
| Where-Object { $_.Status -eq "Success" }

$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

if ($Count -ge 1)
{
    Write-Host "[Alert] Suspicious Sign-In(s) via Visual Studio Code Client found ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\VSCode" -ItemType Directory -Force | Out-Null

    # XLSX
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\VSCode\Suspicious-SignIns-via-Visual-Studio-Code.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "VSCode" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:BE1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-BD
    $WorkSheet.Cells["A:BD"].Style.HorizontalAlignment="Center"

    # ConditionalFormatting - AppId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("aebc6443-996d-45c2-90f0-388ff96faa56",$F1)))' -BackgroundColor Red # Visual Studio Code (VSCode)

    # ConditionalFormatting - AppDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Visual Studio Code",$G1)))' -BackgroundColor Red

    # ConditionalFormatting - SignInEventType
    Add-ConditionalFormatting -Address $WorkSheet.Cells["L:L"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("nonInteractiveUser",$L1)))' -BackgroundColor Red

    # ConditionalFormatting - ResourceDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["U:U"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Microsoft Graph",$U1)))' -BackgroundColor Red # Delegated Access to the Microsoft Graph API

    # ConditionalFormatting - ResourceId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["V:V"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("00000003-0000-0000-c000-000000000000",$V1)))' -BackgroundColor Red # Microsoft Graph

    # ConditionalFormatting - UserType
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AX:AX"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Member",$AX1)))' -BackgroundColor Red

    # ConditionalFormatting - TrustedNamedLocation
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AY:AY"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Yes",$AY1)))' -BackgroundColor $Green # Trusted IP Ranges
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AY:AY"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("No",$AY1)))' -BackgroundColor Red # Untrusted Location

    # ConditionalFormatting - ASN
    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AS1)))' -f $ASN
        Add-ConditionalFormatting -Address $WorkSheet.Cells["AS:AT"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    # ConditionalFormatting - Country
    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AP1)))' -f $Country
        Add-ConditionalFormatting -Address $WorkSheet.Cells["AP:AQ"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    # ConditionalFormatting - UserAgent
    foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
    {
        $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AW1)))' -f $UserAgent
        Add-ConditionalFormatting -Address $WorkSheet.Cells["AW:AW"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
    }

    }
}

# LETHAL-023: Suspicious ADRS Token Request by Microsoft Authentication Broker
# https://www.elastic.co/security-labs/entra-id-oauth-phishing-detection
# https://github.com/elastic/detection-rules/blob/6b6407df88319f466c6cc56147210635bba5eb01/rules/integrations/azure/persistence_entra_id_suspicious_adrs_token_request.toml
# Detects suspicious OAuth 2.0 token requests where the Microsoft Authentication Broker (29d9ed98-a469-4536-ade2-f981bc1d605e) requests access to the Device Registration Service (01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9) on behalf of a user principal. 
# The presence of the adrs_access scope in the authentication processing details suggests an attempt to access ADRS, which is atypical for standard user sign-ins. 
# This behavior may reflect an effort to abuse device registration for unauthorized persistence, such as acquiring a Primary Refresh Token (PRT) or establishing a trusted session.
$Import = $Hunt`
| Where-Object { $_.AppId -eq "29d9ed98-a469-4536-ade2-f981bc1d605e" }`
| Where-Object { $_.ResourceId -eq "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9" }`
| Where-Object { $_."Oauth Scope Info" -match "adrs_access" }`
| Where-Object { $_.IncomingTokenType -eq "refreshToken" }`
| Where-Object { $_.UserType -eq "Member" }

# | Where-Object { $_.IncomingTokenType -eq "refreshToken" -or $_.IncomingTokenType -eq "none" }`

$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

if ($Count -ge 1)
{
    Write-Host "[Alert] $Count Suspicious ADRS Token Request(s) by Microsoft Authentication Broker found" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\Alerts" -ItemType Directory -Force | Out-Null

    # XLSX
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\Suspicious-ADRS-Token-Request-by-MAB.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ADRS Token Requests" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:BE1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-BE
    $WorkSheet.Cells["A:BE"].Style.HorizontalAlignment="Center"
    
    # ConditionalFormatting - AppId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("29d9ed98-a469-4536-ade2-f981bc1d605e",$F1)))' -BackgroundColor Red # Microsoft Authentication Broker (MAB)
    
    # ConditionalFormatting - AppDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Microsoft Authentication Broker",$G1)))' -BackgroundColor Red

    # ConditionalFormatting - ResourceDisplayName
    Add-ConditionalFormatting -Address $WorkSheet.Cells["U:U"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Device Registration Service",$U1)))' -BackgroundColor Red
    
    # ConditionalFormatting - ResourceId
    Add-ConditionalFormatting -Address $WorkSheet.Cells["V:V"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9",$V1)))' -BackgroundColor Red # Device Registration Service (DRS)

    # ConditionalFormatting - Oauth Scope Info
    Add-ConditionalFormatting -Address $WorkSheet.Cells["BD:BD"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("adrs_access",$BD1)))' -BackgroundColor Red # ["adrs_access"]

    # ConditionalFormatting - IncomingTokenType
    Add-ConditionalFormatting -Address $WorkSheet.Cells["BB:BB"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("refreshToken",$BB1)))' -BackgroundColor Red

    # ConditionalFormatting - UserType
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AX:AX"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Member",$AX1)))' -BackgroundColor Red

    # ConditionalFormatting - TrustedNamedLocation
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AY:AY"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Yes",$AY1)))' -BackgroundColor $Green # Trusted IP Ranges
    Add-ConditionalFormatting -Address $WorkSheet.Cells["AY:AY"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("No",$AY1)))' -BackgroundColor Red # Untrusted Location

    # ConditionalFormatting - ASN
    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AS1)))' -f $ASN
        Add-ConditionalFormatting -Address $WorkSheet.Cells["AS:AT"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    # ConditionalFormatting - Country
    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AP1)))' -f $Country
        Add-ConditionalFormatting -Address $WorkSheet.Cells["AP:AQ"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    # ConditionalFormatting - UserAgent
    foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
    {
        $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AW1)))' -f $UserAgent
        Add-ConditionalFormatting -Address $WorkSheet.Cells["AW:AW"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
    }

    }
}

$EndTime_Analytics = (Get-Date)
$Time_Analytics = ($EndTime_Analytics-$StartTime_Analytics)
('EntraSignInLogs Analytics duration:       {0} h {1} min {2} sec' -f $Time_Analytics.Hours, $Time_Analytics.Minutes, $Time_Analytics.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#endregion Analytics

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# Main
Start-Processing
Get-IPLocation
Get-Stats
Get-Analytics

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
$MessageTitle = "EntraSignInLogs-Analyzer.ps1 (https://lethal-forensics.com/)"
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

# Types of Sign-In Identifiers
#
# CorreleationId        - Groups sign-ins from the same sign-in session, generated by client (not Identity Provider)
# RequestId             - An identifier that corresponds to an issued token. The request identifier of the first request in the authentication sequence.
# UniqueTokenIdentifier - Used to correlate the sign-in with the token request (passed during the sign-in). Track tokens issued by Microsoft Entra ID as they're redeemed at resource providers.
# SessionId             - Identify and match the session (cookie) that was generated during the sign-in between the client and the Identity Provider.

# TA may checks how many other third party services they can access from that compromised account.

# SIG # Begin signature block
# MIIrywYJKoZIhvcNAQcCoIIrvDCCK7gCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUeGQ+6kgnwq9D3EJMD57dtJE1
# vo6ggiUEMIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
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
# MCMGCSqGSIb3DQEJBDEWBBRT/4F7rkX+7QAPIitUP1rIgpLVZTANBgkqhkiG9w0B
# AQEFAASCAgAzxA/3PKTlWBTauZuCQhBb5u28G8YQ/XfBGUn1nM/MuPRSUaUb3QAS
# uJYBiGIYLIlp8np9+TFg0nHk8o0NqnZBWZgqICZnk7m+fnnsE3Y27zUQxlvSYAFq
# VdFziBM1HxVrHwdH+4NaPyaYJjx7BF8aq5AU6ebgQUuhje5ejN0ZIPHa0sRWoVGH
# Nvx7S+mYumN5VrO9kzU81Tjxtr+li/CTrURK0DqUxDTAGl2HyPURjdY0HWRVqFmT
# MJPqIDFhE+3jc/NQM4YE6Fs7xRAT2tiPRfvI9uMj1e14UjueZOz8Xsa3vmsVOywG
# T70gmN5DRFqzJagxdKz17XVWrBYB9N/53Fl5Cy5OhX5z7qZSeJS9k6EULVD7WHNz
# 0bjjX7KC6YUsdRjM92HZ4W3dKeD3pDW09ZqSdI/0EhYvkckkm7ihvgDpCNn2kHFC
# /NJvJyAkARAjKgGqJ1PY+omyWU4HspOy6Ee/6vbgPbSiBEssIfnrrA5RcijV4Y9+
# svKXdftRFzaitsYh+OTRfDS4o3zJGfUXUItMg8qsDYNdMao0HHEDHTKX7OxKU53C
# caG1uXTvopnEJM/elzas2PSlhpOViIbbU1EYjuZzRJXn3ZuHCF03oOgZZHOPnDlW
# fIdOqlLL+6CPuunILZzjWkfaDkAgqZwKmh58z3jKMZHViGSCvmp70aGCAyMwggMf
# BgkqhkiG9w0BCQYxggMQMIIDDAIBATBqMFUxCzAJBgNVBAYTAkdCMRgwFgYDVQQK
# Ew9TZWN0aWdvIExpbWl0ZWQxLDAqBgNVBAMTI1NlY3RpZ28gUHVibGljIFRpbWUg
# U3RhbXBpbmcgQ0EgUjM2AhEApCk7bh7d16c0CIetek63JDANBglghkgBZQMEAgIF
# AKB5MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MDkxODA1MDkzOFowPwYJKoZIhvcNAQkEMTIEMFFZ3k1CsQ2WjoIVl9+md72YswLy
# xRPCAoDsfqhMjguyF+ROXnzFXA7JGIqjJPz1MzANBgkqhkiG9w0BAQEFAASCAgC6
# w8CucIG3LYdWIAr8j8yyRo9JA2K9AdAlxDGnfnvUAqZJu+E9oQIyfyb0/QKxyMEd
# AHvE/BHGTmzQPRaOtN5A1bJyEUPkL4TnDgpVWpmB0WRABpnVbiU8IRD9f1uxeRE9
# KW49HeRoLH3WD+a/469hBOXdeE13afw5b0a17x4hmWYwZIhSMQBMEEcVCdUNRsMm
# cd+2uhU3gYHNYykeuNXrJNkt1GmWHEGwQp6Nmhmu6wzIr+2VgDY97fOKFCPjFYsf
# D9sU4iPnirFh1ahJA5qG5kS3Iy/16qCCiiGGv5ocbXieRc3lw8BPBPL8w5K9t7B2
# dxaJmquSBhZqUWs2eeftfSbP6eTxTXRPe+vG6DrKZBdggAPp1thfQtZp33dtP7cT
# YLWQb/+jxXSeqFGizwtx2WQRBh9+8eYRAl4MRHK82ME4HRr1mJGVOr0Rk/PZ95FN
# U/LlO0rlKI5IHUsMqcr6O2ns8KzWwIUc5QdDdmftAo0JaStRvGjlR98yYaHd4EPJ
# dz+UWiqnIcioYeLq+1RPwWW7j88wWewkTUDTDeTiPGkXbNAkn3vCixxq2G2cLqkT
# IaIkpc4U7s00MJC6tFOkfN9PvjxBpz7FkTGOtq2VSgGwT5tFzu8TOykmjJc5K2Se
# MLWkjP9HAXXbpoph9k9+vUj1vmVWVBpyLYIv/AnvyQ==
# SIG # End signature block
