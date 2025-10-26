<#
.SYNOPSIS
  ConvertFrom-UserAuthenticationMethod - Decoding the "UserAuthenticationMethod" field in Microsoft 365 Unified Audit Logs

.DESCRIPTION
  ConvertFrom-UserAuthenticationMethod.ps1 is a simple PowerShell script utilized to convert the "UserAuthenticationMethod" numeric value to a human-readable description.

  Source: Unified Audit Logs (UAL) --> ExtendedProperties --> UserAuthenticationMethod
  Operations: UserLoggedIn, UserLoginFailed --> Sign-in Events

  Sekoia.io analysts have discovered that this field is a bitfield where each bit represents a different authentication method.
  https://blog.sekoia.io/userauthenticationmethod-microsoft-365-decode/

  Bitfield Mapping Technique

  $Decimal = "272"
  $Binary  = [Convert]::ToString($Decimal, 2)

  100010000

  Decimal | 2048 | 1024 | 512 | 256 | 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |
  Bit     |      |      |     |  1  |  0  |  0 |  0 |  1 | 0 | 0 | 0 | 0 |

  16 + 256 = 272

  Note: You can add the leading zeros. Read from left to right.

.PARAMETER DecimalValue
  Specifies the decimal value of the "UserAuthenticationMethod" field.

.EXAMPLE
  PS> .\ConvertFrom-UserAuthenticationMethod.ps1 -DecimalValue 1

  Password in the Cloud

.EXAMPLE
  PS> .\ConvertFrom-UserAuthenticationMethod.ps1 -DecimalValue 16

  Password Hash Sync

.EXAMPLE
  PS> .\ConvertFrom-UserAuthenticationMethod.ps1 -DecimalValue 272

  Password Hash Sync + via Staged Rollout

.EXAMPLE
  PS> .\ConvertFrom-UserAuthenticationMethod.ps1 -DecimalValue 33554704

  Password Hash Sync + via Staged Rollout + Passkey (FIDO2)

.NOTES
  Author - Martin Willing

.LINK
  https://lethal-forensics.com/
#>

[CmdletBinding()]
Param(
    [int]$DecimalValue
)

Begin
{
    $HashTable = @{
        "Password in the Cloud"       = 1
        "Temporary Access Pass"       = 2
        "Seamless SSO"                = 4
        "Pass-through Authentication" = 8
        "Password Hash Sync"          = 16
        "Passwordless Phone Sign-in"  = 64
        "via Staged Rollout"          = 256
        "Windows Hello for Business"  = 262144
        "QR Code"                     = 524288
        "SMS Sign-in"                 = 1048576
        "X.509 Certificate"           = 2097152
        "MacOS Platform Credentials"  = 8388608
        "QR Code PIN"                 = 16777216
        "Passkey (FIDO2)"             = 33554432
        "Email Verification Code"     = 134217728
    }
}

Process
{
    $Return = @()
    foreach ($Bit in ($HashTable.GetEnumerator() | Sort-Object -Property Value ))
    {
        if (($DecimalValue -band $Bit.Value) -ne 0)
        {
            $Return += $Bit.Key
        }
    }
}

End
{
    $UserAuthenticationMethod = $Return -join " + "
    $UserAuthenticationMethod
}