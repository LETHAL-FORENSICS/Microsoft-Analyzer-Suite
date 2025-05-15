Function Test-Csv {

<#
.SYNOPSIS
  Test-Csv - Fast Check if CSV is NOT empty

.DESCRIPTION
  The Test-Csv cmdlet checks if the rows of your CSV file are NOT empty.

.PARAMETER Path
  Specifies the path to the CSV file.

.PARAMETER MaxLines
  Specifies the maximum of lines to read from CSV file.

.PARAMETER NoHeader (Optional)
  If this switch is specified, function will NOT skip first line of the file. 

.EXAMPLE
  Test-Csv -Path <CSV> -MaxLines 2

.EXAMPLE
  Test-Csv -Path <CSV> -MaxLines 1 -NoHeader

.NOTES
  Author - Martin Willing

.LINK
  https://lethal-forensics.com/
#>

Param
(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [string]$Path,

    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$MaxLines,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [switch]$NoHeader
)

Begin
{
    $Quotes    = '"'
    $Delimiter = ','
    $Regex     = "$Delimiter(?=(?:[^$Quotes]|$Quotes[^$Quotes]*$Quotes)*$)" # Known Issue: Multiline fields
}

Process
{
    $Reader = New-Object -TypeName System.IO.StreamReader -ArgumentList $Path -ErrorAction Stop

    $CsvRawLinesCount  = 0
    $CsvDataLinesCount = 0

    while($null -ne ($Line = $Reader.ReadLine()))
    {
        $CsvRawLinesCount++

        if(!$NoHeader -and ($CsvRawLinesCount -eq 1))
        {
            continue
        }

        if($CsvRawLinesCount -gt $MaxLines)
        {
            break
        }

        if($Line -match $Regex)
        {
            $CsvDataLinesCount++
        }
    }
}

End
{
    $Reader.Close()
    $Reader.Dispose()

    if($CsvDataLinesCount -gt 0)
    {
        $true
    }
    else
    {
        $false
    }
}

}