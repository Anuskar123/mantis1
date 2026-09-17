$ErrorActionPreference = "Stop"

$Folder = Split-Path -Parent $MyInvocation.MyCommand.Path
$Part1 = Join-Path $Folder "MANTIS_Raw_Dataset.zip.001"
$Part2 = Join-Path $Folder "MANTIS_Raw_Dataset.zip.002"
$Output = Join-Path $Folder "MANTIS_Raw_Dataset_Reassembled.zip"
$ExpectedHash = "7900EAFC6EDDDD2CFAE0B7AC32C62213F98BABCD005A23D3FB8360C262C412E2"

if (-not (Test-Path -LiteralPath $Part1 -PathType Leaf)) {
    throw "Missing $Part1"
}
if (-not (Test-Path -LiteralPath $Part2 -PathType Leaf)) {
    throw "Missing $Part2"
}
if (Test-Path -LiteralPath $Output) {
    throw "Output already exists: $Output"
}

$Destination = [System.IO.File]::Open($Output, [System.IO.FileMode]::CreateNew)
try {
    foreach ($Part in @($Part1, $Part2)) {
        $Source = [System.IO.File]::OpenRead($Part)
        try {
            $Source.CopyTo($Destination)
        }
        finally {
            $Source.Dispose()
        }
    }
}
finally {
    $Destination.Dispose()
}

$ActualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Output).Hash
if ($ActualHash -ne $ExpectedHash) {
    throw "Reassembled archive hash mismatch. Expected $ExpectedHash but received $ActualHash"
}

Write-Output "Reassembled archive: $Output"
Write-Output "SHA256 verified: $ActualHash"
