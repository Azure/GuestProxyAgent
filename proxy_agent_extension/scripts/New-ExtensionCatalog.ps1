[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $ExtensionPackageDirectory,

    [string] $MakeCatPath = $env:MAKECAT_PATH
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ExtensionPackageDirectory -PathType Container)) {
    throw "Extension package directory does not exist: $ExtensionPackageDirectory"
}

$handlerFiles = @(
    'disable.cmd'
    'enable.cmd'
    'install.cmd'
    'reset.cmd'
    'uninstall.cmd'
    'update.cmd'
)

foreach ($handlerFile in $handlerFiles) {
    $handlerPath = Join-Path $ExtensionPackageDirectory $handlerFile
    if (-not (Test-Path -LiteralPath $handlerPath -PathType Leaf)) {
        throw "Catalog input does not exist: $handlerPath"
    }
}

if ([string]::IsNullOrWhiteSpace($MakeCatPath)) {
    $makeCatCommand = Get-Command makecat.exe -ErrorAction SilentlyContinue
    if ($makeCatCommand) {
        $MakeCatPath = $makeCatCommand.Source
    }
}

if ([string]::IsNullOrWhiteSpace($MakeCatPath)) {
    $windowsKitsBin = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    if (Test-Path -LiteralPath $windowsKitsBin -PathType Container) {
        $MakeCatPath = Get-ChildItem -LiteralPath $windowsKitsBin -Directory |
            Sort-Object Name -Descending |
            ForEach-Object { Join-Path $_.FullName 'x64\makecat.exe' } |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
            Select-Object -First 1
    }
}

if ([string]::IsNullOrWhiteSpace($MakeCatPath) -or
    -not (Test-Path -LiteralPath $MakeCatPath -PathType Leaf)) {
    throw 'makecat.exe was not found. Install the Windows SDK or set MAKECAT_PATH to its full path.'
}

$catalogDefinitionSource = Join-Path $PSScriptRoot '..\src\windows\GuestProxyAgentExtension.cdf'
$catalogDefinitionPath = Join-Path $ExtensionPackageDirectory 'GuestProxyAgentExtension.cdf'
$catalogPath = Join-Path $ExtensionPackageDirectory 'GuestProxyAgentExtension.cat'

Copy-Item -LiteralPath $catalogDefinitionSource -Destination $catalogDefinitionPath -Force
Remove-Item -LiteralPath $catalogPath -Force -ErrorAction SilentlyContinue

Push-Location $ExtensionPackageDirectory
try {
    & $MakeCatPath (Split-Path $catalogDefinitionPath -Leaf)
    if ($LASTEXITCODE -ne 0) {
        throw "makecat.exe failed with exit code $LASTEXITCODE."
    }

    if (-not (Test-Path -LiteralPath $catalogPath -PathType Leaf)) {
        throw "makecat.exe did not create the expected catalog: $catalogPath"
    }
}
finally {
    Pop-Location
    Remove-Item -LiteralPath $catalogDefinitionPath -Force -ErrorAction SilentlyContinue
}

Write-Host "Generated extension catalog: $catalogPath"
