<#
.SYNOPSIS
    Publishes "Managed Encryption Escrow.exe" for one architecture, with its XAML resources.

.DESCRIPTION
    The app project sets EnableCoreMrtTooling=false: the MSBuild PRI step needs a Visual
    Studio workload that build machines do not have. This script does that step instead,
    after dotnet publish:
      1. copies the compiled XAML (.xbf) from obj\ into the output, where MRT loads it;
      2. stages the .xbf files with the WinUI framework .pri files;
      3. runs makepri.exe from the Windows SDK to merge them into resources.pri.
    Without resources.pri the app cannot load its XAML and exits at launch.

.EXAMPLE
    .\build\app\Publish-App.ps1 -Arch x64 -OutputDir dist\x64\app
#>
param(
    [Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string]$Arch,
    [Parameter(Mandatory)][string]$OutputDir,
    [string]$Version
)

$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$project = Join-Path $root 'src\CryptEscrow.App\CryptEscrow.App.csproj'
$projectDir = Split-Path $project

if (Test-Path $OutputDir) { Remove-Item $OutputDir -Recurse -Force }
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$OutputDir = (Resolve-Path $OutputDir).Path

$publishArgs = @(
    'publish', $project,
    '--configuration', 'Release',
    '--runtime', "win-$Arch",
    '--self-contained', 'true',
    '--output', $OutputDir,
    '--verbosity', 'minimal'
)
if ($Version) { $publishArgs += "-p:Version=$Version" }

& dotnet @publishArgs
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed for the app ($Arch): exit $LASTEXITCODE" }

$exe = Join-Path $OutputDir 'Managed Encryption Escrow.exe'
if (-not (Test-Path $exe)) { throw "Expected $exe after publish" }

# makepri.exe runs on the build host, so prefer the host's architecture.
$hostArch = switch ($env:PROCESSOR_ARCHITECTURE) { 'AMD64' { 'x64' } 'ARM64' { 'arm64' } default { 'x86' } }
$toolArchs = @($hostArch) + (@('x64', 'arm64', 'x86') | Where-Object { $_ -ne $hostArch })
$makepri = $null
foreach ($sdkBin in @("${env:ProgramFiles(x86)}\Windows Kits\10\bin", "$env:ProgramFiles\Windows Kits\10\bin") | Where-Object { Test-Path $_ }) {
    foreach ($toolArch in $toolArchs) {
        $found = Get-ChildItem "$sdkBin\*\$toolArch\makepri.exe" -ErrorAction SilentlyContinue |
            Sort-Object { [version]($_.FullName -replace '.*\\(\d+\.\d+\.\d+\.\d+)\\.*', '$1') } -Descending |
            Select-Object -First 1
        if ($found) { $makepri = $found.FullName; break }
    }
    if ($makepri) { break }
}
if (-not $makepri) { throw 'makepri.exe not found: install the Windows 10/11 SDK' }

$xbfFiles = Get-ChildItem (Join-Path $projectDir 'obj\Release') -Recurse -Filter '*.xbf' |
    Where-Object { $_.FullName -match [regex]::Escape("\win-$Arch\") }
if (-not $xbfFiles) { throw "No compiled XAML (.xbf) found under obj\Release for win-$Arch" }
$xbfRoot = ($xbfFiles[0].FullName -split [regex]::Escape("\win-$Arch\"))[0] + "\win-$Arch"

$staging = Join-Path ([IO.Path]::GetTempPath()) "managed-encryption-pri-$Arch"
if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
New-Item -ItemType Directory $staging | Out-Null

try {
    foreach ($xbf in $xbfFiles) {
        $relative = $xbf.FullName.Substring($xbfRoot.Length).TrimStart('\')
        foreach ($destRoot in $staging, $OutputDir) {
            $dest = Join-Path $destRoot $relative
            New-Item -ItemType Directory (Split-Path $dest) -Force | Out-Null
            Copy-Item $xbf.FullName $dest -Force
        }
    }

    foreach ($pri in Get-ChildItem $OutputDir -Filter 'Microsoft.*.pri') {
        Copy-Item $pri.FullName (Join-Path $staging $pri.Name) -Force
    }

    $priconfig = Join-Path $staging 'priconfig.xml'
    & $makepri createconfig /cf $priconfig /dq 'en-US' /pv '10.0.0' /o | Out-Null
    $output = & $makepri new /pr $staging /cf $priconfig /in 'ManagedEncryptionEscrow' /of (Join-Path $OutputDir 'resources.pri') /o 2>&1
    if ($LASTEXITCODE -ne 0) { throw "makepri.exe failed (exit $LASTEXITCODE): $output" }
}
finally {
    Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "Published $exe with resources.pri ($($xbfFiles.Count) XAML files)"
