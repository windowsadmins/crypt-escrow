# Crypt Build Script
# Builds native Windows binaries for BitLocker key escrow to Crypt Server
# Supports code signing with enterprise certificates (nothing hardcoded - public project)
#
# Usage:
#   .\build.ps1                           # Full build with all packages
#   .\build.ps1 -Sign                     # Force signing (fails if no cert)
#   .\build.ps1 -NoSign                   # Skip signing entirely
#   .\build.ps1 -Package                  # Build and create deployment packages
#   .\build.ps1 -Msi                      # Build only MSI packages
#   .\build.ps1 -Nupkg                    # Build only NuGet packages
#   .\build.ps1 -Pkg                      # Build only .pkg packages
#   .\build.ps1 -Deploy -CryptServer url  # Build, package, and create deployment files
#   .\build.ps1 -Runtime win-x64          # Build only x64
#   .\build.ps1 -Configuration Debug      # Debug build

param(
    [switch]$Build = $false,
    [switch]$Sign = $false,
    [switch]$NoSign = $false,
    [switch]$Package = $false,
    [switch]$Deploy = $false,
    [switch]$Msi = $false,
    [switch]$Nupkg = $false,
    [switch]$Pkg = $false,
    [string]$Configuration = "Release",
    [string[]]$Runtime = @("win-x64", "win-arm64"),
    [string]$CertificateName,
    [string]$Thumbprint,
    [string]$CryptServer
)

$ErrorActionPreference = 'Stop'

# Default: run full build with all packages when no flags provided
if (-not ($Build -or $Package -or $Deploy -or $Msi -or $Nupkg -or $Pkg)) {
    $Build = $true
    $Msi = $true
    $Nupkg = $true
    $Pkg = $true
}

if ($Package -or $Deploy) {
    $Build = $true
    $Msi = $true
    $Nupkg = $true
    $Pkg = $true
}

if ($Deploy -and [string]::IsNullOrWhiteSpace($CryptServer)) {
    Write-Host "ERROR: -CryptServer parameter is required when using -Deploy" -ForegroundColor Red
    Write-Host "Example: .\build.ps1 -Deploy -CryptServer https://crypt.ecuad.ca" -ForegroundColor Yellow
    exit 1
}

$rootPath = $PSScriptRoot
$projectPath = Join-Path $rootPath "src\CryptEscrow\CryptEscrow.csproj"
$distDir = Join-Path $rootPath "dist"
$filesToSign = New-Object System.Collections.Generic.List[string]

$script:SignToolPath = $null
$script:SignToolChecked = $false
$script:SignToolWarned = $false

function Write-Log {
    param (
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    switch ($Level) {
        "INFO"    { Write-Host "[$timestamp] [INFO] $Message" -ForegroundColor Cyan }
        "SUCCESS" { Write-Host "[$timestamp] [SUCCESS] $Message" -ForegroundColor Green }
        "WARNING" { Write-Host "[$timestamp] [WARNING] $Message" -ForegroundColor Yellow }
        "ERROR"   { Write-Host "[$timestamp] [ERROR] $Message" -ForegroundColor Red }
    }
}

function Get-SigningCertThumbprint {
    [OutputType([hashtable])]
    param()
    
    # Check CurrentUser store first for enterprise certificate
    $cert = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue | 
        Where-Object { $_.HasPrivateKey -and $_.Subject -like '*EmilyCarrU*' -and $_.NotAfter -gt (Get-Date) } |
        Sort-Object NotAfter -Descending | 
        Select-Object -First 1
    
    if ($cert) {
        return @{
            Thumbprint = $cert.Thumbprint
            Store = "CurrentUser"
            Subject = $cert.Subject
        }
    }
    
    # Check LocalMachine store for enterprise certificate
    $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | 
        Where-Object { $_.HasPrivateKey -and $_.Subject -like '*EmilyCarrU*' -and $_.NotAfter -gt (Get-Date) } |
        Sort-Object NotAfter -Descending | 
        Select-Object -First 1
    
    if ($cert) {
        return @{
            Thumbprint = $cert.Thumbprint
            Store = "LocalMachine"
            Subject = $cert.Subject
        }
    }
    
    return $null
}

function Resolve-SignToolPath {
    if ($script:SignToolChecked) {
        return $script:SignToolPath
    }

    $script:SignToolChecked = $true

    $candidates = New-Object System.Collections.Generic.List[string]

    $commandLookup = Get-Command "signtool.exe" -ErrorAction SilentlyContinue
    if ($commandLookup) {
        $candidates.Add($commandLookup.Source) | Out-Null
    }

    foreach ($envVar in @("SIGNTOOL_PATH", "SIGNTOOL")) {
        $value = [Environment]::GetEnvironmentVariable($envVar)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            if (Test-Path $value -PathType Leaf) {
                $candidates.Add((Resolve-Path $value).Path) | Out-Null
            } elseif (Test-Path $value -PathType Container) {
                $exeCandidate = Join-Path $value "signtool.exe"
                if (Test-Path $exeCandidate) {
                    $candidates.Add((Resolve-Path $exeCandidate).Path) | Out-Null
                }
            }
        }
    }

    $kitRoots = @()
    if ($env:ProgramFiles) {
        $kitRoots += Join-Path $env:ProgramFiles "Windows Kits\10\bin"
    }
    if (${env:ProgramFiles(x86)}) {
        $kitRoots += Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    }

    foreach ($kitRoot in $kitRoots | Where-Object { Test-Path $_ }) {
        $versions = Get-ChildItem -Path $kitRoot -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending
        foreach ($versionDir in $versions) {
            foreach ($arch in @("x64", "arm64", "x86")) {
                $exePath = Join-Path $versionDir.FullName "$arch\signtool.exe"
                if (Test-Path $exePath) {
                    $candidates.Add((Resolve-Path $exePath).Path) | Out-Null
                }
            }
        }
    }

    if ($candidates.Count -gt 0) {
        $script:SignToolPath = $candidates | Select-Object -First 1
    }

    return $script:SignToolPath
}

function Invoke-CodeSign {
    param(
        [Parameter(Mandatory)][string]$TargetFile,
        [string]$CertName,
        [string]$CertThumbprint,
        [int]$MaxAttempts = 4
    )

    $resolvedPath = Resolve-SignToolPath
    if (-not $resolvedPath) {
        if (-not $script:SignToolWarned) {
            Write-Log "Skipping signing: signtool.exe not found. Install Windows SDK or set SIGNTOOL_PATH." "WARNING"
            $script:SignToolWarned = $true
        }
        Write-Log "Skipping: $TargetFile" "WARNING"
        return $false
    }

    if (-not (Test-Path $TargetFile)) {
        Write-Log "File not found for signing: $TargetFile" "WARNING"
        return $false
    }

    # Check if file is locked
    try {
        $fileStream = [System.IO.File]::Open($TargetFile, 'Open', 'Read', 'None')
        $fileStream.Close()
    }
    catch {
        Write-Log "File locked: $TargetFile. Waiting..." "WARNING"
        Start-Sleep -Seconds 3
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }

    # Multiple timestamp servers for redundancy
    $tsas = @(
        'http://timestamp.digicert.com',
        'http://timestamp.sectigo.com',
        'http://timestamp.entrust.net/TSS/RFC3161sha2TS'
    )

    $attempt = 0
    $signed = $false
    
    while ($attempt -lt $MaxAttempts -and -not $signed) {
        $attempt++
        foreach ($tsa in $tsas) {
            try {
                $signArgs = @("sign", "/fd", "SHA256", "/tr", $tsa, "/td", "SHA256")
                
                if ($CertThumbprint) {
                    $signArgs += @("/sha1", $CertThumbprint)
                } elseif ($CertName) {
                    $signArgs += @("/n", $CertName)
                } else {
                    # Auto-select from store
                    $signArgs += "/a"
                }
                
                $signArgs += $TargetFile
                
                & $resolvedPath @signArgs 2>&1 | Out-Null
                
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "Signed: $TargetFile" "SUCCESS"
                    $signed = $true
                    break
                }
            }
            catch {
                # Continue to next TSA
            }
            
            if (-not $signed) {
                Start-Sleep -Seconds (2 * $attempt)
            }
        }
    }

    if (-not $signed) {
        Write-Log "Failed to sign after $MaxAttempts attempts: $TargetFile" "WARNING"
        return $false
    }
    
    return $true
}

function Get-ProjectVersion {
    param([string]$ProjectPath)
    $fallback = "1.0.0"
    try {
        [xml]$proj = Get-Content $ProjectPath -ErrorAction Stop
        $versionNode = $proj.Project.PropertyGroup | Where-Object { $_.Version } | Select-Object -First 1
        if ($versionNode -and $versionNode.Version) {
            return $versionNode.Version
        }
    } catch {
        Write-Log "Could not determine project version. Using $fallback." "WARNING"
    }
    return $fallback
}

function Find-WiXBinPath {
    # Check for WiX v6 (.NET tool)
    try {
        $dotnetWixVersion = & dotnet tool list --global 2>$null | Select-String "^wix\s"
        if ($dotnetWixVersion) {
            Write-Log "Found WiX v6 as .NET global tool" "SUCCESS"
            return "dotnet-tool"
        }
    } catch {}
    
    # Fallback to WiX v3
    $possiblePaths = @(
        "C:\Program Files (x86)\WiX Toolset*\bin\candle.exe",
        "C:\Program Files\WiX Toolset*\bin\candle.exe"
    )
    foreach ($path in $possiblePaths) {
        $found = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
        if ($null -ne $found) {
            return $found[0].Directory.FullName
        }
    }
    return $null
}

function Test-Command {
    param([string]$Command)
    return $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
}

function signNuget {
    param(
        [Parameter(Mandatory)][string]$Nupkg,
        [string]$Thumbprint
    )
    if (-not (Test-Path $Nupkg)) {
        throw "NuGet package '$Nupkg' not found - cannot sign."
    }
    $tsa = 'http://timestamp.digicert.com'
    if (-not $Thumbprint) {
        $certInfo = Get-SigningCertThumbprint
        $Thumbprint = if ($certInfo) { $certInfo.Thumbprint } else { $null }
    }
    if (-not $Thumbprint) {
        Write-Log "No enterprise code-signing cert present - skipping NuGet sign." "WARNING"
        return $false
    }
    & nuget.exe sign `
        $Nupkg `
        -CertificateStoreName My `
        -CertificateSubjectName 'EmilyCarrU Intune Windows Enterprise Certificate' `
        -Timestamper $tsa
    if ($LASTEXITCODE) {
        Write-Log "nuget sign failed ($LASTEXITCODE) for '$Nupkg' - continuing build" "WARNING"
        return $false
    }
    Write-Log "NuGet package signed." "SUCCESS"
    return $true
}

# Signing decision
$autoDetectedCert = $null
if (-not $Sign -and -not $NoSign) {
    try {
        $certInfo = Get-SigningCertThumbprint
        if ($certInfo) {
            $autoDetectedCert = $certInfo
            Write-Log "Auto-detected certificate: $($certInfo.Subject) in $($certInfo.Store) store" "INFO"
            $Sign = $true
            if (-not $Thumbprint) {
                $Thumbprint = $certInfo.Thumbprint
            }
        } else {
            Write-Log "No code signing certificate found - binaries will be unsigned." "WARNING"
        }
    }
    catch {
        Write-Log "Could not check for certificates: $_" "WARNING"
    }
}

if ($NoSign) {
    Write-Log "NoSign parameter specified - skipping all signing." "INFO"
    $Sign = $false
}

if ($Sign -and -not (Resolve-SignToolPath)) {
    Write-Log "Signing requested but signtool.exe not found. Install Windows SDK." "ERROR"
    exit 1
}

# Build
if ($Build) {
    Write-Log "Building Crypt ($Configuration)..." "INFO"
    
    # Verify dotnet is available
    if (-not (Get-Command "dotnet" -ErrorAction SilentlyContinue)) {
        Write-Log ".NET SDK not found. Install from https://dotnet.microsoft.com/download" "ERROR"
        exit 1
    }
    
    # Create dist directory
    if (-not (Test-Path $distDir)) {
        New-Item -ItemType Directory -Path $distDir -Force | Out-Null
    }
    
    # Get version for artifact naming and assembly version
    $timestamp = Get-Date -Format "yyyy.MM.dd.HHmm"
    $version = $timestamp
    
    foreach ($rid in $Runtime) {
        Write-Log "Publishing for $rid..." "INFO"
        
        $publishDir = Join-Path $rootPath "src\CryptEscrow\bin\$Configuration\net10.0-windows\$rid\publish"
        
        # Publish
        & dotnet publish $projectPath `
            -c $Configuration `
            -r $rid `
            --self-contained `
            -p:PublishSingleFile=true `
            -p:PublishTrimmed=true `
            -p:TrimMode=partial `
            -p:Version=$version
        
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Failed to publish for $rid" "ERROR"
            exit 1
        }
        
        # Find and copy the built executable
        $builtExe = Get-ChildItem -Path $publishDir -Filter "crypt.exe" -ErrorAction SilentlyContinue
        if ($builtExe) {
            $arch = if ($rid -match 'x64') { 'x64' } elseif ($rid -match 'arm64') { 'arm64' } else { $rid }
            $archDir = Join-Path $distDir $arch
            if (-not (Test-Path $archDir)) {
                New-Item -ItemType Directory -Path $archDir -Force | Out-Null
            }
            $destPath = Join-Path $archDir "crypt.exe"
            
            Copy-Item $builtExe.FullName $destPath -Force
            $filesToSign.Add($destPath)
            
            Write-Log "Built: $arch\crypt.exe ($('{0:N2}' -f ($builtExe.Length / 1MB)) MB)" "SUCCESS"
        } else {
            Write-Log "Could not find crypt.exe in publish output for $rid" "ERROR"
            exit 1
        }
    }
    
    # Force garbage collection before signing
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    Start-Sleep -Seconds 2
}

# Sign
if ($Sign -and $filesToSign.Count -gt 0) {
    Write-Log "Signing artifacts..." "INFO"
    
    foreach ($file in $filesToSign | Sort-Object -Unique) {
        Write-Log "Signing: $(Split-Path $file -Leaf)" "INFO"
        Invoke-CodeSign -TargetFile $file -CertThumbprint $Thumbprint -CertName $CertificateName
    }
} elseif ($Sign) {
    Write-Log "Sign flag specified but no files to sign." "WARNING"
}

# Ensure release directory for packages
$releaseDir = Join-Path $rootPath "release"
if (-not (Test-Path $releaseDir)) {
    New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null
}

# MSI Package
if ($Msi) {
    Write-Log "Building MSI packages with WiX for x64 and arm64..." "INFO"
    
    # Check for WiX
    $wixBinPath = Find-WiXBinPath
    if (-not $wixBinPath) {
        Write-Log "WiX Toolset not found. Install with: dotnet tool install --global wix" "ERROR"
        exit 1
    }
    
    $useWixV6 = ($wixBinPath -eq "dotnet-tool")
    $timestamp = Get-Date -Format "yyyy.MM.dd.HHmm"
    $semanticVersion = Get-ProjectVersion -ProjectPath $projectPath
    
    $msiArchs = @("x64", "arm64")
    foreach ($msiArch in $msiArchs) {
        $msiTempDir = "release\msi_$msiArch"
        if (Test-Path $msiTempDir) { Remove-Item -Path "$msiTempDir\*" -Recurse -Force }
        else { New-Item -ItemType Directory -Path $msiTempDir | Out-Null }
        
        # Copy binaries for this arch
        Write-Log "Preparing $msiArch binaries for MSI..." "INFO"
        Get-ChildItem -Path "dist\$msiArch\*.exe" | ForEach-Object {
            Copy-Item $_.FullName $msiTempDir -Force
        }
        
        # Build MSI
        $msiOutput = "release\Crypt-$msiArch-$timestamp.msi"
        
        try {
            if ($useWixV6) {
                Write-Log "Building MSI with WiX v6 for $msiArch..." "INFO"
                $wixProjPath = "build\msi\Crypt.wixproj"
                $fullMsiTempDir = Join-Path $rootPath $msiTempDir
                
                $buildArgs = @(
                    "build"
                    $wixProjPath
                    "-p:Platform=$msiArch"
                    "-p:ProductVersion=$semanticVersion"
                    "-p:BinDir=$fullMsiTempDir"
                    "-p:OutputName=Crypt-$msiArch"
                    "--configuration", "Release"
                    "--nologo"
                    "--verbosity", "minimal"
                )
                
                & dotnet @buildArgs
                if ($LASTEXITCODE -ne 0) {
                    throw "WiX v6 build failed for $msiArch"
                }
                
                # Find output MSI
                $builtMsi = "build\msi\bin\$msiArch\Release\Crypt-$msiArch.msi"
                if (Test-Path $builtMsi) {
                    Move-Item $builtMsi $msiOutput -Force
                } else {
                    throw "MSI output not found at $builtMsi"
                }
            }
            
            Write-Log "MSI package created: $msiOutput" "SUCCESS"
            
            # Sign MSI if signing enabled
            if ($Sign) {
                Write-Log "Signing MSI: $(Split-Path $msiOutput -Leaf)" "INFO"
                Invoke-CodeSign -TargetFile $msiOutput -CertThumbprint $Thumbprint -CertName $CertificateName
            }
            
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            Start-Sleep -Seconds 2
        }
        catch {
            $errorMsg = "Failed to build MSI for ${msiArch}: $($_.Exception.Message)"
            Write-Log $errorMsg "ERROR"
            exit 1
        }
        finally {
            Remove-Item -Path "$msiTempDir\*" -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# NuGet Package
if ($Nupkg) {
    Write-Log "Preparing NuGet packages for x64 and arm64..." "INFO"
    
    $timestamp = Get-Date -Format "yyyy.MM.dd.HHmm"
    $semanticVersion = Get-ProjectVersion -ProjectPath $projectPath
    
    $archs = @("x64", "arm64")
    foreach ($arch in $archs) {
        $nuspecPath = "build\nupkg\Crypt-$arch.nuspec"
        $nupkgOut = "release\Crypt-$arch-$timestamp.nupkg"
        
        if (-not (Test-Path $nuspecPath)) {
            Write-Log "Nuspec not found: $nuspecPath" "ERROR"
            continue
        }
        
        # Create temporary directory for NuGet package structure
        $nupkgTempDir = "release\nupkg_$arch"
        if (Test-Path $nupkgTempDir) { Remove-Item $nupkgTempDir -Recurse -Force }
        New-Item -ItemType Directory -Path $nupkgTempDir -Force | Out-Null
        
        $toolsDir = Join-Path $nupkgTempDir "tools"
        New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
        
        # Copy binary to tools directory
        $cryptExe = Join-Path $distDir "$arch\crypt.exe"
        if (Test-Path $cryptExe) {
            Copy-Item $cryptExe $toolsDir -Force
        }
        
        # Replace version in nuspec
        $nuspecContent = Get-Content $nuspecPath -Raw
        $nuspecWithVersion = $nuspecContent -replace '\{\{VERSION\}\}', $semanticVersion
        $tempNuspecPath = Join-Path $nupkgTempDir "Crypt-$arch.nuspec"
        $nuspecWithVersion | Set-Content $tempNuspecPath -Encoding UTF8
        
        # Create nupkg as ZIP
        $zipPath = "$nupkgOut.zip"
        Compress-Archive -Path (Join-Path $nupkgTempDir '*') -DestinationPath $zipPath -Force
        
        # Rename to .nupkg
        if (Test-Path $nupkgOut) { Remove-Item $nupkgOut -Force }
        Move-Item $zipPath $nupkgOut -Force
        
        Write-Log "$arch NuGet package created: $nupkgOut" "SUCCESS"
        
        # Note: NuGet package signing requires nuget.exe
        # if ($Sign) {
        #     signNuget $nupkgOut -Thumbprint $Thumbprint
        # }
        
        Remove-Item $nupkgTempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# .pkg Package (Cimian-Pkg format)
if ($Pkg) {
    Write-Log "Creating .pkg packages for x64 and arm64..." "INFO"
    
    $timestamp = Get-Date -Format "yyyy.MM.dd.HHmm"
    $pkgsDir = Join-Path $rootPath "release"
    
    $archs = @("x64", "arm64")
    foreach ($arch in $archs) {
        $archDir = Join-Path $distDir $arch
        $cryptExe = Join-Path $archDir "crypt.exe"
        
        if (-not (Test-Path $cryptExe)) {
            Write-Log "Binary not found: $cryptExe - skipping .pkg" "WARNING"
            continue
        }
        
        $pkgTempDir = "release\pkg_$arch"
        if (Test-Path $pkgTempDir) { Remove-Item $pkgTempDir -Recurse -Force }
        New-Item -ItemType Directory -Path $pkgTempDir -Force | Out-Null
        
        # Create payload
        $payloadDir = Join-Path $pkgTempDir "payload"
        New-Item -ItemType Directory -Path $payloadDir -Force | Out-Null
        Copy-Item $cryptExe -Destination $payloadDir -Force
        
        # Create scripts
        $scriptsDir = Join-Path $pkgTempDir "scripts"
        New-Item -ItemType Directory -Path $scriptsDir -Force | Out-Null
        
        $postinstallTemplate = Get-Content "build\pkg\postinstall.ps1" -Raw
        $postinstallContent = $postinstallTemplate -replace '\{\{VERSION\}\}', $timestamp
        $postinstallContent | Set-Content (Join-Path $scriptsDir "postinstall.ps1") -Encoding UTF8
        
        $preinstallTemplate = Get-Content "build\pkg\preinstall.ps1" -Raw
        $preinstallContent = $preinstallTemplate -replace '\{\{VERSION\}\}', $timestamp
        $preinstallContent | Set-Content (Join-Path $scriptsDir "preinstall.ps1") -Encoding UTF8
        
        # Create build-info.yaml
        $buildInfoTemplate = Get-Content "build\pkg\build-info.yaml" -Raw
        $buildInfoContent = $buildInfoTemplate -replace '\{\{VERSION\}\}', $timestamp
        $buildInfoContent = $buildInfoContent -replace '\{\{ARCHITECTURE\}\}', $arch
        $buildInfoContent | Set-Content (Join-Path $pkgTempDir "build-info.yaml") -Encoding UTF8
        
        # Create .pkg as ZIP
        $pkgName = "Crypt-$arch-$timestamp.pkg"
        $pkgPath = Join-Path $pkgsDir $pkgName
        if (Test-Path $pkgPath) { Remove-Item $pkgPath -Force }
        Compress-Archive -Path (Join-Path $pkgTempDir '*') -DestinationPath $pkgPath -Force
        
        $pkgSize = (Get-Item $pkgPath).Length
        Write-Log "Created: $pkgName ($('{0:N2}' -f ($pkgSize / 1MB)) MB)" "SUCCESS"
        
        Remove-Item $pkgTempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Deploy
if ($Deploy) {
    Write-Log "Creating Cimian deployment manifests..." "INFO"
    $version = Get-ProjectVersion -ProjectPath $projectPath
    $timestamp = Get-Date -Format "yyyy.MM.dd.HHmm"
    $deployDir = Join-Path $rootPath "deploy"
    $releaseDir = Join-Path $rootPath "release"
    
    if (-not (Test-Path $deployDir)) {
        New-Item -ItemType Directory -Path $deployDir -Force | Out-Null
    }
    
    $archs = @("x64", "arm64")
    foreach ($arch in $archs) {
        $pkgName = "Crypt-$arch-$timestamp.pkg"
        $pkgPath = Join-Path $releaseDir $pkgName
        
        if (-not (Test-Path $pkgPath)) {
            Write-Log "Package not found: $pkgPath - skipping deployment manifest" "WARNING"
            continue
        }
        
        $pkgSize = (Get-Item $pkgPath).Length
        $pkgHash = (Get-FileHash $pkgPath -Algorithm SHA256).Hash.ToLower()
        $cryptExe = Join-Path $distDir "$arch\crypt.exe"
        $cryptHash = if (Test-Path $cryptExe) { (Get-FileHash $cryptExe -Algorithm MD5).Hash.ToLower() } else { "" }
        
        $pkginfoPath = Join-Path $deployDir "Crypt-$arch-$timestamp.yaml"
        
        $pkginfo = @"
name: Crypt
display_name: Crypt - BitLocker Key Escrow
version: $timestamp
description: BitLocker recovery key escrow to Crypt Server with key rotation support
category: Security
developer: Windows Admins Community
catalogs:
  - Testing
  - Production
supported_architectures:
  - $arch
unattended_install: true
unattended_uninstall: false
installer:
  type: pkg
  size: $pkgSize
  location: /security/Crypt-$arch-$timestamp.pkg
  hash: $pkgHash
installs:
  - type: file
    path: 'C:\Program Files\Crypt\crypt.exe'
    md5checksum: '$cryptHash'
    version: '$timestamp'
preinstall_script: |
  # Set Crypt Server URL before installation
  [Environment]::SetEnvironmentVariable('CRYPT_ESCROW_SERVER_URL', '$CryptServer', 'Machine')
  Write-Host "Configured Crypt Server: $CryptServer" -ForegroundColor Green
postinstall_script: |
  # Register daily scheduled task for automatic key rotation
  & 'C:\Program Files\Crypt\crypt.exe' register-task --frequency daily
  Write-Host "Registered Crypt daily task" -ForegroundColor Green
"@
        Set-Content -Path $pkginfoPath -Value $pkginfo -Encoding UTF8
        Write-Log "Created: $(Split-Path $pkginfoPath -Leaf)" "SUCCESS"
    }
    
    # Create deployment instructions
    $readmePath = Join-Path $deployDir "DEPLOYMENT.md"
    $readme = @"
# Crypt Deployment Guide

## Quick Start

1. **Copy packages to Cimian repo:**
   ``````powershell
   # Copy .pkg files
   Copy-Item pkgs\Crypt-*.pkg ..\..\deployment\pkgs\security\
   
   # Copy pkgsinfo manifests
   Copy-Item deploy\Crypt-*.yaml ..\..\deployment\pkgsinfo\security\
   ``````

2. **Configure Crypt Server URL:**
   The pkgsinfo files are pre-configured with: ``$CryptServer``
   Edit the yaml files if you need to change this.

3. **Deploy via Intune/Configuration Manager:**
   - Add to catalog: ``Testing`` first, then ``Production``
   - Devices will auto-install on next Cimian sync
   - Task will run daily to rotate and escrow keys

## Manual Testing

Test on a BitLocker-enabled device:

``````powershell
# Test escrow
crypt escrow --server $CryptServer

# Test verification
crypt verify --server $CryptServer

# Test rotation
crypt rotate --server $CryptServer

# View config
crypt config show

# Register scheduled task
crypt register-task --frequency daily
``````

## Architecture Support

- **x64**: Standard Intel/AMD 64-bit systems
- **arm64**: ARM64-based Surface devices and VMs

## Configuration Options

Set via config file (``C:\ProgramData\ManagedEncryption\config.yaml``), registry (CSP/OMA-URI), or environment variables:

- ``CRYPT_ESCROW_SERVER_URL``: Crypt server URL
- ``CRYPT_KEY_ESCROW_INTERVAL``: Hours between rotations (default: 24)
- ``CRYPT_VALIDATE_KEY``: Verify key after escrow (true/false)
- ``CRYPT_SKIP_USERS``: Skip escrow for specific users (comma-separated)
- ``CRYPT_POST_RUN_COMMAND``: Command to run after escrow

## Monitoring

Logs are written to: ``C:\ProgramData\ManagedEncryption\logs\crypt.log``

Check scheduled task: ``Get-ScheduledTask -TaskName "Crypt BitLocker Key Rotation"``

## Crypt Server Requirements

- Crypt Server 3.x or later (https://github.com/grahamgilbert/Crypt-Server)
- TLS certificate (or use ``--skip-cert-check`` for testing)
- API endpoint accessible from managed devices

## Troubleshooting

``````powershell
# Check if BitLocker is enabled
Get-BitLockerVolume -MountPoint C:

# View current recovery keys
(Get-BitLockerVolume -MountPoint C:).KeyProtector

# Test connectivity
Test-NetConnection crypt.ecuad.ca -Port 443

# Run with verbose logging
`$env:CRYPT_LOG_LEVEL = 'Debug'
crypt escrow --server $CryptServer
``````

## Deployment Timeline

1. **Week 1**: Deploy to Testing catalog (pilot devices)
2. **Week 2**: Monitor and validate escrow in Crypt Server
3. **Week 3**: Promote to Production catalog (full fleet)
4. **Week 4**: Verify 100% fleet coverage

Built: $timestamp
"@
    Set-Content -Path $readmePath -Value $readme -Encoding UTF8
    Write-Log "Created: DEPLOYMENT.md" "SUCCESS"
}

# Summary
Write-Log "Build completed." "SUCCESS"
if (Test-Path $distDir) {
    Write-Log "Artifacts in: $distDir" "INFO"
    Get-ChildItem $distDir -Filter "*.exe" | ForEach-Object {
        $size = '{0:N2}' -f ($_.Length / 1MB)
        Write-Log "  $($_.Name) ($size MB)" "INFO"
    }
}
