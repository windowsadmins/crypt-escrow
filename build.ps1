# Crypt Build Script
# Builds native Windows binaries for BitLocker key escrow to Crypt Server
# Supports code signing with enterprise certificates (nothing hardcoded - public project)
#
# Usage:
#   .\build.ps1                      # Full build with auto-signing if cert found
#   .\build.ps1 -Sign                # Force signing (fails if no cert)
#   .\build.ps1 -NoSign              # Skip signing entirely
#   .\build.ps1 -Runtime win-x64     # Build only x64
#   .\build.ps1 -Configuration Debug # Debug build

param(
    [switch]$Build = $false,
    [switch]$Sign = $false,
    [switch]$NoSign = $false,
    [switch]$All = $false,
    [string]$Configuration = "Release",
    [string[]]$Runtime = @("win-x64", "win-arm64"),
    [string]$CertificateName,
    [string]$Thumbprint
)

$ErrorActionPreference = 'Stop'

# Default: run build when no flags provided
if (-not ($Build -or $All)) {
    $Build = $true
}

if ($All) {
    $Build = $true
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
    
    # Check CurrentUser store first
    $cert = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue | 
        Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) } |
        Sort-Object NotAfter -Descending | 
        Select-Object -First 1
    
    if ($cert) {
        return @{
            Thumbprint = $cert.Thumbprint
            Store = "CurrentUser"
            Subject = $cert.Subject
        }
    }
    
    # Check LocalMachine store
    $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | 
        Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) } |
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
    
    # Get version for artifact naming
    $version = Get-ProjectVersion -ProjectPath $projectPath
    $timestamp = Get-Date -Format "yyyy.MM.dd.HHmm"
    
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
            $destName = "crypt-$arch.exe"
            $destPath = Join-Path $distDir $destName
            
            Copy-Item $builtExe.FullName $destPath -Force
            $filesToSign.Add($destPath)
            
            Write-Log "Built: $destName ($('{0:N2}' -f ($builtExe.Length / 1MB)) MB)" "SUCCESS"
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

# Summary
Write-Log "Build completed." "SUCCESS"
if (Test-Path $distDir) {
    Write-Log "Artifacts in: $distDir" "INFO"
    Get-ChildItem $distDir -Filter "*.exe" | ForEach-Object {
        $size = '{0:N2}' -f ($_.Length / 1MB)
        Write-Log "  $($_.Name) ($size MB)" "INFO"
    }
}
