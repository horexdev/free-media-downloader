[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("windows-x64", "windows-arm64")]
    [string]$Target,

    [Parameter(Mandatory = $true)]
    [string]$WorkDir
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$WindowsTar = Join-Path $env:SystemRoot "System32\tar.exe"

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [string]$WorkingDirectory
    )

    if ($WorkingDirectory) {
        Push-Location -LiteralPath $WorkingDirectory
    }
    try {
        & $FilePath @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "$FilePath failed with exit code $LASTEXITCODE"
        }
    }
    finally {
        if ($WorkingDirectory) {
            Pop-Location
        }
    }
}

function Import-MsvcEnvironment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Architecture
    )

    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
        throw "vswhere.exe was not found"
    }
    $toolsetComponent = if ($Architecture -eq "arm64") {
        "Microsoft.VisualStudio.Component.VC.Tools.ARM64"
    }
    else {
        "Microsoft.VisualStudio.Component.VC.Tools.x86.x64"
    }
    $installation = & $vswhere -latest -products * -requires $toolsetComponent -property installationPath
    if (-not $installation) {
        throw "a Visual Studio C++ toolchain was not found"
    }
    $vsdevcmd = Join-Path $installation "Common7\Tools\VsDevCmd.bat"
    if (-not (Test-Path -LiteralPath $vsdevcmd -PathType Leaf)) {
        throw "VsDevCmd.bat was not found"
    }

    $hostArchitecture = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
    $command = "call `"$vsdevcmd`" -no_logo -arch=$Architecture -host_arch=$hostArchitecture >nul && set"
    $environment = & $env:ComSpec /d /s /c $command
    if ($LASTEXITCODE -ne 0) {
        throw "Visual Studio environment setup failed with exit code $LASTEXITCODE"
    }
    foreach ($line in $environment) {
        $separator = $line.IndexOf("=")
        if ($separator -le 0) {
            continue
        }
        $name = $line.Substring(0, $separator)
        $value = $line.Substring($separator + 1)
        Set-Item -LiteralPath "Env:$name" -Value $value
    }
}

function Get-VerifiedSource {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Component,

        [Parameter(Mandatory = $true)]
        [string]$DownloadDirectory,

        [Parameter(Mandatory = $true)]
        [string]$SourceDirectory
    )

    $source = $Component.sourceDistribution
    if (-not $source.url -or -not $source.sha256) {
        throw "$Name has no locked source distribution"
    }
    $uri = [Uri]$source.url
    if ($uri.Scheme -ne "https" -or $uri.Host -notin @("github.com", "objects.githubusercontent.com")) {
        throw "$Name uses a disallowed source URL"
    }

    $archive = Join-Path $DownloadDirectory "$Name.tar"
    Write-Output "Downloading locked $Name source"
    Invoke-Native -FilePath "curl.exe" -Arguments @(
        "--fail",
        "--location",
        "--proto", "=https",
        "--proto-redir", "=https",
        "--max-redirs", "5",
        "--retry", "3",
        "--tlsv1.2",
        "--output", $archive,
        $uri.AbsoluteUri
    )
    $actualHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne ([string]$source.sha256).ToLowerInvariant()) {
        throw "$Name source hash mismatch: $actualHash"
    }

    $entries = & $script:WindowsTar -tf $archive
    if ($LASTEXITCODE -ne 0) {
        throw "unable to inspect $Name source archive"
    }
    foreach ($entry in $entries) {
        if ($entry.StartsWith("/") -or $entry -match "^[A-Za-z]:" -or
            $entry.Contains("\") -or $entry -match "(^|/)\.\.($|/)") {
            throw "$Name source archive contains an unsafe path"
        }
    }

    New-Item -ItemType Directory -Path $SourceDirectory | Out-Null
    Invoke-Native -FilePath $script:WindowsTar -Arguments @(
        "-xf", $archive,
        "--strip-components=1",
        "-C", $SourceDirectory
    )
}

function Invoke-CMakeBuild {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceDirectory,

        [Parameter(Mandatory = $true)]
        [string]$BuildDirectory,

        [Parameter(Mandatory = $true)]
        [string]$Prefix,

        [Parameter(Mandatory = $true)]
        [string[]]$Options
    )

    $configuration = @(
        "-S", $SourceDirectory,
        "-B", $BuildDirectory,
        "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DCMAKE_INSTALL_PREFIX=$Prefix",
        "-DCMAKE_INSTALL_LIBDIR=lib",
        "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL",
        "-DCMAKE_POLICY_DEFAULT_CMP0091=NEW"
    ) + $Options
    $parallelism = if ($env:NUMBER_OF_PROCESSORS -match "^[1-9][0-9]*$") {
        $env:NUMBER_OF_PROCESSORS
    }
    else {
        "2"
    }
    Invoke-Native -FilePath "cmake" -Arguments $configuration
    Invoke-Native -FilePath "cmake" -Arguments @("--build", $BuildDirectory, "--parallel", $parallelism)
    Invoke-Native -FilePath "cmake" -Arguments @("--install", $BuildDirectory)
}

$resolvedWork = [IO.Path]::GetFullPath($WorkDir)
if (Test-Path -LiteralPath $resolvedWork) {
    throw "work directory must not already exist: $resolvedWork"
}

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$lockPath = Join-Path $repositoryRoot "packs\source-lock.json"
$lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
$requiredComponents = @("zlib", "openssl", "nghttp2", "libssh2", "curl")
foreach ($name in $requiredComponents) {
    if (-not $lock.components.$name) {
        throw "source lock is missing $name"
    }
}

$targetConfiguration = switch ($Target) {
    "windows-x64" {
        @{ VsArchitecture = "amd64"; Triplet = "x64-windows-static-md"; OpenSslTarget = "VC-WIN64A" }
    }
    "windows-arm64" {
        @{ VsArchitecture = "arm64"; Triplet = "arm64-windows-static-md"; OpenSslTarget = "VC-WIN64-ARM" }
    }
}

Import-MsvcEnvironment -Architecture $targetConfiguration.VsArchitecture
foreach ($tool in @("cmake", "curl.exe", "ninja", "nmake", "perl")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "required build tool is missing: $tool"
    }
}
if (-not (Test-Path -LiteralPath $WindowsTar -PathType Leaf)) {
    throw "Windows tar.exe was not found"
}
Invoke-Native -FilePath "perl" -Arguments @("-MLocale::Maketext::Simple", "-e", "1")

$downloads = Join-Path $resolvedWork "downloads"
$sources = Join-Path $resolvedWork "sources"
$builds = Join-Path $resolvedWork "build"
$vcpkgRoot = Join-Path $resolvedWork "vcpkg"
$prefix = Join-Path $vcpkgRoot "installed\$($targetConfiguration.Triplet)"
New-Item -ItemType Directory -Path $downloads, $sources, $builds, $prefix | Out-Null
New-Item -ItemType File -Path (Join-Path $vcpkgRoot ".vcpkg-root") | Out-Null

foreach ($name in $requiredComponents) {
    Get-VerifiedSource `
        -Name $name `
        -Component $lock.components.$name `
        -DownloadDirectory $downloads `
        -SourceDirectory (Join-Path $sources $name)
}

Invoke-CMakeBuild `
    -SourceDirectory (Join-Path $sources "zlib") `
    -BuildDirectory (Join-Path $builds "zlib") `
    -Prefix $prefix `
    -Options @(
        "-DZLIB_BUILD_SHARED=OFF",
        "-DZLIB_BUILD_STATIC=ON",
        "-DZLIB_BUILD_TESTING=OFF"
    )

$opensslSource = Join-Path $sources "openssl"
Invoke-Native `
    -FilePath "perl" `
    -Arguments @(
        "Configure",
        $targetConfiguration.OpenSslTarget,
        "no-shared",
        "no-module",
        "no-tests",
        "no-docs",
        "--prefix=$prefix",
        "--openssldir=$(Join-Path $prefix 'ssl')"
    ) `
    -WorkingDirectory $opensslSource
Invoke-Native -FilePath "nmake" -Arguments @("/NOLOGO") -WorkingDirectory $opensslSource
Invoke-Native -FilePath "nmake" -Arguments @("/NOLOGO", "install_sw", "install_ssldirs") -WorkingDirectory $opensslSource

Invoke-CMakeBuild `
    -SourceDirectory (Join-Path $sources "nghttp2") `
    -BuildDirectory (Join-Path $builds "nghttp2") `
    -Prefix $prefix `
    -Options @(
        "-DBUILD_SHARED_LIBS=OFF",
        "-DBUILD_STATIC_LIBS=ON",
        "-DENABLE_LIB_ONLY=ON",
        "-DENABLE_APP=OFF",
        "-DENABLE_EXAMPLES=OFF",
        "-DENABLE_HPACK_TOOLS=OFF",
        "-DENABLE_PYTHON_BINDINGS=OFF",
        "-DBUILD_TESTING=OFF"
    )

Invoke-CMakeBuild `
    -SourceDirectory (Join-Path $sources "libssh2") `
    -BuildDirectory (Join-Path $builds "libssh2") `
    -Prefix $prefix `
    -Options @(
        "-DBUILD_SHARED_LIBS=OFF",
        "-DBUILD_STATIC_LIBS=ON",
        "-DBUILD_EXAMPLES=OFF",
        "-DBUILD_TESTING=OFF",
        "-DCRYPTO_BACKEND=OpenSSL",
        "-DENABLE_ZLIB_COMPRESSION=ON",
        "-DOPENSSL_ROOT_DIR=$prefix",
        "-DOPENSSL_USE_STATIC_LIBS=TRUE",
        "-DZLIB_INCLUDE_DIR=$(Join-Path $prefix 'include')",
        "-DZLIB_LIBRARY=$(Join-Path $prefix 'lib\zs.lib')"
    )

Invoke-CMakeBuild `
    -SourceDirectory (Join-Path $sources "curl") `
    -BuildDirectory (Join-Path $builds "curl") `
    -Prefix $prefix `
    -Options @(
        "-DBUILD_SHARED_LIBS=OFF",
        "-DBUILD_STATIC_LIBS=ON",
        "-DBUILD_CURL_EXE=OFF",
        "-DBUILD_EXAMPLES=OFF",
        "-DBUILD_TESTING=OFF",
        "-DBUILD_LIBCURL_DOCS=OFF",
        "-DBUILD_MISC_DOCS=OFF",
        "-DENABLE_MANUAL=OFF",
        "-DCURL_USE_OPENSSL=ON",
        "-DOPENSSL_ROOT_DIR=$prefix",
        "-DOPENSSL_USE_STATIC_LIBS=TRUE",
        "-DCURL_ZLIB=ON",
        "-DZLIB_INCLUDE_DIR=$(Join-Path $prefix 'include')",
        "-DZLIB_LIBRARY=$(Join-Path $prefix 'lib\zs.lib')",
        "-DCURL_BROTLI=OFF",
        "-DCURL_ZSTD=OFF",
        "-DUSE_LIBIDN2=OFF",
        "-DCURL_USE_LIBPSL=OFF",
        "-DUSE_NGHTTP2=ON",
        "-DNGHTTP2_USE_STATIC_LIBS=ON",
        "-DNGHTTP2_INCLUDE_DIR=$(Join-Path $prefix 'include')",
        "-DNGHTTP2_LIBRARY=$(Join-Path $prefix 'lib\nghttp2.lib')",
        "-DCURL_USE_LIBSSH2=ON",
        "-DLIBSSH2_USE_STATIC_LIBS=ON",
        "-DLIBSSH2_INCLUDE_DIR=$(Join-Path $prefix 'include')",
        "-DLIBSSH2_LIBRARY=$(Join-Path $prefix 'lib\libssh2.lib')",
        "-DCURL_DISABLE_LDAP=ON",
        "-DCURL_DISABLE_RTSP=ON",
        "-DCURL_DISABLE_DICT=ON",
        "-DCURL_DISABLE_TELNET=ON",
        "-DCURL_DISABLE_TFTP=ON",
        "-DCURL_DISABLE_GOPHER=ON",
        "-DCURL_DISABLE_IMAP=ON",
        "-DCURL_DISABLE_POP3=ON",
        "-DCURL_DISABLE_SMTP=ON"
    )

$requiredOutputs = @(
    "include\curl\curl.h",
    "lib\libcurl.lib",
    "lib\libssh2.lib",
    "lib\libssl.lib",
    "lib\libcrypto.lib",
    "lib\nghttp2.lib",
    "lib\zs.lib"
)
foreach ($relativePath in $requiredOutputs) {
    if (-not (Test-Path -LiteralPath (Join-Path $prefix $relativePath) -PathType Leaf)) {
        throw "static curl SDK output is missing: $relativePath"
    }
}

$environmentValues = @(
    "FMD_CURL_STATIC_PREFIX=$prefix",
    "VCPKG_ROOT=$vcpkgRoot",
    "VCPKGRS_TRIPLET=$($targetConfiguration.Triplet)"
)
if ($env:GITHUB_ENV) {
    $environmentValues | Add-Content -LiteralPath $env:GITHUB_ENV -Encoding utf8
}
$environmentValues
