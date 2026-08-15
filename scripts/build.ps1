# ============================================================================
#  Sentinel - build.ps1
#  One build entry point used by VS Code (Ctrl+F5 -> preLaunchTask).
#
#  Prefers CMake when it is on PATH; otherwise falls back to compiling the
#  sources directly with GCC. Either way the result is <root>\build\Sentinel.exe
#  so the launch configuration always finds the executable.
# ============================================================================
$ErrorActionPreference = "Stop"

$root  = Split-Path -Parent $PSScriptRoot
$build = Join-Path $root "build"
$exe   = Join-Path $build "Sentinel.exe"

if (-not (Test-Path $build)) {
    New-Item -ItemType Directory -Path $build | Out-Null
}

# A previously launched Sentinel (or an antivirus real-time scan) can hold a
# lock on the output exe, which makes the linker fail with "Permission denied".
# Stop any running instance, then wait until the exe path is writable again.
Get-Process -Name Sentinel -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

if (Test-Path $exe) {
    $freed = $false
    for ($i = 0; $i -lt 10; $i++) {
        try { Remove-Item $exe -Force -ErrorAction Stop; $freed = $true; break }
        catch { Start-Sleep -Milliseconds 250 }
    }
    if (-not $freed) {
        throw "Output file is locked (close any running Sentinel.exe): $exe"
    }
}

$cmake = Get-Command cmake -ErrorAction SilentlyContinue
if ($cmake) {
    Write-Host "[Sentinel] Building with CMake..." -ForegroundColor Cyan
    & cmake -S $root -B $build -G "MinGW Makefiles" `
            -DCMAKE_MAKE_PROGRAM=mingw32-make -DCMAKE_BUILD_TYPE=Debug
    if ($LASTEXITCODE -ne 0) { throw "CMake configure failed ($LASTEXITCODE)" }
    & cmake --build $build
    if ($LASTEXITCODE -ne 0) { throw "CMake build failed ($LASTEXITCODE)" }
}
else {
    Write-Host "[Sentinel] CMake not found - building directly with GCC..." -ForegroundColor Yellow
    $sources = @(
        (Join-Path $root "src\main.c"),
        (Join-Path $root "src\ui.c"),
        (Join-Path $root "src\system\sysinfo.c"),
        (Join-Path $root "src\scanner\scanner.c")
    )
    $gccArgs = @(
        '-std=c11', '-Wall', '-Wextra', '-O2', '-mwindows',
        "-I$root\src", "-I$root\include"
    ) + $sources + @('-o', $exe,
        '-lgdi32', '-luser32', '-ladvapi32', '-lbcrypt', '-lshell32', '-lole32')

    & gcc @gccArgs
    if ($LASTEXITCODE -ne 0) { throw "GCC build failed ($LASTEXITCODE)" }
}

Write-Host "[Sentinel] Build succeeded -> $exe" -ForegroundColor Green
