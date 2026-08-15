# Sentinel

**Sentinel** is a C and x86-64 Assembly security-research and host-analysis
platform for **authorized** Windows systems.

> ⚠️ **Authorized use only.** Sentinel is intended solely for systems you own or
> have explicit written permission to test. It does not bypass authentication,
> steal credentials, exfiltrate personal data, or destroy files.

---

## Status

| Stage | Description                         | State          |
|-------|-------------------------------------|----------------|
| 1     | Professional GUI shell + navigation | ✅ done        |
| 2     | Real system information             | ✅ done        |
| **3** | Filesystem scanner                  | ✅ **current** |
| 4     | File analysis                       | planned        |
| 5     | PE analyzer                         | planned        |
| 6     | Process analysis                    | planned        |
| 7     | Persistence analysis                | planned        |
| 8     | Security findings engine            | planned        |
| 9     | SQLite database                     | planned        |
| 10    | Reporting (TXT / JSON / HTML)       | planned        |
| 11    | Email reporting                     | planned        |
| 12    | x86-64 Assembly components          | planned        |
| 13    | Advanced binary analysis            | planned        |
| 14    | Lab analysis (isolated)             | planned        |
| 15    | Optional AI analyst                 | planned        |

Stage 1 delivers a custom-drawn, dark "security operations" GUI: header with a
live status indicator, sidebar navigation, a dashboard with severity cards +
host-status + activity feed, and placeholder pages ready for real backends.

Stage 2 wires the **Host Status** panel to real, live data via `src/system/sysinfo.c`
(Win32 host reconnaissance): OS + build, hostname, processor + core/thread count,
architecture, physical memory, CPU load, system-drive space, process count, and
uptime — the dynamic metrics refresh once per second.

Stage 3 makes the **Scan** page functional via `src/scanner/scanner.c`: a
background-threaded recursive filesystem scanner. Pick a folder (Browse), start a
scan, and watch live progress — files/directories/executables/data counters, an
animated progress bar, current directory, and a rolling list of recent files with
type (detected by magic bytes), size, and **SHA-256** (Windows CNG / BCrypt). The
worker thread keeps the UI fully responsive; junctions/symlinks are not followed;
files over 256 MB are recorded but not hashed. Read-only: nothing is modified.

### Getting a prebuilt binary from CI

Every push to `main` triggers `.github/workflows/build.yml`, which builds Sentinel
on a clean Windows runner and uploads `Sentinel.exe` as an artifact. Open the run
under the repo's **Actions** tab and download **Sentinel-windows** — handy when the
local build is blocked by antivirus.

---

## Prerequisites

Already detected on this machine (MSYS2 **UCRT64**, on `PATH`):

- `gcc` / `g++` (GCC 16.2.0)
- `mingw32-make`
- `gdb`

**Required VS Code extension:** [C/C++](https://marketplace.visualstudio.com/items?itemName=ms-vscode.cpptools)
(`ms-vscode.cpptools`) — used by *Run Without Debugging* (Ctrl+F5).

**Optional:** CMake. It is *not* required — the build script falls back to a
direct GCC compile. To use CMake as the primary build system, install it once
in an MSYS2 UCRT64 shell:

```bash
pacman -S mingw-w64-ucrt-x86_64-cmake
```

The build script auto-detects CMake and switches to it with no config changes.

---

## Build & Run

### From VS Code (recommended)

1. Open this folder in VS Code.
2. Press **Ctrl+F5** (*Run → Run Without Debugging*).

This runs the **Build Sentinel** task (`scripts/build.ps1`) and launches
`build/Sentinel.exe`.

### From a terminal

```bash
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1
./build/Sentinel.exe
```

---

## Layout

```
Sentinel/
├── .vscode/            VS Code build/launch/settings (Ctrl+F5 wired up)
├── src/
│   ├── main.c          WinMain + message loop
│   ├── ui.c            custom-drawn Win32 shell (all Stage 1 UI)
│   ├── ui.h            AppState model + UI API
│   ├── theme.h         palette + layout tokens
│   ├── scanner/        (Stage 3)
│   ├── analysis/       (Stage 4-8)
│   ├── binary/         (Stage 5, 13)
│   ├── reporting/      (Stage 10-11)
│   └── database/       (Stage 9)
├── include/            shared public headers (later stages)
├── asm/                x86-64 Assembly (Stage 12+)
├── scripts/build.ps1   CMake-or-GCC build entry point
├── tests/  reports/  data/  docs/  assets/
├── CMakeLists.txt      primary build system
├── README.md
└── LICENSE
```

## Architecture note

Every page renders from a single `AppState` struct (`src/ui.h`). Stage 1 values
are placeholders (zeros / empty), but each is a defined slot — later stages
write real data into `AppState` and repaint. No drawing code needs to change as
backends are added, which keeps the project modular and always compiling.
