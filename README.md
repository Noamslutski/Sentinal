# Sentinel

## Security Research & Host Analysis Platform

Sentinel is a C-based security research platform designed to analyze and assess the security posture of authorized Windows systems.

The project combines:

* C programming
* x86-64 Assembly
* Windows APIs
* PE binary analysis
* filesystem analysis
* process analysis
* cryptographic hashing
* vulnerability detection
* behavioral analysis
* security scoring
* automated reporting

The long-term goal is to create a powerful **host security analysis and reverse-engineering platform** capable of collecting evidence, correlating findings, and producing detailed security reports.

> **Important:** Sentinel is intended for systems you own or have explicit authorization to assess. It is not designed to bypass authentication, obtain unauthorized access, steal information, or secretly exfiltrate files.

---

## Project Goals

Sentinel will progressively evolve from a simple filesystem scanner into a complete host-security research platform.

### Core objectives

* Recursively analyze authorized filesystems
* Identify file types using signatures rather than extensions
* Calculate cryptographic hashes
* Analyze Windows PE executables
* Inspect executable sections
* Calculate entropy
* Enumerate running processes
* Analyze process metadata
* Inspect persistence mechanisms
* Detect suspicious configurations
* Maintain a local security database
* Assign risk scores to findings
* Generate JSON, TXT, and HTML reports
* Send authenticated security reports by email
* Provide low-level analysis using x86-64 Assembly
* Eventually support dynamic behavioral analysis

---

# Architecture

```text
                         SENTINEL
                            │
                ┌───────────┴───────────┐
                │                       │
          Collection Layer        Analysis Layer
                │                       │
        ┌───────┼────────┐      ┌───────┼────────┐
        ↓       ↓        ↓      ↓       ↓        ↓
    Filesystem Processes Network   PE    Hash   Entropy
        │       │        │      │       │        │
        └───────┴────────┴──────┴───────┴────────┘
                            │
                            ↓
                     Risk Engine
                            │
                            ↓
                     Report Engine
                            │
                  ┌─────────┴─────────┐
                  ↓                   ↓
              Local Report        Email Report
```

---

# Technology Stack

## Primary language

**C**

C is used for the main application and system-level functionality.

## Low-level components

**x86-64 Assembly**

Assembly will be introduced where low-level CPU interaction, performance analysis, or architecture-specific functionality is useful.

## Operating system

**Windows 10/11**

The initial implementation targets Windows.

## Compiler

**GCC / MinGW-w64**

## Development environment

**Visual Studio Code**

## Build system

**CMake**

## Database

**SQLite**

## Optional technologies

* Python for auxiliary tooling
* HTML/CSS for reports
* JSON for machine-readable output
* Git for version control

---

# Project Structure

The project will eventually follow this structure:

```text
Sentinel/
│
├── CMakeLists.txt
├── README.md
├── LICENSE
│
├── src/
│   ├── main.c
│   │
│   ├── scanner/
│   │   ├── filesystem.c
│   │   ├── processes.c
│   │   ├── services.c
│   │   └── network.c
│   │
│   ├── analysis/
│   │   ├── hash.c
│   │   ├── entropy.c
│   │   ├── signatures.c
│   │   └── risk.c
│   │
│   ├── binary/
│   │   ├── pe.c
│   │   ├── disassembler.c
│   │   └── imports.c
│   │
│   ├── reporting/
│   │   ├── report.c
│   │   ├── json.c
│   │   └── email.c
│   │
│   └── database/
│       └── database.c
│
├── include/
│   ├── scanner/
│   ├── analysis/
│   ├── binary/
│   ├── reporting/
│   └── database/
│
├── asm/
│   ├── cpu.asm
│   └── lowlevel.asm
│
├── tests/
│
├── reports/
│
├── data/
│
└── docs/
```

The initial version will be much smaller and will grow into this structure gradually.

---

# Development Roadmap

## Phase 1 — Foundation

* [ ] Create CMake project
* [ ] Create application entry point
* [ ] Implement command-line interface
* [ ] Implement logging system
* [ ] Implement configuration system

Example:

```text
sentinel.exe --help

sentinel.exe scan <path>

sentinel.exe analyze <file>

sentinel.exe report
```

---

## Phase 2 — Filesystem Scanner

Implement recursive filesystem analysis.

For each authorized file:

```text
Path
Filename
Size
Extension
Creation time
Modification time
Attributes
File signature
```

Example:

```text
[FILE] program.exe
Size: 184320 bytes
Type: PE32+
SHA-256: ...
```

---

## Phase 3 — Cryptographic Analysis

Implement hashing.

Initial target:

```text
SHA-256
```

Store:

```text
Path
Size
Hash
Timestamp
```

This allows Sentinel to detect changes between scans.

---

## Phase 4 — PE Analysis

Implement a Windows PE parser.

Analyze:

```text
DOS Header
PE Header
COFF Header
Optional Header
Section Headers
Import Directory
Export Directory
Resource Directory
```

Example output:

```text
PE ANALYSIS
───────────

Architecture: x86-64
Entry Point: 0x140001530
Sections: 7

.text
Virtual Size: ...
Permissions: RX
Entropy: ...

.rdata
Permissions: R

.data
Permissions: RW
```

---

## Phase 5 — Static Security Analysis

Analyze executables for suspicious characteristics.

Potential indicators include:

* unusual section permissions
* executable/writable regions
* unusual section names
* high-entropy sections
* suspicious imports
* malformed PE structures
* unusual entry points
* embedded executable data

Individual indicators should not automatically be classified as malware.

Sentinel should instead combine evidence.

---

# Phase 6 — Process Analysis

Enumerate running processes.

Collect information such as:

```text
PID
Process name
Executable path
Parent process
Architecture
Loaded modules
```

Example:

```text
PID      NAME
--------------------------
1204     explorer.exe
2480     chrome.exe
4216     sentinel.exe
```

---

# Phase 7 — Persistence Analysis

Inspect authorized Windows persistence mechanisms such as:

```text
Startup applications
Services
Scheduled tasks
Registry Run / RunOnce locations
```

Report unexpected or suspicious entries.

---

# Phase 8 — Risk Engine

Sentinel will assign findings a risk score based on multiple indicators.

Example:

```text
Unknown executable          +20
Unusual location            +10
High entropy                +15
Suspicious imports          +20
Executable + writable       +25
Known malicious hash        +100
```

Example result:

```text
Risk Score: 72 / 100

Severity: HIGH
```

The scoring system will be configurable rather than hard-coded.

---

# Phase 9 — Database

Use SQLite to store scan history.

Possible schema:

```text
files
─────
id
path
size
sha256
first_seen
last_seen

findings
────────
id
file_id
severity
category
description
timestamp

processes
─────────
id
pid
name
path
timestamp
```

This allows Sentinel to answer questions such as:

> What changed since yesterday?

---

# Phase 10 — Reporting

Generate:

```text
report.txt
report.json
report.html
```

Example:

```text
SENTINEL SECURITY REPORT

Files scanned: 183492

Critical: 2
High:     7
Medium:   31
Low:      94

Overall risk: HIGH
```

---

# Phase 11 — Email Reporting

Sentinel can optionally send an authenticated report to a configured security mailbox.

Only security findings and reports should be transmitted by default.

Credentials must never be hard-coded into the executable.

---

# Phase 12 — Assembly Integration

Introduce x86-64 Assembly for selected low-level components.

Potential uses:

* CPU feature detection
* high-resolution timing
* optimized memory operations
* architecture-specific binary analysis
* low-level instrumentation

Assembly should complement the C architecture rather than replace C unnecessarily.

---

# Phase 13 — Advanced Binary Analysis

Eventually implement:

```text
x86-64 disassembler
        ↓
instruction analysis
        ↓
function detection
        ↓
control-flow graph
        ↓
call graph
        ↓
cross-reference analysis
```

This turns Sentinel into a reverse-engineering platform.

---

# Phase 14 — Behavioral Analysis

A future research component can execute authorized samples inside an isolated laboratory environment and observe:

```text
Processes
Files
Memory
System calls
Network activity
Loaded modules
```

Static and dynamic evidence can then be correlated.

---

# Phase 15 — AI Analysis

An optional AI layer can receive structured findings:

```text
PE information
Hashes
Imports
Strings
Process behavior
Memory events
Network events
Risk indicators
```

and generate an analyst-style explanation.

The AI should reason over collected evidence rather than automatically making unsupported claims.

---

# Security Principles

Sentinel follows these principles:

1. **Authorization first**
2. **Least privilege**
3. **No credential bypass**
4. **No unauthorized access**
5. **No covert data exfiltration**
6. **No destructive behavior**
7. **Detailed logging**
8. **Explicit user configuration**
9. **Safe testing environments**
10. **Evidence-based findings**

Testing should be performed on:

* your own computer
* your own virtual machines
* CTF environments
* authorized penetration-testing environments
* systems where you have explicit permission

---

# Initial Milestone

The first working version will intentionally be simple.

```text
sentinel.exe scan C:\Test
```

Expected output:

```text
╔══════════════════════════════════════╗
║          SENTINEL SECURITY           ║
║           FILE SCANNER               ║
╚══════════════════════════════════════╝

Target:
C:\Test

Scanning...

[FILE] example.exe
[FILE] document.txt
[DIR ] projects
[FILE] projects\test.exe

──────────────────────────────────────
Files scanned:       4
Directories:         1
Executables:         2
──────────────────────────────────────

Scan completed.
```

From this foundation, every subsequent subsystem will be added incrementally.

---

# Long-Term Vision

The ultimate goal is to create a modular security research platform capable of answering:

> **What exists on this authorized machine, what has changed, what looks unusual, why does it look unusual, and what evidence supports that conclusion?**

Sentinel is intended to become a combination of:

```text
Host Scanner
     +
PE Analyzer
     +
Process Monitor
     +
Reverse Engineering Toolkit
     +
Security Database
     +
Risk Engine
     +
Automated Reporting
     +
AI Analyst
```

---

## Current Status

**Version:** 0.1.0 — Project Initialization

**Current milestone:** Project setup

**Next milestone:** Recursive filesystem scanner

---

## Author

**Noam Slutski**

Security research project written primarily in C with x86-64 Assembly components.
