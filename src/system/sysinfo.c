/* ============================================================================
 *  Sentinel - system/sysinfo.c
 *  Implementation of host reconnaissance using the Win32 API.
 *
 *  Everything here is read-only observation of the local host: registry values
 *  Windows itself publishes, processor topology, memory/disk counters, the
 *  process count, and system uptime. No process is opened for inspection and
 *  nothing is modified.
 * ==========================================================================*/
#include "sysinfo.h"

#include <tlhelp32.h>   /* CreateToolhelp32Snapshot */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- helpers ----------------------------------------------------------- */

/* Read a REG_SZ value into `out`. Returns TRUE on success. */
static BOOL reg_sz(HKEY root, const char *subkey, const char *value,
                   char *out, DWORD out_size)
{
    DWORD size = out_size;
    out[0] = '\0';
    LSTATUS st = RegGetValueA(root, subkey, value, RRF_RT_REG_SZ,
                              NULL, out, &size);
    return st == ERROR_SUCCESS;
}

/* Trim leading/trailing ASCII whitespace in place. */
static void trim(char *s)
{
    char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n > 0 && (s[n-1] == ' ' || s[n-1] == '\t')) s[--n] = '\0';
}

static ULONGLONG ft_to_u64(FILETIME ft)
{
    ULARGE_INTEGER u;
    u.LowPart  = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

/* ---- static gathering -------------------------------------------------- */

static void gather_os(SystemInfo *si)
{
    const char *CV = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    char product[96] = "";
    char build_str[32] = "";

    reg_sz(HKEY_LOCAL_MACHINE, CV, "ProductName", product, sizeof(product));
    reg_sz(HKEY_LOCAL_MACHINE, CV, "CurrentBuildNumber", build_str, sizeof(build_str));
    int build = atoi(build_str);

    /* Windows 11 still reports "Windows 10" in ProductName; correct it by build. */
    if (build >= 22000) {
        char *hit = strstr(product, "Windows 10");
        if (hit) memcpy(hit, "Windows 11", 10);
    }

    if (product[0] && build > 0)
        snprintf(si->os, sizeof(si->os), "%s (Build %d)", product, build);
    else if (product[0])
        snprintf(si->os, sizeof(si->os), "%s", product);
    else
        snprintf(si->os, sizeof(si->os), "Windows");
}

static void gather_cpu(SystemInfo *si)
{
    reg_sz(HKEY_LOCAL_MACHINE,
           "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
           "ProcessorNameString", si->cpu_model, sizeof(si->cpu_model));
    trim(si->cpu_model);
    if (si->cpu_model[0] == '\0')
        snprintf(si->cpu_model, sizeof(si->cpu_model), "Unknown CPU");

    SYSTEM_INFO sinf;
    GetNativeSystemInfo(&sinf);
    si->cores_logical = (int)sinf.dwNumberOfProcessors;

    switch (sinf.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: strcpy(si->arch, "x64");   break;
        case PROCESSOR_ARCHITECTURE_ARM64: strcpy(si->arch, "ARM64"); break;
        case PROCESSOR_ARCHITECTURE_INTEL: strcpy(si->arch, "x86");   break;
        default:                           strcpy(si->arch, "?");     break;
    }

    /* Physical core count via processor-relationship info (best effort). */
    int physical = 0;
    DWORD len = 0;
    GetLogicalProcessorInformation(NULL, &len);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && len > 0) {
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION *buf = malloc(len);
        if (buf && GetLogicalProcessorInformation(buf, &len)) {
            DWORD count = len / sizeof(buf[0]);
            for (DWORD i = 0; i < count; ++i)
                if (buf[i].Relationship == RelationProcessorCore) physical++;
        }
        free(buf);
    }
    si->cores_physical = (physical > 0) ? physical : si->cores_logical;
}

static void gather_disk(SystemInfo *si)
{
    char windir[MAX_PATH] = "C:\\Windows";
    GetWindowsDirectoryA(windir, sizeof(windir));
    si->sys_drive_letter = windir[0] ? windir[0] : 'C';

    char root[4] = { si->sys_drive_letter, ':', '\\', '\0' };
    ULARGE_INTEGER avail, total, freeTotal;
    if (GetDiskFreeSpaceExA(root, &avail, &total, &freeTotal)) {
        si->disk_total = total.QuadPart;
        si->disk_free  = freeTotal.QuadPart;
    }
}

/* ---- dynamic sampling -------------------------------------------------- */

static int count_processes(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    int count = 0;
    if (Process32First(snap, &pe)) {
        do { count++; } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return count;
}

static void sample_cpu(SystemInfo *si)
{
    FILETIME idle, kernel, user;
    if (!GetSystemTimes(&idle, &kernel, &user)) return;

    ULONGLONG i = ft_to_u64(idle);
    ULONGLONG k = ft_to_u64(kernel);   /* kernel time INCLUDES idle time */
    ULONGLONG u = ft_to_u64(user);

    if (si->_have_prev) {
        ULONGLONG d_idle   = i - si->_prev_idle;
        ULONGLONG d_total  = (k - si->_prev_kernel) + (u - si->_prev_user);
        if (d_total > 0) {
            ULONGLONG busy = (d_total > d_idle) ? (d_total - d_idle) : 0;
            int pct = (int)((busy * 100ULL) / d_total);
            si->cpu_load_pct = (pct < 0) ? 0 : (pct > 100 ? 100 : pct);
        }
    }
    si->_prev_idle   = i;
    si->_prev_kernel = k;
    si->_prev_user   = u;
    si->_have_prev   = 1;
}

/* ---- public API -------------------------------------------------------- */

void sysinfo_init(SystemInfo *si)
{
    memset(si, 0, sizeof(*si));

    gather_os(si);
    gather_cpu(si);
    gather_disk(si);

    DWORD n = sizeof(si->hostname);
    if (!GetComputerNameA(si->hostname, &n) || si->hostname[0] == '\0')
        snprintf(si->hostname, sizeof(si->hostname), "unknown-host");

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms))
        si->ram_total = ms.ullTotalPhys;

    sysinfo_refresh(si);   /* first dynamic sample */
}

void sysinfo_refresh(SystemInfo *si)
{
    sample_cpu(si);

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) {
        si->ram_total = ms.ullTotalPhys;
        si->ram_used  = ms.ullTotalPhys - ms.ullAvailPhys;
        si->ram_pct   = (int)ms.dwMemoryLoad;
    }

    char root[4] = { si->sys_drive_letter ? si->sys_drive_letter : 'C', ':', '\\', '\0' };
    ULARGE_INTEGER avail, total, freeTotal;
    if (GetDiskFreeSpaceExA(root, &avail, &total, &freeTotal)) {
        si->disk_total = total.QuadPart;
        si->disk_free  = freeTotal.QuadPart;
    }

    si->proc_count = count_processes();
    si->uptime_ms  = GetTickCount64();
}
