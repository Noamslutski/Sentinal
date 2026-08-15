/* ============================================================================
 *  Sentinel - sysinfo.h
 *  Host / system reconnaissance for authorized Windows hosts.
 *
 *  Splits cleanly into:
 *    - STATIC facts gathered once at startup (OS, hostname, CPU model, ...)
 *    - DYNAMIC metrics refreshed on a timer (CPU load, memory, uptime, ...)
 *
 *  All values live in one `SystemInfo` struct so the UI can render them the
 *  same data-driven way it renders everything else (see AppState in ui.h).
 * ==========================================================================*/
#ifndef SENTINEL_SYSINFO_H
#define SENTINEL_SYSINFO_H

#ifndef WINVER
#define WINVER       0x0A00
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <windows.h>

typedef struct {
    /* ---- static (filled by sysinfo_init) ---- */
    char       os[128];          /* e.g. "Windows 11 Home (Build 26200)"   */
    char       hostname[64];
    char       cpu_model[96];    /* e.g. "AMD Ryzen 5 5600"                */
    int        cores_physical;
    int        cores_logical;
    char       arch[16];         /* "x64" / "ARM64" / "x86"               */
    ULONGLONG  ram_total;        /* bytes                                  */
    char       sys_drive_letter; /* 'C'                                    */
    ULONGLONG  disk_total;       /* bytes                                  */

    /* ---- dynamic (refreshed by sysinfo_refresh) ---- */
    int        cpu_load_pct;     /* 0..100                                 */
    ULONGLONG  ram_used;         /* bytes                                  */
    int        ram_pct;          /* 0..100                                 */
    ULONGLONG  disk_free;        /* bytes                                  */
    int        proc_count;
    ULONGLONG  uptime_ms;

    /* ---- internal CPU sampling state ---- */
    ULONGLONG  _prev_idle, _prev_kernel, _prev_user;
    int        _have_prev;
} SystemInfo;

/* Gather static facts and take the first dynamic sample. */
void sysinfo_init(SystemInfo *si);

/* Update the dynamic metrics (call periodically, e.g. once per second). */
void sysinfo_refresh(SystemInfo *si);

#endif /* SENTINEL_SYSINFO_H */
