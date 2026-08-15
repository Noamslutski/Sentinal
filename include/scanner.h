/* ============================================================================
 *  Sentinel - scanner.h
 *  Authorized recursive filesystem scanner.
 *
 *  Runs on a background worker thread so the UI never blocks. For every file
 *  it records path, name, size, extension, type (by magic signature),
 *  timestamps, attributes, and a SHA-256 hash (Windows CNG / BCrypt).
 *
 *  The UI reads a consistent SNAPSHOT (counters + the most-recent files) under
 *  a lock; it never touches the worker's live state directly.
 *
 *  Authorized use only: this observes files the operator already has rights to
 *  read. It does not modify, move, or delete anything.
 * ==========================================================================*/
#ifndef SENTINEL_SCANNER_H
#define SENTINEL_SCANNER_H

#ifndef WINVER
#define WINVER       0x0A00
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <windows.h>

/* Posted to the notify window on progress/completion (repaint request). */
#define WM_SCAN_PROGRESS (WM_APP + 1)

/* Files larger than this are recorded but not hashed (keeps scans responsive). */
#define SCAN_HASH_CAP_BYTES (256ULL * 1024ULL * 1024ULL)

/* How many most-recent files the UI can show. */
#define SCAN_RECENT 32

typedef enum {
    SCAN_IDLE = 0,
    SCAN_RUNNING,
    SCAN_DONE,
    SCAN_STOPPED
} ScanState;

typedef struct {
    char       path[MAX_PATH];
    char       name[128];
    ULONGLONG  size;
    char       ext[24];      /* lowercase, no dot; "" if none              */
    char       type[24];     /* "PE image", "PDF", "Text", "Binary", ...   */
    FILETIME   created;
    FILETIME   modified;
    DWORD      attrs;
    char       sha256[72];   /* hex, or a short note for skipped files      */
    BOOL       is_executable;
} FileRecord;

typedef struct {
    volatile LONG    state;          /* ScanState                           */
    volatile LONG    cancel;         /* stop request                        */

    CRITICAL_SECTION cs;             /* guards everything below             */
    char             target[MAX_PATH];
    char             current_dir[MAX_PATH];
    ULONGLONG        files, dirs, executables, bytes, errors;
    FileRecord       recent[SCAN_RECENT];
    ULONGLONG        recent_total;   /* total pushes (ring write count)     */

    ULONGLONG        started_ms, ended_ms;
    HWND             notify_hwnd;
    HANDLE           thread;
} Scanner;

/* Immutable copy for rendering. */
typedef struct {
    ScanState  state;
    char       target[MAX_PATH];
    char       current_dir[MAX_PATH];
    ULONGLONG  files, dirs, executables, bytes, errors;
    FileRecord recent[SCAN_RECENT];   /* most-recent first                  */
    int        recent_n;
    ULONGLONG  started_ms, ended_ms;
} ScanSnapshot;

void      scanner_init(Scanner *sc, HWND notify);
void      scanner_destroy(Scanner *sc);           /* stops + joins thread   */
BOOL      scanner_start(Scanner *sc, const char *target);
void      scanner_stop(Scanner *sc);              /* async cancel request   */
ScanState scanner_state(Scanner *sc);
void      scanner_snapshot(Scanner *sc, ScanSnapshot *out);

#endif /* SENTINEL_SCANNER_H */
