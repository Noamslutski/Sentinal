/* ============================================================================
 *  Sentinel - ui.h
 *  Public interface for the UI shell plus the central application-state model.
 *
 *  DESIGN NOTE
 *  -----------
 *  Every page renders from the `AppState` structure.  Right now the dashboard
 *  values are placeholders (all zero / empty), but each field is a well-defined
 *  slot: later stages simply write real data into `AppState` and call
 *  InvalidateRect() to repaint.  The UI never invents its own numbers, so the
 *  backend can be plugged in one page at a time without touching drawing code.
 * ==========================================================================*/
#ifndef SENTINEL_UI_H
#define SENTINEL_UI_H

/* Target a modern Windows API level (needed for ClearType + DWM features). */
#ifndef WINVER
#define WINVER       0x0A00
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <windows.h>
#include "sysinfo.h"
#include "scanner.h"

/* ---- Navigation pages -------------------------------------------------- */
typedef enum {
    PAGE_DASHBOARD = 0,
    PAGE_SCAN,
    PAGE_PROCESSES,
    PAGE_FILES,
    PAGE_NETWORK,
    PAGE_FINDINGS,
    PAGE_REPORTS,
    PAGE_COUNT
} PageId;

/* ---- Activity log ------------------------------------------------------ */
#define UI_MAX_LOG      64
#define UI_LOG_TEXT_LEN 160

typedef struct {
    char time[16];               /* "HH:MM:SS"                              */
    char text[UI_LOG_TEXT_LEN];  /* message                                 */
} LogEntry;

/* ---- Dashboard data model --------------------------------------------- *
 * Severity card counts. Populated by the findings engine in Stage 8; zero
 * for now. Live host metrics live in AppState.sys (see sysinfo.h).        */
typedef struct {
    int  critical, high, medium, low;
} DashboardData;

/* ---- Application state (one per main window) --------------------------- */
typedef struct {
    HWND    hwnd;
    PageId  current_page;
    int     hovered_nav;                /* nav index under cursor, or -1    */
    RECT    nav_rects[PAGE_COUNT];      /* hit-test rects, recomputed/paint */

    POINT   mouse;                      /* last known cursor position       */
    int     hovered_btn;               /* scan-page button hover, or -1    */
    RECT    scan_btn_browse;
    RECT    scan_btn_action;            /* Start / Stop                     */
    int     last_scan_state;           /* for transition logging           */

    /* Cached fonts (created once, freed on destroy). */
    HFONT   font_brand;
    HFONT   font_h1;
    HFONT   font_section;
    HFONT   font_body;
    HFONT   font_small;
    HFONT   font_nav;
    HFONT   font_number;
    HFONT   font_status;
    HFONT   font_mono;

    /* Activity feed (oldest first). */
    LogEntry log[UI_MAX_LOG];
    int      log_count;

    DashboardData data;   /* severity counts (Stage 8)        */
    SystemInfo    sys;    /* live host metrics (Stage 2)       */
    Scanner       scanner;/* filesystem scanner (Stage 3)      */
} AppState;

/* ---- API --------------------------------------------------------------- */
ATOM ui_register_class(HINSTANCE hInst);
HWND ui_create_main_window(HINSTANCE hInst, int nCmdShow);
void ui_log(AppState *app, const char *fmt, ...);

#endif /* SENTINEL_UI_H */
