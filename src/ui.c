/* ============================================================================
 *  Sentinel - ui.c
 *  The entire Stage 1 UI shell: a custom-drawn, double-buffered Win32 window
 *  with a dark "security operations" aesthetic.
 *
 *  WHY CUSTOM-DRAWN (GDI) INSTEAD OF NATIVE CONTROLS?
 *  Native Win32 controls (buttons, list views) are painted by the OS and are
 *  very hard to give a modern dark theme.  By owner-drawing everything against
 *  a memory DC we get full control of the look, zero external dependencies,
 *  and a single, predictable place where "real data" from later stages will be
 *  rendered.  Every page reads from AppState (see ui.h).
 *
 *  RENDER PIPELINE
 *      WM_PAINT -> paint_all() into an off-screen bitmap -> BitBlt to screen.
 *  Double-buffering keeps hover/repaint flicker-free.
 * ==========================================================================*/
#include "ui.h"
#include "theme.h"

#include <windowsx.h>   /* GET_X_LPARAM / GET_Y_LPARAM */
#include <shlobj.h>     /* SHBrowseForFolder (folder picker) */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/* Semantic weight aliases (values come from wingdi.h). */
#ifndef FW_SEMIBOLD
#define FW_SEMIBOLD 600
#endif

static const char *g_class_name = "SentinelMainWindow";

static const char *g_nav_labels[PAGE_COUNT] = {
    "Dashboard", "Scan", "Processes", "Files", "Network", "Findings", "Reports"
};

/* Short descriptions shown on each not-yet-implemented page. */
static const char *g_page_desc[PAGE_COUNT] = {
    "Real-time posture summary for this authorized host.",
    "Configure and launch authorized filesystem and system scans.",
    "Enumerate running processes, parent chains, and loaded modules.",
    "Inspect file metadata, hashes, entropy, and PE structure.",
    "Review network connections and listening endpoints.",
    "Correlated security findings with severity, evidence, and risk score.",
    "Generate and export TXT, JSON, and HTML security reports."
};

/* ---- Forward declarations --------------------------------------------- */
static LRESULT CALLBACK wnd_proc(HWND, UINT, WPARAM, LPARAM);
static void paint_all(AppState *, HDC, RECT);

/* ==========================================================================
 *  Small GDI helpers
 * ==========================================================================*/
static void fill_rect(HDC hdc, const RECT *rc, COLORREF color)
{
    HBRUSH b = CreateSolidBrush(color);
    FillRect(hdc, rc, b);
    DeleteObject(b);
}

static void draw_hline(HDC hdc, int x1, int x2, int y, COLORREF color)
{
    RECT r = { x1, y, x2, y + 1 };
    fill_rect(hdc, &r, color);
}

static void draw_vline(HDC hdc, int x, int y1, int y2, COLORREF color)
{
    RECT r = { x, y1, x + 1, y2 };
    fill_rect(hdc, &r, color);
}

/* Rounded rectangle with independent fill + border colours. */
static void draw_panel(HDC hdc, RECT rc, int radius, COLORREF fill, COLORREF border)
{
    HBRUSH b  = CreateSolidBrush(fill);
    HPEN   p  = CreatePen(PS_SOLID, 1, border);
    HBRUSH ob = (HBRUSH)SelectObject(hdc, b);
    HPEN   op = (HPEN)SelectObject(hdc, p);
    RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, radius, radius);
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(b);
    DeleteObject(p);
}

/* Filled circle centred on (cx,cy). */
static void fill_ellipse(HDC hdc, int cx, int cy, int r, COLORREF color)
{
    HBRUSH b  = CreateSolidBrush(color);
    HPEN   p  = CreatePen(PS_SOLID, 1, color);
    HBRUSH ob = (HBRUSH)SelectObject(hdc, b);
    HPEN   op = (HPEN)SelectObject(hdc, p);
    Ellipse(hdc, cx - r, cy - r, cx + r, cy + r);
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(b);
    DeleteObject(p);
}

/* Draw text (font selected + restored, background transparent). */
static void draw_text(HDC hdc, const char *text, RECT rc,
                      HFONT font, COLORREF color, UINT flags)
{
    HFONT of = (HFONT)SelectObject(hdc, font);
    SetTextColor(hdc, color);
    SetBkMode(hdc, TRANSPARENT);
    DrawTextA(hdc, text, -1, &rc, flags | DT_NOPREFIX);
    SelectObject(hdc, of);
}

static int text_width(HDC hdc, const char *text, HFONT font)
{
    HFONT of = (HFONT)SelectObject(hdc, font);
    SIZE sz;
    GetTextExtentPoint32A(hdc, text, (int)strlen(text), &sz);
    SelectObject(hdc, of);
    return sz.cx;
}

/* Bounded, always-null-terminating copy (avoids strncpy truncation warnings). */
static void copy_str(char *dst, size_t dstsz, const char *src)
{
    if (dstsz == 0) return;
    size_t i = 0;
    for (; i + 1 < dstsz && src[i]; ++i) dst[i] = src[i];
    dst[i] = '\0';
}

/* ==========================================================================
 *  Iconography (all vector, drawn with GDI - no icon fonts to depend on)
 * ==========================================================================*/
static void stroke_begin(HDC hdc, COLORREF color, int width,
                         HPEN *pen, HPEN *oldpen, HBRUSH *oldbrush)
{
    *pen      = CreatePen(PS_SOLID, width, color);
    *oldpen   = (HPEN)SelectObject(hdc, *pen);
    *oldbrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
}
static void stroke_end(HDC hdc, HPEN pen, HPEN oldpen, HBRUSH oldbrush)
{
    SelectObject(hdc, oldpen);
    SelectObject(hdc, oldbrush);
    DeleteObject(pen);
}

/* A small (~20px) glyph for a navigation page, centred on (cx,cy). */
static void draw_nav_icon(HDC hdc, PageId page, int cx, int cy, COLORREF color)
{
    HPEN pen, opn; HBRUSH obr;

    switch (page) {
    case PAGE_DASHBOARD: {                       /* 2x2 grid */
        RECT r1 = { cx-8, cy-8, cx-1, cy-1 };
        RECT r2 = { cx+1, cy-8, cx+8, cy-1 };
        RECT r3 = { cx-8, cy+1, cx-1, cy+8 };
        RECT r4 = { cx+1, cy+1, cx+8, cy+8 };
        fill_rect(hdc, &r1, color); fill_rect(hdc, &r2, color);
        fill_rect(hdc, &r3, color); fill_rect(hdc, &r4, color);
        break;
    }
    case PAGE_SCAN: {                            /* magnifier */
        stroke_begin(hdc, color, 2, &pen, &opn, &obr);
        Ellipse(hdc, cx-9, cy-9, cx+3, cy+3);
        MoveToEx(hdc, cx+1, cy+1, NULL); LineTo(hdc, cx+8, cy+8);
        stroke_end(hdc, pen, opn, obr);
        break;
    }
    case PAGE_PROCESSES: {                       /* CPU chip */
        stroke_begin(hdc, color, 2, &pen, &opn, &obr);
        RoundRect(hdc, cx-7, cy-7, cx+7, cy+7, 4, 4);
        stroke_end(hdc, pen, opn, obr);
        RECT inner = { cx-2, cy-2, cx+2, cy+2 };
        fill_rect(hdc, &inner, color);
        RECT pins[4] = {
            { cx-4, cy-10, cx-2, cy-7 }, { cx+2, cy-10, cx+4, cy-7 },
            { cx-4, cy+7,  cx-2, cy+10 },{ cx+2, cy+7,  cx+4, cy+10 }
        };
        for (int k = 0; k < 4; ++k) fill_rect(hdc, &pins[k], color);
        break;
    }
    case PAGE_FILES: {                           /* document, folded corner */
        stroke_begin(hdc, color, 2, &pen, &opn, &obr);
        POINT doc[6] = { {cx-7,cy-9},{cx+3,cy-9},{cx+7,cy-5},
                         {cx+7,cy+9},{cx-7,cy+9},{cx-7,cy-9} };
        Polyline(hdc, doc, 6);
        MoveToEx(hdc, cx+3, cy-9, NULL); LineTo(hdc, cx+3, cy-5); LineTo(hdc, cx+7, cy-5);
        MoveToEx(hdc, cx-4, cy+1, NULL); LineTo(hdc, cx+4, cy+1);
        MoveToEx(hdc, cx-4, cy+5, NULL); LineTo(hdc, cx+4, cy+5);
        stroke_end(hdc, pen, opn, obr);
        break;
    }
    case PAGE_NETWORK: {                         /* node graph */
        stroke_begin(hdc, color, 2, &pen, &opn, &obr);
        MoveToEx(hdc, cx, cy-6, NULL); LineTo(hdc, cx-8, cy+6);
        MoveToEx(hdc, cx, cy-6, NULL); LineTo(hdc, cx+8, cy+6);
        stroke_end(hdc, pen, opn, obr);
        fill_ellipse(hdc, cx,   cy-7, 3, color);
        fill_ellipse(hdc, cx-8, cy+7, 3, color);
        fill_ellipse(hdc, cx+8, cy+7, 3, color);
        break;
    }
    case PAGE_FINDINGS: {                         /* alert triangle */
        stroke_begin(hdc, color, 2, &pen, &opn, &obr);
        POINT tri[4] = { {cx,cy-9},{cx+9,cy+8},{cx-9,cy+8},{cx,cy-9} };
        Polyline(hdc, tri, 4);
        MoveToEx(hdc, cx, cy-2, NULL); LineTo(hdc, cx, cy+3);
        stroke_end(hdc, pen, opn, obr);
        fill_ellipse(hdc, cx, cy+6, 1, color);
        break;
    }
    case PAGE_REPORTS: {                          /* bar chart */
        draw_hline(hdc, cx-8, cx+9, cy+8, color);
        RECT b1 = { cx-7, cy+2, cx-3, cy+8 };
        RECT b2 = { cx-1, cy-3, cx+3, cy+8 };
        RECT b3 = { cx+5, cy-8, cx+9, cy+8 };
        fill_rect(hdc, &b1, color); fill_rect(hdc, &b2, color); fill_rect(hdc, &b3, color);
        break;
    }
    default: break;
    }
}

/* Sentinel emblem: a shield with a cut-out check mark. */
static void draw_shield(HDC hdc, int x, int y, int w, int h,
                        COLORREF fill, COLORREF cut)
{
    POINT s[5] = {
        { x,              y            },
        { x + w,          y            },
        { x + w,          y + (h*55)/100 },
        { x + w/2,        y + h        },
        { x,              y + (h*55)/100 }
    };
    HBRUSH b  = CreateSolidBrush(fill);
    HPEN   p  = CreatePen(PS_SOLID, 1, fill);
    HBRUSH ob = (HBRUSH)SelectObject(hdc, b);
    HPEN   op = (HPEN)SelectObject(hdc, p);
    Polygon(hdc, s, 5);
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(b);
    DeleteObject(p);

    /* Check mark carved out of the shield face. */
    HPEN cp  = CreatePen(PS_SOLID, 2, cut);
    HPEN ocp = (HPEN)SelectObject(hdc, cp);
    MoveToEx(hdc, x + (w*28)/100, y + (h*48)/100, NULL);
    LineTo  (hdc, x + (w*45)/100, y + (h*64)/100);
    LineTo  (hdc, x + (w*74)/100, y + (h*30)/100);
    SelectObject(hdc, ocp);
    DeleteObject(cp);
}

/* ==========================================================================
 *  Time helpers
 * ==========================================================================*/
static void format_header_date(char *buf, size_t n)
{
    static const char *mon[12] = { "Jan","Feb","Mar","Apr","May","Jun",
                                   "Jul","Aug","Sep","Oct","Nov","Dec" };
    SYSTEMTIME st; GetLocalTime(&st);
    snprintf(buf, n, "%s %02d, %04d   |   %02d:%02d:%02d",
             mon[(st.wMonth - 1) % 12], st.wDay, st.wYear,
             st.wHour, st.wMinute, st.wSecond);
}

/* ==========================================================================
 *  Header bar
 * ==========================================================================*/
static void paint_header(AppState *app, HDC hdc, RECT client)
{
    RECT bar = { 0, 0, client.right, HEADER_H };
    fill_rect(hdc, &bar, COL_BG_HEADER);
    draw_hline(hdc, 0, client.right, HEADER_H - 1, COL_BORDER);

    int cy = HEADER_H / 2;

    /* Emblem + wordmark. */
    draw_shield(hdc, 20, cy - 11, 18, 22, COL_ACCENT, COL_BG_HEADER);

    SetTextCharacterExtra(hdc, 3);      /* letter-spacing for the wordmark */
    RECT brand = { 50, 0, 320, HEADER_H };
    draw_text(hdc, "SENTINEL", brand, app->font_brand, COL_TEXT,
              DT_SINGLELINE | DT_VCENTER);
    int bw = text_width(hdc, "SENTINEL", app->font_brand) + 8 * 3;
    SetTextCharacterExtra(hdc, 0);

    int dx = 50 + bw + 18;
    draw_vline(hdc, dx, 18, HEADER_H - 18, COL_BORDER);
    RECT sub = { dx + 16, 0, dx + 360, HEADER_H };
    draw_text(hdc, "HOST ANALYSIS PLATFORM", sub, app->font_status,
              COL_TEXT_MUTED, DT_SINGLELINE | DT_VCENTER);

    /* Status pill (right-aligned). */
    const char *status = "SYSTEM ONLINE";
    int tw    = text_width(hdc, status, app->font_status);
    int pillw = 16 + 10 + 8 + tw + 16;
    int pillh = 28;
    RECT pill = { client.right - 20 - pillw, cy - pillh/2,
                  client.right - 20,          cy + pillh/2 };
    draw_panel(hdc, pill, 14, COL_PANEL, COL_BORDER);

    int dotx = pill.left + 18;
    fill_ellipse(hdc, dotx, cy, 6, COL_ONLINE_DIM);   /* soft glow */
    fill_ellipse(hdc, dotx, cy, 4, COL_ONLINE);       /* live dot  */

    RECT tr = { dotx + 12, pill.top, pill.right - 12, pill.bottom };
    draw_text(hdc, status, tr, app->font_status, COL_ONLINE,
              DT_SINGLELINE | DT_VCENTER);
}

/* ==========================================================================
 *  Sidebar navigation
 * ==========================================================================*/
static void paint_sidebar(AppState *app, HDC hdc, RECT client)
{
    RECT sb = { 0, HEADER_H, SIDEBAR_W, client.bottom };
    fill_rect(hdc, &sb, COL_BG_SIDEBAR);
    draw_vline(hdc, SIDEBAR_W - 1, HEADER_H, client.bottom, COL_BORDER);

    SetTextCharacterExtra(hdc, 2);
    RECT cap = { 24, HEADER_H + 18, SIDEBAR_W - 16, HEADER_H + 34 };
    draw_text(hdc, "NAVIGATION", cap, app->font_status, COL_TEXT_FAINT,
              DT_SINGLELINE);
    SetTextCharacterExtra(hdc, 0);

    int y = HEADER_H + 44;
    for (int i = 0; i < PAGE_COUNT; ++i) {
        RECT item = { 8, y, SIDEBAR_W - 8, y + NAV_ITEM_H };
        app->nav_rects[i] = item;

        BOOL active = (app->current_page == (PageId)i);
        BOOL hover  = (app->hovered_nav == i);
        COLORREF fg = active ? COL_ACCENT : (hover ? COL_TEXT : COL_TEXT_MUTED);

        if (active) {
            draw_panel(hdc, item, 10, COL_NAV_ACTIVE, COL_NAV_ACTIVE);
            RECT indicator = { 0, y + 10, 3, y + NAV_ITEM_H - 10 };
            fill_rect(hdc, &indicator, COL_ACCENT);
        } else if (hover) {
            draw_panel(hdc, item, 10, COL_NAV_HOVER, COL_NAV_HOVER);
        }

        draw_nav_icon(hdc, (PageId)i, item.left + 24, y + NAV_ITEM_H/2, fg);

        RECT label = { item.left + 46, y, item.right - 10, y + NAV_ITEM_H };
        draw_text(hdc, g_nav_labels[i], label, app->font_nav, fg,
                  DT_SINGLELINE | DT_VCENTER);

        y += NAV_ITEM_H + 2;
    }

    /* Footer: version + stage tag. */
    RECT f1 = { 24, client.bottom - 54, SIDEBAR_W - 16, client.bottom - 36 };
    draw_text(hdc, "Sentinel  v0.1.0", f1, app->font_small, COL_TEXT_MUTED,
              DT_SINGLELINE);
    RECT f2 = { 24, client.bottom - 32, SIDEBAR_W - 16, client.bottom - 14 };
    draw_text(hdc, "Stage 1  -  UI Shell", f2, app->font_small, COL_TEXT_FAINT,
              DT_SINGLELINE);
}

/* ==========================================================================
 *  Section header helper: accent tick + spaced uppercase label
 * ==========================================================================*/
static void draw_section_title(AppState *app, HDC hdc, int x, int y,
                               const char *text)
{
    RECT tick = { x, y + 1, x + 3, y + 15 };
    fill_rect(hdc, &tick, COL_ACCENT);
    SetTextCharacterExtra(hdc, 1);
    RECT tr = { x + 12, y, x + 420, y + 16 };
    draw_text(hdc, text, tr, app->font_section, COL_TEXT, DT_SINGLELINE);
    SetTextCharacterExtra(hdc, 0);
}

/* ==========================================================================
 *  Dashboard: severity cards + host status + activity feed
 * ==========================================================================*/
static void draw_stat_card(AppState *app, HDC hdc, RECT rc,
                           const char *label, int value, COLORREF sev)
{
    draw_panel(hdc, rc, 12, COL_PANEL, COL_BORDER);

    int px = rc.left + 18;
    int py = rc.top + 20;
    fill_ellipse(hdc, px + 3, py + 5, 4, sev);
    SetTextCharacterExtra(hdc, 1);
    RECT lr = { px + 16, py - 3, rc.right - 14, py + 15 };
    draw_text(hdc, label, lr, app->font_status, sev, DT_SINGLELINE);
    SetTextCharacterExtra(hdc, 0);

    char num[16];
    snprintf(num, sizeof(num), "%d", value);
    RECT nr = { rc.left + 16, rc.top + 34, rc.right - 14, rc.bottom - 24 };
    draw_text(hdc, num, nr, app->font_number, COL_TEXT,
              DT_SINGLELINE | DT_VCENTER | DT_LEFT);

    RECT cr = { rc.left + 18, rc.bottom - 26, rc.right - 14, rc.bottom - 8 };
    draw_text(hdc, "findings", cr, app->font_small, COL_TEXT_FAINT, DT_SINGLELINE);
}

/* Colour the CPU-load value by pressure so it reads at a glance. */
static COLORREF load_color(int pct)
{
    if (pct >= 85) return COL_CRITICAL;
    if (pct >= 60) return COL_HIGH;
    return COL_TEXT;
}

static void paint_host_status(AppState *app, HDC hdc, RECT p)
{
    draw_panel(hdc, p, 12, COL_PANEL, COL_BORDER);
    int px = p.left + 22;
    int py = p.top + 22;
    draw_section_title(app, hdc, px, py, "HOST STATUS");

    const SystemInfo *s = &app->sys;

    /* Build the display strings from live values. */
    char v_os[136], v_host[80], v_cpu[136], v_mem[80];
    char v_load[24], v_disk[96], v_proc[24], v_up[48];

    double gb = 1073741824.0;
    snprintf(v_os,   sizeof(v_os),   "%s", s->os);
    snprintf(v_host, sizeof(v_host), "%s", s->hostname);
    if (s->cores_physical > 0 && s->cores_physical != s->cores_logical)
        snprintf(v_cpu, sizeof(v_cpu), "%s  (%dC/%dT)",
                 s->cpu_model, s->cores_physical, s->cores_logical);
    else
        snprintf(v_cpu, sizeof(v_cpu), "%s  (%d threads)",
                 s->cpu_model, s->cores_logical);
    snprintf(v_mem,  sizeof(v_mem),  "%.1f / %.1f GB  (%d%%)",
             s->ram_used / gb, s->ram_total / gb, s->ram_pct);
    snprintf(v_load, sizeof(v_load), "%d%%", s->cpu_load_pct);
    snprintf(v_disk, sizeof(v_disk), "%c:  %.0f GB free / %.0f GB",
             s->sys_drive_letter, s->disk_free / gb, s->disk_total / gb);
    snprintf(v_proc, sizeof(v_proc), "%d", s->proc_count);

    ULONGLONG secs = s->uptime_ms / 1000ULL;
    int ud = (int)(secs / 86400ULL);
    int uh = (int)((secs % 86400ULL) / 3600ULL);
    int um = (int)((secs % 3600ULL) / 60ULL);
    int us = (int)(secs % 60ULL);
    if (ud > 0) snprintf(v_up, sizeof(v_up), "%dd %02d:%02d:%02d", ud, uh, um, us);
    else        snprintf(v_up, sizeof(v_up), "%02d:%02d:%02d", uh, um, us);

    const char *labels[8] = {
        "Operating System", "Host Name", "Processor", "Physical Memory",
        "CPU Load", "System Drive", "Processes", "Uptime"
    };
    const char *values[8] = {
        v_os, v_host, v_cpu, v_mem, v_load, v_disk, v_proc, v_up
    };
    COLORREF colors[8] = {
        COL_TEXT, COL_TEXT, COL_TEXT, COL_TEXT,
        load_color(s->cpu_load_pct), COL_TEXT, COL_TEXT, COL_TEXT
    };
    const int n = 8;

    int top  = py + 40;
    int rowH = ((p.bottom - 16) - top) / n;
    if (rowH < 28) rowH = 28;

    for (int i = 0; i < n; ++i) {
        int ry = top + i * rowH;
        RECT lr = { px, ry, (p.left + p.right)/2, ry + rowH };
        draw_text(hdc, labels[i], lr, app->font_body, COL_TEXT_MUTED,
                  DT_SINGLELINE | DT_VCENTER);

        RECT vr = { p.left, ry, p.right - 22, ry + rowH };
        draw_text(hdc, values[i], vr, app->font_body, colors[i],
                  DT_SINGLELINE | DT_VCENTER | DT_RIGHT | DT_END_ELLIPSIS);

        if (i < n - 1) draw_hline(hdc, px, p.right - 22, ry + rowH, COL_SEP);
    }
}

static void paint_activity(AppState *app, HDC hdc, RECT p)
{
    draw_panel(hdc, p, 12, COL_PANEL, COL_BORDER);
    int px = p.left + 22;
    int py = p.top + 22;
    draw_section_title(app, hdc, px, py, "RECENT ACTIVITY");

    int top    = py + 40;
    int lineH  = 26;
    int maxln  = (p.bottom - 18 - top) / lineH;
    if (maxln < 1) maxln = 1;

    int start = (app->log_count > maxln) ? app->log_count - maxln : 0;
    for (int i = start; i < app->log_count; ++i) {
        int y = top + (i - start) * lineH;
        char stamp[24];
        snprintf(stamp, sizeof(stamp), "[%s]", app->log[i].time);

        RECT sr = { px, y, px + 100, y + lineH };
        draw_text(hdc, stamp, sr, app->font_mono, COL_ACCENT,
                  DT_SINGLELINE | DT_VCENTER);
        int off = text_width(hdc, stamp, app->font_mono) + 10;

        RECT tr = { px + off, y, p.right - 16, y + lineH };
        draw_text(hdc, app->log[i].text, tr, app->font_mono, COL_TEXT_MUTED,
                  DT_SINGLELINE | DT_VCENTER);
    }
}

static void paint_dashboard(AppState *app, HDC hdc, RECT c)
{
    int left  = c.left + PAD;
    int top   = c.top + PAD;
    int right = c.right - PAD;
    int innerW = right - left;

    RECT title = { left, top, right, top + 28 };
    draw_text(hdc, "Security Overview", title, app->font_h1, COL_TEXT,
              DT_SINGLELINE);

    char date[64];
    format_header_date(date, sizeof(date));
    RECT dr = { right - 320, top, right, top + 28 };
    draw_text(hdc, date, dr, app->font_small, COL_TEXT_MUTED,
              DT_SINGLELINE | DT_RIGHT | DT_VCENTER);

    RECT sub = { left, top + 28, right, top + 48 };
    draw_text(hdc, g_page_desc[PAGE_DASHBOARD], sub, app->font_small,
              COL_TEXT_MUTED, DT_SINGLELINE);

    /* Severity cards. */
    int y     = top + 62;
    int gap   = 16;
    int cardH = 116;
    int cardW = (innerW - 3 * gap) / 4;
    const char *labels[4] = { "CRITICAL", "HIGH", "MEDIUM", "LOW" };
    COLORREF    sev[4]    = { COL_CRITICAL, COL_HIGH, COL_MEDIUM, COL_LOW };
    int         vals[4]   = { app->data.critical, app->data.high,
                              app->data.medium, app->data.low };
    for (int i = 0; i < 4; ++i) {
        int x = left + i * (cardW + gap);
        RECT rc = { x, y, x + cardW, y + cardH };
        draw_stat_card(app, hdc, rc, labels[i], vals[i], sev[i]);
    }
    y += cardH + 22;

    /* Host status (left) + activity feed (right). */
    int bottom = c.bottom - PAD;
    int leftW  = (int)(innerW * 0.56);
    RECT host = { left,             y, left + leftW, bottom };
    RECT act  = { left + leftW + gap, y, right,      bottom };
    paint_host_status(app, hdc, host);
    paint_activity(app, hdc, act);
}

/* ==========================================================================
 *  Placeholder page (Scan / Processes / Files / Network / Findings / Reports)
 * ==========================================================================*/
static void paint_placeholder(AppState *app, HDC hdc, RECT c)
{
    PageId pg = app->current_page;
    int left  = c.left + PAD;
    int top   = c.top + PAD;
    int right = c.right - PAD;

    RECT title = { left, top, right, top + 28 };
    draw_text(hdc, g_nav_labels[pg], title, app->font_h1, COL_TEXT, DT_SINGLELINE);
    RECT sub = { left, top + 28, right, top + 48 };
    draw_text(hdc, g_page_desc[pg], sub, app->font_small, COL_TEXT_MUTED,
              DT_SINGLELINE);

    RECT panel = { left, top + 70, right, c.bottom - PAD };
    draw_panel(hdc, panel, 12, COL_PANEL, COL_BORDER);

    int cx = (panel.left + panel.right) / 2;
    int cy = (panel.top + panel.bottom) / 2;

    RECT badge = { cx - 32, cy - 62, cx + 32, cy + 2 };
    draw_panel(hdc, badge, 16, COL_PANEL_ALT, COL_BORDER);
    draw_nav_icon(hdc, pg, cx, cy - 30, COL_ACCENT);

    RECT m1 = { panel.left, cy + 10, panel.right, cy + 38 };
    draw_text(hdc, "Module not yet implemented", m1, app->font_h1,
              COL_TEXT_MUTED, DT_SINGLELINE | DT_CENTER);
    RECT m2 = { panel.left, cy + 40, panel.right, cy + 62 };
    draw_text(hdc, "Scheduled for an upcoming Sentinel development stage.",
              m2, app->font_small, COL_TEXT_FAINT, DT_SINGLELINE | DT_CENTER);
}

/* ==========================================================================
 *  Scan page (Stage 3) — controls, live progress, recent files
 * ==========================================================================*/
enum { BTN_SECONDARY = 0, BTN_PRIMARY = 1, BTN_DANGER = 2 };

static void fmt_size(ULONGLONG b, char *out, size_t n)
{
    double d = (double)b;
    if      (b >= 1073741824ULL) snprintf(out, n, "%.2f GB", d / 1073741824.0);
    else if (b >= 1048576ULL)    snprintf(out, n, "%.1f MB", d / 1048576.0);
    else if (b >= 1024ULL)       snprintf(out, n, "%.0f KB", d / 1024.0);
    else                         snprintf(out, n, "%llu B", (unsigned long long)b);
}

/* Integer with thousands separators, e.g. 18392 -> "18,392". */
static void fmt_commas(ULONGLONG v, char *out, size_t n)
{
    char tmp[32];
    int len = snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)v);
    int commas = (len - 1) / 3;
    int outlen = len + commas;
    if ((size_t)outlen >= n) { strncpy(out, tmp, n - 1); out[n-1] = '\0'; return; }
    out[outlen] = '\0';
    int oi = outlen - 1, cnt = 0;
    for (int i = len - 1; i >= 0; --i) {
        out[oi--] = tmp[i];
        if (++cnt % 3 == 0 && i > 0) out[oi--] = ',';
    }
}

static void draw_button(AppState *app, HDC hdc, RECT r, const char *label,
                        int style, BOOL hover)
{
    COLORREF fill, border, fg;
    if (style == BTN_PRIMARY) {
        fill = hover ? RGB(88, 232, 214) : COL_ACCENT; border = fill; fg = COL_BG_CONTENT;
    } else if (style == BTN_DANGER) {
        fill = hover ? RGB(255, 112, 104) : COL_CRITICAL; border = fill; fg = RGB(24, 12, 12);
    } else {
        fill = hover ? COL_PANEL_ALT : COL_PANEL; border = COL_BORDER;
        fg = hover ? COL_TEXT : COL_TEXT_MUTED;
    }
    draw_panel(hdc, r, 8, fill, border);
    draw_text(hdc, label, r, app->font_nav, fg,
              DT_SINGLELINE | DT_CENTER | DT_VCENTER);
}

/* Native folder picker (authorized target selection). */
static BOOL browse_for_folder(HWND owner, char *out, size_t n)
{
    BOOL picked = FALSE;
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    BROWSEINFOA bi;
    memset(&bi, 0, sizeof(bi));
    bi.hwndOwner = owner;
    bi.lpszTitle = "Select a folder to scan (authorized hosts only)";
    bi.ulFlags   = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_EDITBOX;

    LPITEMIDLIST pidl = SHBrowseForFolderA(&bi);
    if (pidl) {
        char path[MAX_PATH];
        if (SHGetPathFromIDListA(pidl, path)) {
            copy_str(out, n, path);
            picked = TRUE;
        }
        CoTaskMemFree(pidl);
    }
    CoUninitialize();
    return picked;
}

/* One live counter tile inside the progress card. */
static void draw_tile(AppState *app, HDC hdc, RECT r, const char *value,
                      const char *label, COLORREF vcolor)
{
    draw_panel(hdc, r, 8, COL_PANEL_ALT, COL_BORDER);
    RECT vr = { r.left + 12, r.top + 5,  r.right - 8, r.top + 27 };
    draw_text(hdc, value, vr, app->font_h1, vcolor, DT_SINGLELINE);
    RECT lr = { r.left + 12, r.top + 26, r.right - 8, r.top + 42 };
    draw_text(hdc, label, lr, app->font_small, COL_TEXT_MUTED, DT_SINGLELINE);
}

static void paint_scan(AppState *app, HDC hdc, RECT c)
{
    int left  = c.left + PAD;
    int top   = c.top + PAD;
    int right = c.right - PAD;

    RECT title = { left, top, right, top + 28 };
    draw_text(hdc, "Scan", title, app->font_h1, COL_TEXT, DT_SINGLELINE);
    RECT sub = { left, top + 28, right, top + 48 };
    draw_text(hdc, g_page_desc[PAGE_SCAN], sub, app->font_small, COL_TEXT_MUTED,
              DT_SINGLELINE);

    ScanSnapshot s;
    scanner_snapshot(&app->scanner, &s);
    BOOL running = (s.state == SCAN_RUNNING);

    int y = top + 62;

    /* ---- control card ---- */
    RECT ctrl = { left, y, right, y + 84 };
    draw_panel(hdc, ctrl, 12, COL_PANEL, COL_BORDER);

    int bh = 38, by = ctrl.top + (84 - bh) / 2;
    const char *actLabel = running ? "Stop Scan" : "Start Scan";
    int aw = text_width(hdc, actLabel, app->font_nav) + 44;
    RECT ba = { right - 18 - aw, by, right - 18, by + bh };
    int bw = text_width(hdc, "Browse", app->font_nav) + 44;
    RECT bb = { ba.left - 12 - bw, by, ba.left - 12, by + bh };
    app->scan_btn_browse = bb;
    app->scan_btn_action = ba;

    draw_button(app, hdc, bb, "Browse", BTN_SECONDARY,
                app->hovered_btn == 0 && !running);
    draw_button(app, hdc, ba, actLabel, running ? BTN_DANGER : BTN_PRIMARY,
                app->hovered_btn == 1);

    SetTextCharacterExtra(hdc, 1);
    RECT capr = { ctrl.left + 20, ctrl.top + 16, ctrl.left + 320, ctrl.top + 32 };
    draw_text(hdc, "SCAN TARGET", capr, app->font_status, COL_TEXT_FAINT, DT_SINGLELINE);
    SetTextCharacterExtra(hdc, 0);
    RECT pathr = { ctrl.left + 20, ctrl.top + 34, bb.left - 16, ctrl.top + 66 };
    draw_text(hdc, s.target, pathr, app->font_body, COL_TEXT,
              DT_SINGLELINE | DT_VCENTER | DT_PATH_ELLIPSIS);

    y = ctrl.bottom + 16;

    /* ---- progress card ---- */
    RECT prog = { left, y, right, y + 152 };
    draw_panel(hdc, prog, 12, COL_PANEL, COL_BORDER);
    int px = prog.left + 20;

    char status[420];
    COLORREF scol;
    if (running) {
        snprintf(status, sizeof(status), "Scanning:  %s",
                 s.current_dir[0] ? s.current_dir : s.target);
        scol = COL_TEXT;
    } else if (s.state == SCAN_DONE) {
        double sec = (s.ended_ms > s.started_ms) ? (s.ended_ms - s.started_ms)/1000.0 : 0.0;
        snprintf(status, sizeof(status), "Scan complete  -  %.1fs elapsed", sec);
        scol = COL_ONLINE;
    } else if (s.state == SCAN_STOPPED) {
        snprintf(status, sizeof(status), "Scan stopped by operator");
        scol = COL_HIGH;
    } else {
        snprintf(status, sizeof(status), "Idle  -  choose a target and press Start Scan");
        scol = COL_TEXT_MUTED;
    }
    RECT sr = { px, prog.top + 18, prog.right - 20, prog.top + 38 };
    draw_text(hdc, status, sr, app->font_body, scol,
              DT_SINGLELINE | DT_VCENTER | DT_PATH_ELLIPSIS);

    /* progress bar */
    int barY = prog.top + 48, barH = 10;
    RECT track = { px, barY, prog.right - 20, barY + barH };
    draw_panel(hdc, track, barH/2, COL_PANEL_ALT, COL_PANEL_ALT);
    int trackW = track.right - track.left;
    if (running) {                                  /* indeterminate sweep */
        int segW = trackW * 28 / 100; if (segW < 60) segW = 60;
        int span = trackW + segW;
        int pos  = (int)((GetTickCount64() / 8) % (ULONGLONG)span);
        int a = track.left - segW + pos;
        int b = a + segW;
        if (a < track.left)  a = track.left;
        if (b > track.right) b = track.right;
        if (b > a) { RECT seg = { a, barY, b, barY + barH };
                     draw_panel(hdc, seg, barH/2, COL_ACCENT, COL_ACCENT); }
    } else if (s.state == SCAN_DONE) {
        draw_panel(hdc, track, barH/2, COL_ONLINE, COL_ONLINE);
    } else if (s.state == SCAN_STOPPED) {
        RECT half = { track.left, barY, track.left + trackW/3, barY + barH };
        draw_panel(hdc, half, barH/2, COL_HIGH, COL_HIGH);
    }

    /* counter tiles */
    char v_files[24], v_dirs[24], v_exe[24], v_data[24], v_el[24];
    fmt_commas(s.files, v_files, sizeof(v_files));
    fmt_commas(s.dirs, v_dirs, sizeof(v_dirs));
    fmt_commas(s.executables, v_exe, sizeof(v_exe));
    fmt_size(s.bytes, v_data, sizeof(v_data));
    double el = running ? (GetTickCount64() - s.started_ms)/1000.0
              : (s.ended_ms > s.started_ms ? (s.ended_ms - s.started_ms)/1000.0 : 0.0);
    snprintf(v_el, sizeof(v_el), "%.1fs", el);

    const char *tv[5] = { v_files, v_dirs, v_exe, v_data, v_el };
    const char *tl[5] = { "Files", "Directories", "Executables", "Data", "Elapsed" };
    COLORREF    tc[5] = { COL_TEXT, COL_TEXT,
                          s.executables ? COL_HIGH : COL_TEXT, COL_TEXT, COL_TEXT };
    int tilesY = barY + barH + 16, tileH = 46, gap = 12, cols = 5;
    int tileW = (trackW - (cols - 1) * gap) / cols;
    for (int i = 0; i < cols; ++i) {
        RECT ti = { px + i*(tileW+gap), tilesY, px + i*(tileW+gap) + tileW, tilesY + tileH };
        draw_tile(app, hdc, ti, tv[i], tl[i], tc[i]);
    }

    y = prog.bottom + 16;

    /* ---- recent files ---- */
    RECT list = { left, y, right, c.bottom - PAD };
    draw_panel(hdc, list, 12, COL_PANEL, COL_BORDER);
    int lx = list.left + 20, lyt = list.top + 18;
    draw_section_title(app, hdc, lx, lyt, "RECENT FILES");
    char shown_lbl[32];
    snprintf(shown_lbl, sizeof(shown_lbl), "%d shown", s.recent_n);
    RECT scr = { list.right - 160, lyt, list.right - 20, lyt + 16 };
    draw_text(hdc, shown_lbl, scr, app->font_small, COL_TEXT_FAINT,
              DT_SINGLELINE | DT_RIGHT);

    int rowsTop = lyt + 34, rowH = 26;
    int maxRows = (list.bottom - 14 - rowsTop) / rowH;
    if (maxRows < 0) maxRows = 0;

    if (s.recent_n == 0) {
        RECT er = { list.left, (list.top + list.bottom)/2 - 10,
                    list.right, (list.top + list.bottom)/2 + 10 };
        draw_text(hdc, "No files scanned yet — start a scan to populate.",
                  er, app->font_small, COL_TEXT_FAINT, DT_SINGLELINE | DT_CENTER);
    } else {
        int shaRight  = list.right - 20;
        int shaLeft   = shaRight - 156;
        int sizeRight = shaLeft - 16;
        int sizeLeft  = sizeRight - 90;
        int typeLeft  = lx + (list.right - 20 - lx) * 44 / 100;
        int shown = (s.recent_n < maxRows) ? s.recent_n : maxRows;

        for (int i = 0; i < shown; ++i) {
            FileRecord *f = &s.recent[i];
            int ry = rowsTop + i * rowH;

            RECT nr = { lx, ry, typeLeft - 10, ry + rowH };
            draw_text(hdc, f->name, nr, app->font_body,
                      f->is_executable ? COL_HIGH : COL_TEXT,
                      DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);

            RECT tr = { typeLeft, ry, sizeLeft - 10, ry + rowH };
            draw_text(hdc, f->type, tr, app->font_small, COL_TEXT_MUTED,
                      DT_SINGLELINE | DT_VCENTER);

            char szb[24]; fmt_size(f->size, szb, sizeof(szb));
            RECT szr = { sizeLeft, ry, sizeRight, ry + rowH };
            draw_text(hdc, szb, szr, app->font_body, COL_TEXT_MUTED,
                      DT_SINGLELINE | DT_VCENTER | DT_RIGHT);

            char shab[24];
            if (f->sha256[0] == '(') { strcpy(shab, "n/a"); }
            else { memcpy(shab, f->sha256, 16); strcpy(shab + 16, ".."); }
            RECT shr = { shaLeft, ry, shaRight, ry + rowH };
            draw_text(hdc, shab, shr, app->font_mono, COL_ACCENT,
                      DT_SINGLELINE | DT_VCENTER | DT_RIGHT);

            if (i < shown - 1)
                draw_hline(hdc, lx, list.right - 20, ry + rowH, COL_SEP);
        }
    }
}

/* ==========================================================================
 *  Compose the full frame
 * ==========================================================================*/
static void paint_all(AppState *app, HDC hdc, RECT client)
{
    fill_rect(hdc, &client, COL_BG_CONTENT);
    paint_header(app, hdc, client);
    paint_sidebar(app, hdc, client);

    RECT content = { SIDEBAR_W, HEADER_H, client.right, client.bottom };
    switch (app->current_page) {
    case PAGE_DASHBOARD: paint_dashboard(app, hdc, content);   break;
    case PAGE_SCAN:      paint_scan(app, hdc, content);        break;
    default:             paint_placeholder(app, hdc, content); break;
    }
}

/* Content region (right of the sidebar, below the header). */
static RECT content_rect(HWND hwnd)
{
    RECT rc; GetClientRect(hwnd, &rc);
    RECT content = { SIDEBAR_W, HEADER_H, rc.right, rc.bottom };
    return content;
}

/* Log scan start/stop/complete transitions to the activity feed. */
static void scan_check_transition(AppState *app)
{
    ScanState st = scanner_state(&app->scanner);
    if ((int)st == app->last_scan_state) return;

    if (st == SCAN_DONE) {
        ScanSnapshot s; scanner_snapshot(&app->scanner, &s);
        double sec = (s.ended_ms > s.started_ms) ? (s.ended_ms - s.started_ms)/1000.0 : 0.0;
        ui_log(app, "Scan complete: %llu files, %llu dirs, %llu exe (%.1fs)",
               (unsigned long long)s.files, (unsigned long long)s.dirs,
               (unsigned long long)s.executables, sec);
    } else if (st == SCAN_STOPPED) {
        ui_log(app, "Scan stopped by operator");
    }
    app->last_scan_state = (int)st;
}

/* ==========================================================================
 *  Activity log (printf-style)
 * ==========================================================================*/
void ui_log(AppState *app, const char *fmt, ...)
{
    if (!app) return;
    if (app->log_count >= UI_MAX_LOG) {           /* drop oldest */
        memmove(&app->log[0], &app->log[1],
                sizeof(LogEntry) * (UI_MAX_LOG - 1));
        app->log_count = UI_MAX_LOG - 1;
    }
    LogEntry *e = &app->log[app->log_count++];

    SYSTEMTIME st; GetLocalTime(&st);
    snprintf(e->time, sizeof(e->time), "%02d:%02d:%02d",
             st.wHour % 100, st.wMinute % 100, st.wSecond % 100);

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(e->text, sizeof(e->text), fmt, ap);
    va_end(ap);

    if (app->hwnd) InvalidateRect(app->hwnd, NULL, FALSE);
}

/* ==========================================================================
 *  Font lifecycle
 * ==========================================================================*/
static HFONT make_font(int px, int weight, const char *face)
{
    return CreateFontA(-px, 0, 0, 0, weight, FALSE, FALSE, FALSE,
                       DEFAULT_CHARSET, OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS,
                       CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, face);
}

static void create_fonts(AppState *a)
{
    a->font_brand   = make_font(22, FW_BOLD,     "Segoe UI");
    a->font_h1      = make_font(19, FW_SEMIBOLD, "Segoe UI");
    a->font_section = make_font(12, FW_BOLD,     "Segoe UI");
    a->font_body    = make_font(14, FW_NORMAL,   "Segoe UI");
    a->font_small   = make_font(12, FW_NORMAL,   "Segoe UI");
    a->font_nav     = make_font(14, FW_SEMIBOLD, "Segoe UI");
    a->font_number  = make_font(40, FW_LIGHT,    "Segoe UI");
    a->font_status  = make_font(11, FW_SEMIBOLD, "Segoe UI");
    a->font_mono    = make_font(13, FW_NORMAL,   "Consolas");
}

static void destroy_fonts(AppState *a)
{
    HFONT *fonts[] = {
        &a->font_brand, &a->font_h1, &a->font_section, &a->font_body,
        &a->font_small, &a->font_nav, &a->font_number, &a->font_status,
        &a->font_mono
    };
    for (size_t i = 0; i < sizeof(fonts)/sizeof(fonts[0]); ++i) {
        if (*fonts[i]) { DeleteObject(*fonts[i]); *fonts[i] = NULL; }
    }
}

/* Ask the DWM to render a dark title bar (Windows 10 1809+ / 11). */
static void enable_dark_titlebar(HWND hwnd)
{
    HMODULE dwm = LoadLibraryA("dwmapi.dll");
    if (!dwm) return;
    typedef HRESULT (WINAPI *SetAttrFn)(HWND, DWORD, LPCVOID, DWORD);
    SetAttrFn set = (SetAttrFn)(void*)GetProcAddress(dwm, "DwmSetWindowAttribute");
    if (set) {
        BOOL dark = TRUE;
        /* 20 = DWMWA_USE_IMMERSIVE_DARK_MODE; 19 on older builds. */
        if (FAILED(set(hwnd, 20, &dark, sizeof(dark))))
            set(hwnd, 19, &dark, sizeof(dark));
    }
    FreeLibrary(dwm);
}

/* ==========================================================================
 *  Window procedure
 * ==========================================================================*/
static AppState *get_app(HWND h)
{
    return (AppState *)GetWindowLongPtrA(h, GWLP_USERDATA);
}

static int nav_hit_test(AppState *app, int mx, int my)
{
    POINT pt = { mx, my };
    for (int i = 0; i < PAGE_COUNT; ++i)
        if (PtInRect(&app->nav_rects[i], pt)) return i;
    return -1;
}

static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    AppState *app = get_app(hwnd);

    switch (msg) {
    case WM_CREATE: {
        app = (AppState *)calloc(1, sizeof(AppState));
        if (!app) return -1;
        app->hwnd            = hwnd;
        app->current_page    = PAGE_DASHBOARD;
        app->hovered_nav     = -1;
        app->hovered_btn     = -1;
        app->last_scan_state = SCAN_IDLE;
        create_fonts(app);
        sysinfo_init(&app->sys);
        scanner_init(&app->scanner, hwnd);
        SetWindowLongPtrA(hwnd, GWLP_USERDATA, (LONG_PTR)app);

        enable_dark_titlebar(hwnd);

        ui_log(app, "Sentinel started");
        ui_log(app, "Host: %s  (%s)", app->sys.hostname, app->sys.arch);
        ui_log(app, "OS:   %s", app->sys.os);
        ui_log(app, "Collected host system information");
        ui_log(app, "Operating in authorized-host mode");
        SetTimer(hwnd, 1, 1000, NULL);   /* live clock + metrics refresh */
        return 0;
    }

    case WM_TIMER:
        if (!app) return 0;
        if (wp == 1) {                       /* 1 Hz: clock + host metrics */
            sysinfo_refresh(&app->sys);
            InvalidateRect(hwnd, NULL, FALSE);
        } else if (wp == 2) {                /* ~30 Hz while scanning */
            scan_check_transition(app);
            RECT rc = content_rect(hwnd);
            InvalidateRect(hwnd, &rc, FALSE);
            if (scanner_state(&app->scanner) != SCAN_RUNNING)
                KillTimer(hwnd, 2);          /* self-stop when scan ends */
        }
        return 0;

    case WM_SCAN_PROGRESS: {
        if (!app) return 0;
        scan_check_transition(app);
        RECT rc = content_rect(hwnd);
        InvalidateRect(hwnd, &rc, FALSE);
        return 0;
    }

    case WM_ERASEBKGND:
        return 1;                            /* handled in WM_PAINT */

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc; GetClientRect(hwnd, &rc);

        HDC     mem  = CreateCompatibleDC(hdc);
        HBITMAP bmp  = CreateCompatibleBitmap(hdc, rc.right, rc.bottom);
        HBITMAP obmp = (HBITMAP)SelectObject(mem, bmp);

        if (app) paint_all(app, mem, rc);
        BitBlt(hdc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);

        SelectObject(mem, obmp);
        DeleteObject(bmp);
        DeleteDC(mem);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_MOUSEMOVE: {
        if (!app) break;
        int mx = GET_X_LPARAM(lp), my = GET_Y_LPARAM(lp);
        app->mouse.x = mx; app->mouse.y = my;

        int hov = nav_hit_test(app, mx, my);
        POINT pt = { mx, my };
        int hbtn = -1;
        if (app->current_page == PAGE_SCAN) {
            if (PtInRect(&app->scan_btn_browse, pt))      hbtn = 0;
            else if (PtInRect(&app->scan_btn_action, pt)) hbtn = 1;
        }
        if (hov != app->hovered_nav || hbtn != app->hovered_btn) {
            app->hovered_nav = hov;
            app->hovered_btn = hbtn;
            InvalidateRect(hwnd, NULL, FALSE);
        }
        TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hwnd, 0 };
        TrackMouseEvent(&tme);
        return 0;
    }

    case WM_MOUSELEAVE:
        if (app && (app->hovered_nav != -1 || app->hovered_btn != -1)) {
            app->hovered_nav = -1;
            app->hovered_btn = -1;
            InvalidateRect(hwnd, NULL, FALSE);
        }
        return 0;

    case WM_SETCURSOR:
        if (app && LOWORD(lp) == HTCLIENT &&
            (app->hovered_nav >= 0 || app->hovered_btn >= 0)) {
            SetCursor(LoadCursorA(NULL, IDC_HAND));
            return TRUE;
        }
        break;

    case WM_LBUTTONDOWN: {
        if (!app) break;
        int mx = GET_X_LPARAM(lp), my = GET_Y_LPARAM(lp);
        POINT pt = { mx, my };

        int hit = nav_hit_test(app, mx, my);
        if (hit >= 0 && hit != (int)app->current_page) {
            app->current_page = (PageId)hit;
            ui_log(app, "Opened %s view", g_nav_labels[hit]);
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }

        if (app->current_page == PAGE_SCAN) {
            BOOL running = (scanner_state(&app->scanner) == SCAN_RUNNING);

            if (!running && PtInRect(&app->scan_btn_browse, pt)) {
                char picked[MAX_PATH];
                if (browse_for_folder(hwnd, picked, sizeof(picked))) {
                    EnterCriticalSection(&app->scanner.cs);
                    copy_str(app->scanner.target, sizeof(app->scanner.target), picked);
                    LeaveCriticalSection(&app->scanner.cs);
                    ui_log(app, "Scan target set: %s", picked);
                    InvalidateRect(hwnd, NULL, FALSE);
                }
            } else if (PtInRect(&app->scan_btn_action, pt)) {
                if (running) {
                    scanner_stop(&app->scanner);
                } else {
                    char target[MAX_PATH];
                    EnterCriticalSection(&app->scanner.cs);
                    copy_str(target, sizeof(target), app->scanner.target);
                    LeaveCriticalSection(&app->scanner.cs);

                    if (scanner_start(&app->scanner, target)) {
                        app->last_scan_state = SCAN_RUNNING;
                        ui_log(app, "Scan started: %s", target);
                        SetTimer(hwnd, 2, 33, NULL);   /* animate progress */
                        InvalidateRect(hwnd, NULL, FALSE);
                    }
                }
            }
        }
        return 0;
    }

    case WM_GETMINMAXINFO: {
        MINMAXINFO *mmi = (MINMAXINFO *)lp;
        mmi->ptMinTrackSize.x = 1000;
        mmi->ptMinTrackSize.y = 640;
        return 0;
    }

    case WM_DESTROY:
        if (app) {
            KillTimer(hwnd, 1);
            KillTimer(hwnd, 2);
            scanner_destroy(&app->scanner);   /* stops + joins worker thread */
            destroy_fonts(app);
            free(app);
            SetWindowLongPtrA(hwnd, GWLP_USERDATA, 0);
        }
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcA(hwnd, msg, wp, lp);
}

/* ==========================================================================
 *  Public API
 * ==========================================================================*/
ATOM ui_register_class(HINSTANCE hInst)
{
    WNDCLASSEXA wc = { 0 };
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = wnd_proc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursorA(NULL, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(COL_BG_CONTENT);
    wc.lpszClassName = g_class_name;
    wc.hIcon         = LoadIconA(NULL, IDI_APPLICATION);
    wc.hIconSm       = LoadIconA(NULL, IDI_APPLICATION);
    return RegisterClassExA(&wc);
}

HWND ui_create_main_window(HINSTANCE hInst, int nCmdShow)
{
    const int W = 1200, H = 780;
    int sx = GetSystemMetrics(SM_CXSCREEN);
    int sy = GetSystemMetrics(SM_CYSCREEN);
    int x  = (sx - W) / 2;
    int y  = (sy - H) / 2;
    if (x < 0) x = 0;
    if (y < 0) y = 0;

    HWND hwnd = CreateWindowExA(
        0, g_class_name, "Sentinel  -  Security Research Platform",
        WS_OVERLAPPEDWINDOW,
        x, y, W, H,
        NULL, NULL, hInst, NULL);

    if (hwnd) {
        ShowWindow(hwnd, nCmdShow);
        UpdateWindow(hwnd);
    }
    return hwnd;
}
