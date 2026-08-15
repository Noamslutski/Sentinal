/* ============================================================================
 *  Sentinel - theme.h
 *  Central palette and layout constants for the UI shell.
 *
 *  Keeping every colour and metric in one place means the whole look of the
 *  application can be re-skinned from here, and later stages can reuse the
 *  same tokens instead of hard-coding colours all over the codebase.
 * ==========================================================================*/
#ifndef SENTINEL_THEME_H
#define SENTINEL_THEME_H

#include <windows.h>

/* ---- Surfaces ---------------------------------------------------------- */
#define COL_BG_CONTENT   RGB( 13,  17,  23)   /* main content background      */
#define COL_BG_SIDEBAR   RGB( 11,  15,  20)   /* navigation rail              */
#define COL_BG_HEADER    RGB( 16,  21,  28)   /* top bar                      */
#define COL_PANEL        RGB( 22,  27,  34)   /* cards / panels               */
#define COL_PANEL_ALT    RGB( 26,  32,  41)   /* raised chips inside panels   */
#define COL_BORDER       RGB( 45,  51,  60)   /* panel outlines               */
#define COL_SEP          RGB( 28,  34,  42)   /* faint row separators         */
#define COL_NAV_HOVER    RGB( 21,  27,  35)   /* nav item hover fill          */
#define COL_NAV_ACTIVE   RGB( 18,  30,  33)   /* nav item selected fill       */

/* ---- Accent ------------------------------------------------------------ */
#define COL_ACCENT       RGB( 45, 212, 191)   /* Sentinel teal                */
#define COL_ACCENT_DIM   RGB( 24,  70,  66)

/* ---- Text -------------------------------------------------------------- */
#define COL_TEXT         RGB(230, 237, 243)   /* primary                      */
#define COL_TEXT_MUTED   RGB(139, 148, 158)   /* secondary                    */
#define COL_TEXT_FAINT   RGB( 92, 101, 112)   /* captions / placeholders      */

/* ---- Status / severity ------------------------------------------------- */
#define COL_ONLINE       RGB( 63, 185,  80)
#define COL_ONLINE_DIM   RGB( 26,  62,  38)
#define COL_CRITICAL     RGB(248,  81,  73)
#define COL_HIGH         RGB(240, 136,  62)
#define COL_MEDIUM       RGB(216, 168,  38)
#define COL_LOW          RGB( 63, 185,  80)

/* ---- Layout metrics ---------------------------------------------------- */
#define HEADER_H         58
#define SIDEBAR_W        224
#define PAD              24
#define NAV_ITEM_H       46

#endif /* SENTINEL_THEME_H */
