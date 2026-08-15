/* ============================================================================
 *  Sentinel - scanner/scanner.c
 *  Worker-thread recursive filesystem scanner with SHA-256 (Windows CNG).
 * ==========================================================================*/
#include "scanner.h"

#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- small helpers ----------------------------------------------------- */

static ULONGLONG now_ms(void) { return GetTickCount64(); }

/* Bounded, always-null-terminating copy (avoids strncpy truncation warnings). */
static void copy_str(char *dst, size_t dstsz, const char *src)
{
    if (dstsz == 0) return;
    size_t i = 0;
    for (; i + 1 < dstsz && src[i]; ++i) dst[i] = src[i];
    dst[i] = '\0';
}

static void to_lower(char *s)
{
    for (; *s; ++s)
        if (*s >= 'A' && *s <= 'Z') *s = (char)(*s + 32);
}

static void bytes_to_hex(const unsigned char *in, int n, char *out)
{
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < n; ++i) {
        out[i*2]   = H[(in[i] >> 4) & 0xF];
        out[i*2+1] = H[in[i] & 0xF];
    }
    out[n*2] = '\0';
}

static BOOL ext_is_executable(const char *ext)
{
    static const char *E[] = { "exe","dll","sys","scr","com","cpl",
                               "ocx","drv","efi",0 };
    for (int i = 0; E[i]; ++i) if (strcmp(ext, E[i]) == 0) return TRUE;
    return FALSE;
}

/* Classify a file by leading magic bytes, falling back to text/binary. */
static void classify(const char *path, const char *ext,
                     char *type, size_t tn, BOOL *is_exec)
{
    unsigned char b[16] = {0};
    DWORD got = 0;
    HANDLE h = CreateFileA(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        ReadFile(h, b, sizeof(b), &got, NULL);
        CloseHandle(h);
    }

    *is_exec = ext_is_executable(ext);

    #define M(n, ...) (got >= (n) && memcmp(b, (const unsigned char[]){__VA_ARGS__}, (n)) == 0)
    if (M(2, 'M','Z'))                          { strncpy(type,"PE image",tn);  *is_exec = TRUE; return; }
    if (M(4, 0x7F,'E','L','F'))                 { strncpy(type,"ELF",tn);        return; }
    if (M(4, 'P','K',0x03,0x04))                { strncpy(type,"ZIP/Office",tn); return; }
    if (M(4, 0x25,'P','D','F'))                 { strncpy(type,"PDF",tn);        return; }
    if (M(8, 0x89,'P','N','G',0x0D,0x0A,0x1A,0x0A)){ strncpy(type,"PNG",tn);     return; }
    if (M(3, 0xFF,0xD8,0xFF))                   { strncpy(type,"JPEG",tn);       return; }
    if (M(4, 'G','I','F','8'))                  { strncpy(type,"GIF",tn);        return; }
    if (M(2, 0x1F,0x8B))                        { strncpy(type,"GZIP",tn);       return; }
    if (M(4, 'R','a','r','!'))                  { strncpy(type,"RAR",tn);        return; }
    if (M(4, '%','!','P','S'))                  { strncpy(type,"PostScript",tn); return; }
    #undef M

    if (*is_exec) { strncpy(type, "Executable", tn); return; }

    /* Fallback: mostly-printable leading bytes => Text, else Binary. */
    if (got > 0) {
        int printable = 0;
        for (DWORD i = 0; i < got; ++i) {
            unsigned char c = b[i];
            if (c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c < 0x7F))
                printable++;
        }
        strncpy(type, (printable * 100 / (int)got >= 85) ? "Text" : "Binary", tn);
    } else {
        strncpy(type, "Empty", tn);
    }
    type[tn-1] = '\0';
}

/* SHA-256 a file into out_hex (65 chars). Returns FALSE on read/hash error. */
static BOOL sha256_file(BCRYPT_ALG_HANDLE alg, const char *path, char *out_hex)
{
    HANDLE h = CreateFileA(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;

    BCRYPT_HASH_HANDLE hash = NULL;
    if (BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0) != 0) {
        CloseHandle(h);
        return FALSE;
    }

    BOOL ok = TRUE;
    unsigned char *buf = (unsigned char *)malloc(65536);
    if (!buf) { BCryptDestroyHash(hash); CloseHandle(h); return FALSE; }

    DWORD got = 0;
    while (ReadFile(h, buf, 65536, &got, NULL) && got > 0) {
        if (BCryptHashData(hash, buf, got, 0) != 0) { ok = FALSE; break; }
    }
    free(buf);
    CloseHandle(h);

    if (ok) {
        unsigned char digest[32];
        if (BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0)
            bytes_to_hex(digest, 32, out_hex);
        else
            ok = FALSE;
    }
    BCryptDestroyHash(hash);
    return ok;
}

/* ---- shared-state mutation (all under cs) ------------------------------ */

static void set_current_dir(Scanner *sc, const char *dir)
{
    EnterCriticalSection(&sc->cs);
    copy_str(sc->current_dir, sizeof(sc->current_dir), dir);
    LeaveCriticalSection(&sc->cs);
}

static void push_file(Scanner *sc, const FileRecord *r)
{
    EnterCriticalSection(&sc->cs);
    sc->files++;
    sc->bytes += r->size;
    if (r->is_executable) sc->executables++;
    sc->recent[sc->recent_total % SCAN_RECENT] = *r;
    sc->recent_total++;
    ULONGLONG n = sc->files;
    LeaveCriticalSection(&sc->cs);

    if ((n & 63) == 0 && sc->notify_hwnd)      /* throttle repaints */
        PostMessageA(sc->notify_hwnd, WM_SCAN_PROGRESS, 0, 0);
}

/* ---- record building --------------------------------------------------- */

static void build_record(FileRecord *r, const char *full,
                         const WIN32_FIND_DATAA *fd, BCRYPT_ALG_HANDLE alg)
{
    memset(r, 0, sizeof(*r));
    copy_str(r->path, sizeof(r->path), full);
    copy_str(r->name, sizeof(r->name), fd->cFileName);

    ULARGE_INTEGER sz;
    sz.LowPart  = fd->nFileSizeLow;
    sz.HighPart = fd->nFileSizeHigh;
    r->size = sz.QuadPart;

    r->created  = fd->ftCreationTime;
    r->modified = fd->ftLastWriteTime;
    r->attrs    = fd->dwFileAttributes;

    const char *dot = strrchr(fd->cFileName, '.');
    if (dot && dot != fd->cFileName && dot[1]) {
        copy_str(r->ext, sizeof(r->ext), dot + 1);
        to_lower(r->ext);
    }

    classify(full, r->ext, r->type, sizeof(r->type), &r->is_executable);

    if (r->size > SCAN_HASH_CAP_BYTES)
        strncpy(r->sha256, "(not hashed: large file)", sizeof(r->sha256) - 1);
    else if (!sha256_file(alg, full, r->sha256))
        strncpy(r->sha256, "(unreadable)", sizeof(r->sha256) - 1);
}

/* ---- recursive walk ---------------------------------------------------- */

static void walk(Scanner *sc, BCRYPT_ALG_HANDLE alg, const char *dir)
{
    if (sc->cancel) return;
    set_current_dir(sc, dir);

    char pattern[MAX_PATH];
    if (_snprintf(pattern, sizeof(pattern), "%s\\*", dir) < 0) return;

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        EnterCriticalSection(&sc->cs); sc->errors++; LeaveCriticalSection(&sc->cs);
        return;
    }

    do {
        if (sc->cancel) break;
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;

        char full[MAX_PATH];
        if (_snprintf(full, sizeof(full), "%s\\%s", dir, fd.cFileName) < 0)
            continue;                     /* path too long: skip */

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
                continue;                 /* don't follow junctions/symlinks */
            EnterCriticalSection(&sc->cs); sc->dirs++; LeaveCriticalSection(&sc->cs);
            walk(sc, alg, full);
        } else {
            FileRecord r;
            build_record(&r, full, &fd, alg);
            push_file(sc, &r);
        }
    } while (FindNextFileA(h, &fd));

    FindClose(h);
}

static DWORD WINAPI scan_thread(LPVOID param)
{
    Scanner *sc = (Scanner *)param;

    BCRYPT_ALG_HANDLE alg = NULL;
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);

    char target[MAX_PATH];
    EnterCriticalSection(&sc->cs);
    copy_str(target, sizeof(target), sc->target);
    LeaveCriticalSection(&sc->cs);

    walk(sc, alg, target);

    if (alg) BCryptCloseAlgorithmProvider(alg, 0);

    sc->ended_ms = now_ms();
    InterlockedExchange(&sc->state, sc->cancel ? SCAN_STOPPED : SCAN_DONE);
    if (sc->notify_hwnd)
        PostMessageA(sc->notify_hwnd, WM_SCAN_PROGRESS, 0, 0);
    return 0;
}

/* ---- public API -------------------------------------------------------- */

void scanner_init(Scanner *sc, HWND notify)
{
    memset(sc, 0, sizeof(*sc));
    InitializeCriticalSection(&sc->cs);
    sc->notify_hwnd = notify;
    sc->state = SCAN_IDLE;
    GetCurrentDirectoryA(sizeof(sc->target), sc->target);
}

void scanner_destroy(Scanner *sc)
{
    InterlockedExchange(&sc->cancel, 1);
    if (sc->thread) {
        WaitForSingleObject(sc->thread, INFINITE);
        CloseHandle(sc->thread);
        sc->thread = NULL;
    }
    DeleteCriticalSection(&sc->cs);
}

BOOL scanner_start(Scanner *sc, const char *target)
{
    if (scanner_state(sc) == SCAN_RUNNING) return FALSE;

    if (sc->thread) { CloseHandle(sc->thread); sc->thread = NULL; }

    EnterCriticalSection(&sc->cs);
    copy_str(sc->target, sizeof(sc->target), target);
    sc->current_dir[0] = '\0';
    sc->files = sc->dirs = sc->executables = sc->bytes = sc->errors = 0;
    sc->recent_total = 0;
    LeaveCriticalSection(&sc->cs);

    InterlockedExchange(&sc->cancel, 0);
    sc->started_ms = now_ms();
    sc->ended_ms   = 0;
    InterlockedExchange(&sc->state, SCAN_RUNNING);

    sc->thread = CreateThread(NULL, 0, scan_thread, sc, 0, NULL);
    if (!sc->thread) {
        InterlockedExchange(&sc->state, SCAN_IDLE);
        return FALSE;
    }
    return TRUE;
}

void scanner_stop(Scanner *sc)
{
    if (scanner_state(sc) == SCAN_RUNNING)
        InterlockedExchange(&sc->cancel, 1);
}

ScanState scanner_state(Scanner *sc)
{
    return (ScanState)InterlockedCompareExchange(&sc->state, 0, 0);
}

void scanner_snapshot(Scanner *sc, ScanSnapshot *out)
{
    memset(out, 0, sizeof(*out));
    out->state = scanner_state(sc);

    EnterCriticalSection(&sc->cs);
    copy_str(out->target, sizeof(out->target), sc->target);
    copy_str(out->current_dir, sizeof(out->current_dir), sc->current_dir);
    out->files       = sc->files;
    out->dirs        = sc->dirs;
    out->executables = sc->executables;
    out->bytes       = sc->bytes;
    out->errors      = sc->errors;
    out->started_ms  = sc->started_ms;
    out->ended_ms    = sc->ended_ms;

    ULONGLONG total = sc->recent_total;
    int n = (total < SCAN_RECENT) ? (int)total : SCAN_RECENT;
    for (int k = 0; k < n; ++k) {
        /* most-recent first */
        ULONGLONG idx = (total - 1 - (ULONGLONG)k) % SCAN_RECENT;
        out->recent[k] = sc->recent[idx];
    }
    out->recent_n = n;
    LeaveCriticalSection(&sc->cs);
}
