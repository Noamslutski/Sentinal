/* ============================================================================
 *  Sentinel - main.c
 *  Application entry point: register the window class, create the main
 *  window, and run the Win32 message loop.
 *
 *  Sentinel is a security-research and host-analysis tool intended ONLY for
 *  systems the operator owns or is explicitly authorized to test.
 * ==========================================================================*/
#include "ui.h"   /* pulls in windows.h with the right WINVER already set */

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    (void)hPrevInstance;
    (void)lpCmdLine;

    /* Crisp rendering on high-DPI displays. */
    SetProcessDPIAware();

    if (!ui_register_class(hInstance)) {
        MessageBoxA(NULL, "Failed to register the Sentinel window class.",
                    "Sentinel", MB_ICONERROR | MB_OK);
        return 1;
    }

    HWND hwnd = ui_create_main_window(hInstance, nCmdShow);
    if (!hwnd) {
        MessageBoxA(NULL, "Failed to create the Sentinel main window.",
                    "Sentinel", MB_ICONERROR | MB_OK);
        return 1;
    }

    /* Standard Win32 message pump. */
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}
