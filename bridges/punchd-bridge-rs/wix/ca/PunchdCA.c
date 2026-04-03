/*
 * WiX Custom Actions for Punchd VPN installer.
 * Handles browsing for vpn-config.toml and copying it to ProgramData.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <msi.h>
#include <msiquery.h>
#include <commdlg.h>
#include <strsafe.h>
#include <shlobj.h>

#pragma comment(lib, "msi.lib")
#pragma comment(lib, "shell32.lib")

typedef BOOL (WINAPI *PFN_GetOpenFileNameW)(LPOPENFILENAMEW);

static BOOL DynGetOpenFileNameW(LPOPENFILENAMEW pOfn)
{
    HMODULE hMod = LoadLibraryW(L"comdlg32.dll");
    if (!hMod) return FALSE;
    PFN_GetOpenFileNameW pfn = (PFN_GetOpenFileNameW)GetProcAddress(hMod, "GetOpenFileNameW");
    if (!pfn) { FreeLibrary(hMod); return FALSE; }
    BOOL result = pfn(pOfn);
    FreeLibrary(hMod);
    return result;
}

#define CONFIG_DIR L"punchd-vpn"
#define CONFIG_FILE L"vpn-config.toml"

/* Helper: validate TOML content has required fields */
static BOOL ValidateTomlContent(const char *content, DWORD len)
{
    /* Check for stun_server and gateway_id */
    return len > 10
        && strstr(content, "stun_server") != NULL
        && strstr(content, "gateway_id") != NULL;
}

/*
 * BrowseAndValidateConfig — immediate CA.
 * Opens a file dialog, validates the TOML, sets VPN_CONFIG_FILE property.
 */
UINT __stdcall BrowseAndValidateConfig(MSIHANDLE hInstall)
{
    WCHAR filePath[MAX_PATH] = {0};

    HWND hwnd = FindWindowW(L"MsiDialogCloseClass", NULL);
    if (!hwnd) hwnd = FindWindowW(L"MsiDialogNoCloseClass", NULL);
    if (!hwnd) hwnd = GetForegroundWindow();

    OPENFILENAMEW ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(OPENFILENAMEW);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = L"TOML Config\0*.toml\0All Files\0*.*\0";
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Select vpn-config.toml";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    ofn.lpstrDefExt = L"toml";

    if (!DynGetOpenFileNameW(&ofn)) {
        return ERROR_INSTALL_FAILURE; /* User cancelled */
    }

    /* Read and validate */
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        MessageBoxW(hwnd, L"Cannot read the selected file.",
                    L"Punchd VPN - File Error", MB_OK | MB_ICONERROR);
        return ERROR_INSTALL_FAILURE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0 || fileSize > 64000) {
        CloseHandle(hFile);
        MessageBoxW(hwnd, L"File is empty or too large.",
                    L"Punchd VPN - File Error", MB_OK | MB_ICONERROR);
        return ERROR_INSTALL_FAILURE;
    }

    char *content = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize + 1);
    DWORD bytesRead = 0;
    ReadFile(hFile, content, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);
    content[bytesRead] = '\0';

    if (!ValidateTomlContent(content, bytesRead)) {
        HeapFree(GetProcessHeap(), 0, content);
        MessageBoxW(hwnd,
            L"The selected file is not a valid VPN config.\n"
            L"It must contain 'stun_server' and 'gateway_id' fields.\n\n"
            L"Download from KeyleSSH: Admin > Gateways > Download VPN Config",
            L"Punchd VPN - Invalid Configuration", MB_OK | MB_ICONERROR);
        return ERROR_INSTALL_FAILURE;
    }

    HeapFree(GetProcessHeap(), 0, content);
    MsiSetPropertyW(hInstall, L"VPN_CONFIG_FILE", filePath);
    return ERROR_SUCCESS;
}

/*
 * CopyConfig — deferred CA.
 * Copies vpn-config.toml to C:\ProgramData\punchd-vpn\
 */
UINT __stdcall CopyConfig(MSIHANDLE hInstall)
{
    WCHAR customData[MAX_PATH * 2];
    DWORD dataLen = sizeof(customData) / sizeof(WCHAR);

    if (MsiGetPropertyW(hInstall, L"CustomActionData", customData, &dataLen) != ERROR_SUCCESS
        || dataLen == 0)
        return ERROR_SUCCESS; /* No config file — skip silently */

    /* Build dest: C:\ProgramData\punchd-vpn\vpn-config.toml */
    WCHAR destDir[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, destDir)))
        return ERROR_INSTALL_FAILURE;

    StringCchCatW(destDir, MAX_PATH, L"\\" CONFIG_DIR);
    CreateDirectoryW(destDir, NULL);

    WCHAR destPath[MAX_PATH];
    StringCchCopyW(destPath, MAX_PATH, destDir);
    StringCchCatW(destPath, MAX_PATH, L"\\" CONFIG_FILE);

    if (!CopyFileW(customData, destPath, FALSE)) {
        return ERROR_INSTALL_FAILURE;
    }

    return ERROR_SUCCESS;
}

/*
 * RemoveConfig — deferred CA for uninstall.
 */
UINT __stdcall RemoveConfig(MSIHANDLE hInstall)
{
    (void)hInstall;
    WCHAR destDir[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, destDir)))
        return ERROR_SUCCESS;

    StringCchCatW(destDir, MAX_PATH, L"\\" CONFIG_DIR L"\\" CONFIG_FILE);
    DeleteFileW(destDir);
    return ERROR_SUCCESS;
}
