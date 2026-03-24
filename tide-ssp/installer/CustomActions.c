/*
 * WiX Custom Actions for TideSSP installer.
 *
 * Handles appending/removing "TideSSP" from the REG_MULTI_SZ
 * SecurityPackages value under HKLM\SYSTEM\CurrentControlSet\Control\Lsa,
 * writing the TideCloak config JSON to registry,
 * and cleaning up UF_MNS_LOGON_ACCOUNT flags on uninstall.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <msi.h>
#include <msiquery.h>
#include <lm.h>
#include <commdlg.h>
#include <strsafe.h>
#include <stdio.h>

#pragma comment(lib, "msi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "comdlg32.lib")

#define LSA_KEY L"SYSTEM\\CurrentControlSet\\Control\\Lsa"
#define MSV1_0_KEY L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0"
#define PACKAGE_NAME L"TideSSP"
#define SUBAUTH_NAME L"TideSubAuth"

/* ---------- helpers ---------- */

/* Return total byte size of a REG_MULTI_SZ buffer (including double-null). */
static DWORD MultiSzSize(const WCHAR *msz)
{
    const WCHAR *p = msz;
    while (*p)
        p += wcslen(p) + 1;
    return (DWORD)((p - msz + 1) * sizeof(WCHAR));
}

/* Check if a string exists in a REG_MULTI_SZ. */
static BOOL MultiSzContains(const WCHAR *msz, const WCHAR *target)
{
    const WCHAR *p = msz;
    while (*p) {
        if (_wcsicmp(p, target) == 0)
            return TRUE;
        p += wcslen(p) + 1;
    }
    return FALSE;
}

/* ---------- install actions ---------- */

UINT __stdcall RegisterSecurityPackage(MSIHANDLE hInstall)
{
    (void)hInstall;
    HKEY hKey = NULL;
    DWORD cbData = 0;
    WCHAR *msz = NULL;
    UINT ret = ERROR_SUCCESS;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, LSA_KEY, 0,
                      KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
        return ERROR_INSTALL_FAILURE;

    /* Read current SecurityPackages */
    DWORD type = 0;
    RegQueryValueExW(hKey, L"Security Packages", NULL, &type, NULL, &cbData);
    if (cbData == 0)
        cbData = 2; /* empty multi-sz: just double-null */

    /* Allocate enough for existing + new entry */
    DWORD extraBytes = (DWORD)((wcslen(PACKAGE_NAME) + 1) * sizeof(WCHAR));
    msz = (WCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbData + extraBytes);
    if (!msz) { ret = ERROR_INSTALL_FAILURE; goto done; }

    RegQueryValueExW(hKey, L"Security Packages", NULL, NULL, (BYTE *)msz, &cbData);

    if (!MultiSzContains(msz, PACKAGE_NAME)) {
        /* Append: find the double-null terminator and insert before it */
        WCHAR *end = msz;
        while (*end)
            end += wcslen(end) + 1;
        /* end now points to the final '\0' of the double-null */
        StringCchCopyW(end, wcslen(PACKAGE_NAME) + 1, PACKAGE_NAME);
        DWORD newSize = MultiSzSize(msz);
        RegSetValueExW(hKey, L"Security Packages", 0, REG_MULTI_SZ,
                       (BYTE *)msz, newSize);
    }

done:
    if (msz) HeapFree(GetProcessHeap(), 0, msz);
    if (hKey) RegCloseKey(hKey);
    return ret;
}

UINT __stdcall RegisterSubAuth(MSIHANDLE hInstall)
{
    (void)hInstall;
    HKEY hKey = NULL;
    DWORD disp = 0;

    /* Register TideSubAuth as MSV1_0 SubAuth package */
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, MSV1_0_KEY, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_WOW64_64KEY, NULL,
                        &hKey, &disp) != ERROR_SUCCESS)
        return ERROR_INSTALL_FAILURE;

    RegSetValueExW(hKey, L"Auth0", 0, REG_SZ,
                   (BYTE *)SUBAUTH_NAME, (DWORD)((wcslen(SUBAUTH_NAME) + 1) * sizeof(WCHAR)));
    RegCloseKey(hKey);

    /* Enable Restricted Admin mode (required for passwordless RDP via TideSSP) */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, LSA_KEY, 0,
                      KEY_WRITE | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        DWORD val = 0;
        RegSetValueExW(hKey, L"DisableRestrictedAdmin", 0, REG_DWORD,
                       (BYTE *)&val, sizeof(val));
        RegCloseKey(hKey);
    }

    return ERROR_SUCCESS;
}

/* ---------- uninstall actions ---------- */

UINT __stdcall UnregisterSecurityPackage(MSIHANDLE hInstall)
{
    (void)hInstall;
    HKEY hKey = NULL;
    DWORD cbData = 0;
    WCHAR *msz = NULL, *out = NULL;
    UINT ret = ERROR_SUCCESS;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, LSA_KEY, 0,
                      KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
        return ERROR_SUCCESS; /* nothing to undo */

    DWORD type = 0;
    RegQueryValueExW(hKey, L"Security Packages", NULL, &type, NULL, &cbData);
    if (cbData == 0) goto done;

    msz = (WCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbData);
    out = (WCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbData);
    if (!msz || !out) goto done;

    RegQueryValueExW(hKey, L"Security Packages", NULL, NULL, (BYTE *)msz, &cbData);

    /* Rebuild without TideSSP */
    WCHAR *src = msz;
    WCHAR *dst = out;
    while (*src) {
        DWORD len = (DWORD)wcslen(src);
        if (_wcsicmp(src, PACKAGE_NAME) != 0) {
            StringCchCopyW(dst, len + 1, src);
            dst += len + 1;
        }
        src += len + 1;
    }
    *dst = L'\0'; /* double-null terminate */

    DWORD newSize = MultiSzSize(out);
    RegSetValueExW(hKey, L"Security Packages", 0, REG_MULTI_SZ,
                   (BYTE *)out, newSize);

done:
    if (msz) HeapFree(GetProcessHeap(), 0, msz);
    if (out) HeapFree(GetProcessHeap(), 0, out);
    if (hKey) RegCloseKey(hKey);
    return ret;
}

UINT __stdcall UnregisterSubAuth(MSIHANDLE hInstall)
{
    (void)hInstall;
    HKEY hKey = NULL;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, MSV1_0_KEY, 0,
                      KEY_WRITE | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, L"Auth0");
        RegCloseKey(hKey);
    }

    /* Restore DisableRestrictedAdmin to default (disabled) */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, LSA_KEY, 0,
                      KEY_WRITE | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, L"DisableRestrictedAdmin");
        RegCloseKey(hKey);
    }
    return ERROR_SUCCESS;
}

UINT __stdcall ClearMnsFlags(MSIHANDLE hInstall)
{
    (void)hInstall;
    /* Clear UF_MNS_LOGON_ACCOUNT (0x20000) from all local users */
    LPUSER_INFO_1 pBuf = NULL;
    DWORD entriesRead = 0, totalEntries = 0;

    if (NetUserEnum(NULL, 1, FILTER_NORMAL_ACCOUNT,
                    (LPBYTE *)&pBuf, MAX_PREFERRED_LENGTH,
                    &entriesRead, &totalEntries, NULL) == NERR_Success && pBuf) {
        for (DWORD i = 0; i < entriesRead; i++) {
            if (pBuf[i].usri1_flags & UF_MNS_LOGON_ACCOUNT) {
                USER_INFO_1008 flagInfo;
                flagInfo.usri1008_flags = pBuf[i].usri1_flags & ~UF_MNS_LOGON_ACCOUNT;
                NetUserSetInfo(NULL, pBuf[i].usri1_name, 1008,
                              (LPBYTE)&flagInfo, NULL);
            }
        }
        NetApiBufferFree(pBuf);
    }
    return ERROR_SUCCESS;
}

/* ---------- TideCloak config actions ---------- */

/* Helper: read a file (UTF-8) into a wide-char buffer. Returns wchar count or 0 on failure. */
static int ReadFileToWide(const WCHAR *filePath, WCHAR *outBuf, int outCapacity)
{
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0 || fileSize > 64000) { CloseHandle(hFile); return 0; }

    char *utf8 = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize + 1);
    if (!utf8) { CloseHandle(hFile); return 0; }

    DWORD bytesRead = 0;
    ReadFile(hFile, utf8, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);
    utf8[bytesRead] = '\0';

    int wLen = MultiByteToWideChar(CP_UTF8, 0, utf8, (int)bytesRead,
                                   outBuf, outCapacity - 1);
    outBuf[wLen] = L'\0';
    HeapFree(GetProcessHeap(), 0, utf8);
    return wLen;
}

/* Helper: validate JSON content (wide string) contains required fields */
static BOOL ValidateJsonContent(const WCHAR *json)
{
    return wcsstr(json, L"\"jwk\"") != NULL && wcsstr(json, L"\"x\"") != NULL;
}

/*
 * BrowseConfig — immediate CA, opens a file dialog to select tidecloak.json.
 * Sets TIDE_CONFIG_FILE property with the selected path.
 */
UINT __stdcall BrowseConfig(MSIHANDLE hInstall)
{
    WCHAR filePath[MAX_PATH] = {0};

    /* Find the MSI dialog window to use as owner */
    HWND hwndOwner = FindWindowW(L"MsiDialogCloseClass", NULL);
    if (!hwndOwner)
        hwndOwner = FindWindowW(L"MsiDialogNoCloseClass", NULL);
    if (!hwndOwner)
        hwndOwner = GetForegroundWindow();

    OPENFILENAMEW ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(OPENFILENAMEW);
    ofn.hwndOwner = hwndOwner;
    ofn.lpstrFilter = L"JSON Files\0*.json\0All Files\0*.*\0";
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Select tidecloak.json";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    ofn.lpstrDefExt = L"json";

    if (GetOpenFileNameW(&ofn)) {
        MsiSetPropertyW(hInstall, L"TIDE_CONFIG_FILE", filePath);
    }

    return ERROR_SUCCESS;
}

/*
 * ValidateConfig — immediate CA, runs during UI sequence.
 * Opens a file browser dialog to select tidecloak.json, then validates it.
 */
UINT __stdcall ValidateConfig(MSIHANDLE hInstall)
{
    WCHAR filePath[MAX_PATH] = {0};
    WCHAR jsonBuf[32768];

    /* Open file browser dialog */
    HWND hwnd = FindWindowW(L"MsiDialogCloseClass", NULL);
    if (!hwnd) hwnd = FindWindowW(L"MsiDialogNoCloseClass", NULL);
    if (!hwnd) hwnd = GetForegroundWindow();

    OPENFILENAMEW ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(OPENFILENAMEW);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = L"JSON Files\0*.json\0All Files\0*.*\0";
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Select tidecloak.json";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    ofn.lpstrDefExt = L"json";

    if (!GetOpenFileNameW(&ofn)) {
        /* User cancelled */
        return ERROR_INSTALL_FAILURE;
    }

    /* Store the selected path */
    MsiSetPropertyW(hInstall, L"TIDE_CONFIG_FILE", filePath);

    /* Read and validate the file */
    int wLen = ReadFileToWide(filePath, jsonBuf, sizeof(jsonBuf) / sizeof(WCHAR));
    if (wLen == 0) {
        MessageBoxW(hwnd,
            L"Cannot read the selected file.",
            L"TideSSP \x2014 File Error", MB_OK | MB_ICONERROR);
        return ERROR_INSTALL_FAILURE;
    }

    if (!ValidateJsonContent(jsonBuf)) {
        MessageBoxW(hwnd,
            L"The selected file does not appear to be a valid TideCloak configuration.\n"
            L"It must contain a \"jwk\" section with an Ed25519 public key.\n\n"
            L"Export from TideCloak Admin Console:\n"
            L"Clients \x2192 your client \x2192 Action dropdown \x2192 Download adapter config.",
            L"TideSSP \x2014 Invalid Configuration", MB_OK | MB_ICONERROR);
        return ERROR_INSTALL_FAILURE;
    }

    return ERROR_SUCCESS;
}

/*
 * CopyConfig — deferred CA.
 * CustomActionData format: "FILE=<path>|JSON=<json content>"
 * Prefers pasted JSON; falls back to copying from file path.
 * Creates %SystemRoot%\System32\tidecloak.json.
 */
UINT __stdcall CopyConfig(MSIHANDLE hInstall)
{
    WCHAR customData[32768];
    DWORD dataLen = sizeof(customData) / sizeof(WCHAR);

    if (MsiGetPropertyW(hInstall, L"CustomActionData", customData, &dataLen) != ERROR_SUCCESS
        || dataLen == 0)
        return ERROR_INSTALL_FAILURE;

    /* Build destination path: System32\tidecloak.json */
    WCHAR destPath[MAX_PATH];
    UINT sysLen = GetSystemDirectoryW(destPath, MAX_PATH);
    if (sysLen == 0 || sysLen >= MAX_PATH - 20) return ERROR_INSTALL_FAILURE;
    wcscat_s(destPath, MAX_PATH, L"\\tidecloak.json");

    /* Try pasted JSON first */
    WCHAR *jsonMarker = wcsstr(customData, L"|JSON=");
    if (jsonMarker) {
        WCHAR *jsonStart = jsonMarker + 6;
        DWORD jsonChars = (DWORD)wcslen(jsonStart);
        if (jsonChars > 10) {
            /* Convert UTF-16 to UTF-8 and write */
            int utf8Len = WideCharToMultiByte(CP_UTF8, 0, jsonStart, (int)jsonChars, NULL, 0, NULL, NULL);
            if (utf8Len > 0) {
                char *utf8 = (char *)HeapAlloc(GetProcessHeap(), 0, utf8Len);
                if (utf8) {
                    WideCharToMultiByte(CP_UTF8, 0, jsonStart, (int)jsonChars, utf8, utf8Len, NULL, NULL);
                    HANDLE hFile = CreateFileW(destPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
                    if (hFile != INVALID_HANDLE_VALUE) {
                        DWORD written = 0;
                        WriteFile(hFile, utf8, (DWORD)utf8Len, &written, NULL);
                        CloseHandle(hFile);
                        HeapFree(GetProcessHeap(), 0, utf8);
                        return ERROR_SUCCESS;
                    }
                    HeapFree(GetProcessHeap(), 0, utf8);
                }
            }
        }
    }

    /* Fall back to copying from file path */
    WCHAR *fileStart = wcsstr(customData, L"FILE=");
    if (fileStart) {
        fileStart += 5;
        WCHAR srcPath[MAX_PATH];
        WCHAR *pipePos = wcschr(fileStart, L'|');
        DWORD pathChars = pipePos ? (DWORD)(pipePos - fileStart) : (DWORD)wcslen(fileStart);
        if (pathChars > 0 && pathChars < MAX_PATH) {
            wcsncpy_s(srcPath, MAX_PATH, fileStart, pathChars);
            srcPath[pathChars] = L'\0';
            if (CopyFileW(srcPath, destPath, FALSE))
                return ERROR_SUCCESS;
        }
    }

    /* If no config provided but file already exists (repair), succeed silently */
    {
        DWORD attr = GetFileAttributesW(destPath);
        if (attr != INVALID_FILE_ATTRIBUTES)
            return ERROR_SUCCESS;
    }

    return ERROR_INSTALL_FAILURE;
}

/* RemoveConfig — delete tidecloak.json from System32 on uninstall */
UINT __stdcall RemoveConfig(MSIHANDLE hInstall)
{
    (void)hInstall;
    WCHAR path[MAX_PATH];
    UINT sysLen = GetSystemDirectoryW(path, MAX_PATH);
    if (sysLen > 0 && sysLen < MAX_PATH - 20) {
        wcscat_s(path, MAX_PATH, L"\\tidecloak.json");
        DeleteFileW(path);
    }
    return ERROR_SUCCESS;
}
