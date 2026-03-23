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
#include <strsafe.h>
#include <stdio.h>

#pragma comment(lib, "msi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")

#define LSA_KEY L"SYSTEM\\CurrentControlSet\\Control\\Lsa"
#define TIDESSP_KEY L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\TideSSP"
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
                      KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS)
        return ERROR_INSTALL_FAILURE;

    /* Read current SecurityPackages */
    DWORD type = 0;
    RegQueryValueExW(hKey, L"SecurityPackages", NULL, &type, NULL, &cbData);
    if (cbData == 0)
        cbData = 2; /* empty multi-sz: just double-null */

    /* Allocate enough for existing + new entry */
    DWORD extraBytes = (DWORD)((wcslen(PACKAGE_NAME) + 1) * sizeof(WCHAR));
    msz = (WCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbData + extraBytes);
    if (!msz) { ret = ERROR_INSTALL_FAILURE; goto done; }

    RegQueryValueExW(hKey, L"SecurityPackages", NULL, NULL, (BYTE *)msz, &cbData);

    if (!MultiSzContains(msz, PACKAGE_NAME)) {
        /* Append: find the double-null terminator and insert before it */
        WCHAR *end = msz;
        while (*end)
            end += wcslen(end) + 1;
        /* end now points to the final '\0' of the double-null */
        StringCchCopyW(end, wcslen(PACKAGE_NAME) + 1, PACKAGE_NAME);
        DWORD newSize = MultiSzSize(msz);
        RegSetValueExW(hKey, L"SecurityPackages", 0, REG_MULTI_SZ,
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

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, MSV1_0_KEY, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL,
                        &hKey, &disp) != ERROR_SUCCESS)
        return ERROR_INSTALL_FAILURE;

    RegSetValueExW(hKey, L"Auth0", 0, REG_SZ,
                   (BYTE *)SUBAUTH_NAME, (DWORD)((wcslen(SUBAUTH_NAME) + 1) * sizeof(WCHAR)));
    RegCloseKey(hKey);
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
                      KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS)
        return ERROR_SUCCESS; /* nothing to undo */

    DWORD type = 0;
    RegQueryValueExW(hKey, L"SecurityPackages", NULL, &type, NULL, &cbData);
    if (cbData == 0) goto done;

    msz = (WCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbData);
    out = (WCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbData);
    if (!msz || !out) goto done;

    RegQueryValueExW(hKey, L"SecurityPackages", NULL, NULL, (BYTE *)msz, &cbData);

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
    RegSetValueExW(hKey, L"SecurityPackages", 0, REG_MULTI_SZ,
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
                      KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, L"Auth0");
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

/*
 * WriteConfig — deferred CA, receives CustomActionData:
 *   "TIDE_CONFIG=<json>;TIDE_CONFIG_FILE=<path>"
 *
 * If TIDE_CONFIG is non-empty, writes it directly.
 * Otherwise reads the file at TIDE_CONFIG_FILE.
 * Stores as REG_SZ at HKLM\...\Lsa\TideSSP\Config.
 */
UINT __stdcall WriteConfig(MSIHANDLE hInstall)
{
    WCHAR customData[32768];
    DWORD dataLen = sizeof(customData) / sizeof(WCHAR);
    HKEY hKey = NULL;
    DWORD disp = 0;
    UINT ret = ERROR_INSTALL_FAILURE;

    if (MsiGetPropertyW(hInstall, L"CustomActionData", customData, &dataLen) != ERROR_SUCCESS)
        return ERROR_INSTALL_FAILURE;

    /* Parse "TIDE_CONFIG=...;TIDE_CONFIG_FILE=..." */
    WCHAR *configJson = NULL;
    DWORD configJsonLen = 0;

    /* Find TIDE_CONFIG= */
    WCHAR *cfgStart = wcsstr(customData, L"TIDE_CONFIG=");
    WCHAR *fileStart = wcsstr(customData, L"TIDE_CONFIG_FILE=");

    /* Extract TIDE_CONFIG value (between "TIDE_CONFIG=" and ";TIDE_CONFIG_FILE=") */
    WCHAR jsonBuf[32768];
    jsonBuf[0] = L'\0';

    if (cfgStart) {
        cfgStart += wcslen(L"TIDE_CONFIG=");
        /* Find the separator before TIDE_CONFIG_FILE */
        WCHAR *sep = wcsstr(cfgStart, L";TIDE_CONFIG_FILE=");
        DWORD copyLen = sep ? (DWORD)(sep - cfgStart) : (DWORD)wcslen(cfgStart);
        if (copyLen > 0 && copyLen < sizeof(jsonBuf)/sizeof(WCHAR)) {
            wcsncpy_s(jsonBuf, sizeof(jsonBuf)/sizeof(WCHAR), cfgStart, copyLen);
            jsonBuf[copyLen] = L'\0';
        }
    }

    /* If no inline config, try reading from file */
    if (jsonBuf[0] == L'\0' && fileStart) {
        WCHAR filePath[MAX_PATH];
        fileStart += wcslen(L"TIDE_CONFIG_FILE=");
        /* File path is the rest of the string (or until next ;) */
        DWORD copyLen = (DWORD)wcslen(fileStart);
        if (copyLen > 0 && copyLen < MAX_PATH) {
            wcsncpy_s(filePath, MAX_PATH, fileStart, copyLen);
            filePath[copyLen] = L'\0';

            /* Trim trailing whitespace/semicolons */
            while (copyLen > 0 && (filePath[copyLen-1] == L';' ||
                   filePath[copyLen-1] == L' ' || filePath[copyLen-1] == L'\0')) {
                filePath[--copyLen] = L'\0';
            }

            /* Read file as UTF-8 and convert to UTF-16 */
            HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ,
                                       NULL, OPEN_EXISTING, 0, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD fileSize = GetFileSize(hFile, NULL);
                if (fileSize > 0 && fileSize < 32000) {
                    char *utf8 = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize + 1);
                    if (utf8) {
                        DWORD bytesRead = 0;
                        ReadFile(hFile, utf8, fileSize, &bytesRead, NULL);
                        utf8[bytesRead] = '\0';

                        /* Convert UTF-8 to UTF-16 */
                        int wLen = MultiByteToWideChar(CP_UTF8, 0, utf8, (int)bytesRead,
                                                       jsonBuf, sizeof(jsonBuf)/sizeof(WCHAR) - 1);
                        jsonBuf[wLen] = L'\0';
                        HeapFree(GetProcessHeap(), 0, utf8);
                    }
                }
                CloseHandle(hFile);
            }
        }
    }

    if (jsonBuf[0] == L'\0')
        return ERROR_INSTALL_FAILURE;

    /* Write to registry */
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, TIDESSP_KEY, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL,
                        &hKey, &disp) != ERROR_SUCCESS)
        return ERROR_INSTALL_FAILURE;

    configJsonLen = (DWORD)((wcslen(jsonBuf) + 1) * sizeof(WCHAR));
    if (RegSetValueExW(hKey, L"Config", 0, REG_SZ,
                       (BYTE *)jsonBuf, configJsonLen) == ERROR_SUCCESS)
        ret = ERROR_SUCCESS;

    RegCloseKey(hKey);
    return ret;
}

/* RemoveConfig — delete the TideSSP registry key on uninstall */
UINT __stdcall RemoveConfig(MSIHANDLE hInstall)
{
    (void)hInstall;
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, TIDESSP_KEY);
    return ERROR_SUCCESS;
}
