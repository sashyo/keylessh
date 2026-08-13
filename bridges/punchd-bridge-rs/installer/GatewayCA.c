/*
 * WiX custom actions for the Punchd Gateway installer.
 *
 * Lets the installing admin pick gateway.toml and tidecloak.json during setup
 * and copies them into ProgramData, instead of installing and then requiring a
 * manual copy before the service can do anything useful.
 *
 * Both files are optional: an admin who has not generated them yet can install
 * now and add them later, so a cancelled browse is never an install failure.
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

#define CONFIG_DIR      L"punchd-gateway"
#define GATEWAY_TOML    L"gateway.toml"
#define TIDECLOAK_JSON  L"tidecloak.json"

/* Largest config we will accept. tidecloak.json carries a JWK set, so this is
 * generous compared with the few KB either file normally occupies. */
#define MAX_CONFIG_BYTES 262144

typedef BOOL(WINAPI *PFN_GetOpenFileNameW)(LPOPENFILENAMEW);

/* comdlg32 is loaded on demand: msiexec's UI sequence does not need it
 * otherwise, and this keeps the DLL loadable where it is absent. */
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

static HWND InstallerWindow(void)
{
    HWND hwnd = FindWindowW(L"MsiDialogCloseClass", NULL);
    if (!hwnd) hwnd = FindWindowW(L"MsiDialogNoCloseClass", NULL);
    if (!hwnd) hwnd = GetForegroundWindow();
    return hwnd;
}

/* Read a whole file into a NUL-terminated heap buffer. Caller frees. */
static char *ReadWholeFile(const WCHAR *path, DWORD *outLen)
{
    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0 || fileSize > MAX_CONFIG_BYTES) {
        CloseHandle(hFile);
        return NULL;
    }

    char *content = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize + 1);
    if (!content) { CloseHandle(hFile); return NULL; }

    DWORD bytesRead = 0;
    BOOL ok = ReadFile(hFile, content, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);
    if (!ok) {
        HeapFree(GetProcessHeap(), 0, content);
        return NULL;
    }
    content[bytesRead] = '\0';
    if (outLen) *outLen = bytesRead;
    return content;
}

/*
 * Shared browse-and-validate. `mustContainA`/`mustContainB` are substrings the
 * file has to have to be plausibly the right file — enough to catch picking the
 * wrong one of the two, without second-guessing a config the gateway itself
 * will parse properly at startup.
 */
static UINT BrowseForConfig(MSIHANDLE hInstall,
                            const WCHAR *filter,
                            const WCHAR *defExt,
                            const WCHAR *title,
                            const WCHAR *property,
                            const char *mustContainA,
                            const char *mustContainB,
                            const WCHAR *wrongFileMessage)
{
    WCHAR filePath[MAX_PATH] = {0};
    HWND hwnd = InstallerWindow();

    OPENFILENAMEW ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(OPENFILENAMEW);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = title;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    ofn.lpstrDefExt = defExt;

    /* Cancelled: leave the property as it was. Selecting a file is optional, so
     * this is a normal outcome and must not fail the install. */
    if (!DynGetOpenFileNameW(&ofn))
        return ERROR_SUCCESS;

    DWORD len = 0;
    char *content = ReadWholeFile(filePath, &len);
    if (!content) {
        MessageBoxW(hwnd, L"That file could not be read, or is empty or unusually large.",
                    L"Punchd Gateway", MB_OK | MB_ICONERROR);
        return ERROR_SUCCESS;
    }

    BOOL looksRight = (strstr(content, mustContainA) != NULL)
                   && (mustContainB == NULL || strstr(content, mustContainB) != NULL);
    HeapFree(GetProcessHeap(), 0, content);

    if (!looksRight) {
        MessageBoxW(hwnd, wrongFileMessage, L"Punchd Gateway", MB_OK | MB_ICONERROR);
        return ERROR_SUCCESS;
    }

    MsiSetPropertyW(hInstall, property, filePath);
    return ERROR_SUCCESS;
}

/* Immediate CA behind the "Browse..." button for gateway.toml. */
UINT __stdcall BrowseGatewayToml(MSIHANDLE hInstall)
{
    return BrowseForConfig(
        hInstall,
        L"Gateway config (*.toml)\0*.toml\0All Files\0*.*\0",
        L"toml",
        L"Select gateway.toml",
        L"GATEWAY_TOML_FILE",
        "gateway_id",
        NULL,
        L"That does not look like a gateway.toml — it has no 'gateway_id'.\n\n"
        L"Download it from KeyleSSH: Punchd \x2192 Gateways \x2192 Download gateway.toml");
}

/* Immediate CA behind the "Browse..." button for tidecloak.json. */
UINT __stdcall BrowseTidecloakJson(MSIHANDLE hInstall)
{
    return BrowseForConfig(
        hInstall,
        L"TideCloak adapter config (*.json)\0*.json\0All Files\0*.*\0",
        L"json",
        L"Select tidecloak.json",
        L"TIDECLOAK_JSON_FILE",
        "realm",
        "auth-server-url",
        L"That does not look like a TideCloak adapter config — it needs 'realm' "
        L"and 'auth-server-url'.\n\n"
        L"Download it from KeyleSSH: Punchd \x2192 Gateways \x2192 Download tidecloak.json");
}

/* Copy one file into the config directory, creating the directory if needed. */
static BOOL CopyIntoConfigDir(const WCHAR *source, const WCHAR *destName)
{
    if (!source || !*source) return TRUE; /* nothing chosen — fine */

    WCHAR destDir[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, destDir)))
        return FALSE;

    if (FAILED(StringCchCatW(destDir, MAX_PATH, L"\\" CONFIG_DIR)))
        return FALSE;
    CreateDirectoryW(destDir, NULL);

    WCHAR destPath[MAX_PATH];
    if (FAILED(StringCchCopyW(destPath, MAX_PATH, destDir))) return FALSE;
    if (FAILED(StringCchCatW(destPath, MAX_PATH, L"\\"))) return FALSE;
    if (FAILED(StringCchCatW(destPath, MAX_PATH, destName))) return FALSE;

    /* Overwrite: choosing a file in the wizard is an explicit instruction to
     * use it, including over a config left by an earlier install. */
    return CopyFileW(source, destPath, FALSE);
}

/*
 * Deferred CA. CustomActionData carries both paths as "<toml>|<json>", either
 * side possibly empty.
 */
UINT __stdcall CopyGatewayConfig(MSIHANDLE hInstall)
{
    WCHAR data[MAX_PATH * 2 + 2];
    DWORD dataLen = sizeof(data) / sizeof(WCHAR);

    if (MsiGetPropertyW(hInstall, L"CustomActionData", data, &dataLen) != ERROR_SUCCESS
        || dataLen == 0)
        return ERROR_SUCCESS; /* nothing chosen — install proceeds unconfigured */

    WCHAR *sep = wcschr(data, L'|');
    const WCHAR *tomlPath = data;
    const WCHAR *jsonPath = L"";
    if (sep) {
        *sep = L'\0';
        jsonPath = sep + 1;
    }

    if (!CopyIntoConfigDir(tomlPath, GATEWAY_TOML)) return ERROR_INSTALL_FAILURE;
    if (!CopyIntoConfigDir(jsonPath, TIDECLOAK_JSON)) return ERROR_INSTALL_FAILURE;

    return ERROR_SUCCESS;
}

/*
 * Deferred CA on uninstall. Removes only the files this installer places, so an
 * admin's other files in the directory survive.
 */
UINT __stdcall RemoveGatewayConfig(MSIHANDLE hInstall)
{
    (void)hInstall;
    WCHAR base[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, base)))
        return ERROR_SUCCESS;
    if (FAILED(StringCchCatW(base, MAX_PATH, L"\\" CONFIG_DIR L"\\")))
        return ERROR_SUCCESS;

    WCHAR path[MAX_PATH];
    if (SUCCEEDED(StringCchCopyW(path, MAX_PATH, base))
        && SUCCEEDED(StringCchCatW(path, MAX_PATH, GATEWAY_TOML)))
        DeleteFileW(path);

    if (SUCCEEDED(StringCchCopyW(path, MAX_PATH, base))
        && SUCCEEDED(StringCchCatW(path, MAX_PATH, TIDECLOAK_JSON)))
        DeleteFileW(path);

    return ERROR_SUCCESS;
}
