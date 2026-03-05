/*
 * TideSubAuth — MSV1_0 Subauthentication DLL for passwordless RDP.
 *
 * When MSV1_0 processes an interactive logon for a user with
 * UF_MNS_LOGON_ACCOUNT set, it calls our Msv1_0SubAuthenticationRoutine
 * INSTEAD of its own password validation.
 *
 * We check the submitted NT OWF hash against TideSSP's NLA session map
 * (via an exported function in TideSSP.dll, loaded in the same lsass process).
 * If the hash matches a live NLA session → approve (passwordless RDP).
 * Otherwise, fall back to comparing against the stored SAM hash so that
 * normal password logons (console, etc.) still work.
 */

#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <subauth.h>

/* ── Debug logging (to same file as TideSSP) ───────────────────── */

static void subauth_log(const char *fmt, ...)
{
    HANDLE hFile = CreateFileW(
        L"C:\\TideSSP_debug.log",
        FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[1024];
    int off = wsprintfA(buf, "[%02d:%02d:%02d.%03d] SubAuth: ",
                        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    va_list ap;
    va_start(ap, fmt);
    off += wvsprintfA(buf + off, fmt, ap);
    va_end(ap);

    buf[off++] = '\r';
    buf[off++] = '\n';

    DWORD written;
    WriteFile(hFile, buf, (DWORD)off, &written, NULL);
    CloseHandle(hFile);
}

/* ── TideSSP cross-DLL call ────────────────────────────────────── */

typedef BOOLEAN (NTAPI *TideNlaVerifyNtHashFn)(const void *ntHash, ULONG hashLen);

static BOOLEAN TryTideVerify(const void *ntOwfHash)
{
    HMODULE hTide = GetModuleHandleW(L"TideSSP");
    if (!hTide) {
        subauth_log("TideSSP.dll not loaded in this process");
        return FALSE;
    }

    TideNlaVerifyNtHashFn pfn =
        (TideNlaVerifyNtHashFn)GetProcAddress(hTide, "TideNlaVerifyNtHash");
    if (!pfn) {
        subauth_log("TideNlaVerifyNtHash export not found");
        return FALSE;
    }

    return pfn(ntOwfHash, 16);
}

/* ── SubAuth entry point ───────────────────────────────────────── */

NTSTATUS NTAPI
Msv1_0SubAuthenticationRoutine(
    IN  NETLOGON_LOGON_INFO_CLASS   LogonLevel,
    IN  PVOID                       LogonInformation,
    IN  ULONG                       Flags,
    IN  PUSER_ALL_INFORMATION       UserAll,
    OUT PULONG                      WhichFields,
    OUT PULONG                      UserFlags,
    OUT PBOOLEAN                    Authoritative,
    OUT PLARGE_INTEGER              LogoffTime,
    OUT PLARGE_INTEGER              KickoffTime)
{
    *Authoritative = TRUE;
    *WhichFields   = 0;
    *UserFlags     = 0;
    LogoffTime->QuadPart  = 0x7FFFFFFFFFFFFFFF;
    KickoffTime->QuadPart = 0x7FFFFFFFFFFFFFFF;

    subauth_log("called: LogonLevel=%d, Flags=0x%08X", LogonLevel, Flags);

    /* We only handle interactive logons (what termsrv sends for RDP). */
    if (LogonLevel != NetlogonInteractiveInformation &&
        LogonLevel != NetlogonInteractiveTransitiveInformation) {
        subauth_log("non-interactive logon level %d — approving", LogonLevel);
        return STATUS_SUCCESS;
    }

    PNETLOGON_INTERACTIVE_INFO info =
        (PNETLOGON_INTERACTIVE_INFO)LogonInformation;

    const UCHAR *submitted = (const UCHAR *)&info->NtOwfPassword;
    subauth_log("NT hash submitted: %02x%02x%02x%02x...",
                submitted[0], submitted[1], submitted[2], submitted[3]);

    /* 1. Check TideSSP NLA session (passwordless RDP) */
    if (TryTideVerify(&info->NtOwfPassword)) {
        subauth_log("TideSSP NLA session verified — APPROVED");
        return STATUS_SUCCESS;
    }

    /* 2. Fallback: normal NT hash comparison (console logon, etc.) */
    if (UserAll->NtPasswordPresent &&
        UserAll->NtPassword.Length >= 16) {
        if (memcmp(&info->NtOwfPassword,
                   UserAll->NtPassword.Buffer, 16) == 0) {
            subauth_log("NT hash matches SAM — APPROVED (normal password)");
            return STATUS_SUCCESS;
        }
    }

    /* 3. Check LM hash as fallback */
    if (UserAll->LmPasswordPresent &&
        UserAll->LmPassword.Length >= 16) {
        if (memcmp(&info->LmOwfPassword,
                   UserAll->LmPassword.Buffer, 16) == 0) {
            subauth_log("LM hash matches SAM — APPROVED (LM fallback)");
            return STATUS_SUCCESS;
        }
    }

    subauth_log("no match — REJECTED");
    *Authoritative = TRUE;
    return STATUS_LOGON_FAILURE;
}

/* ── DLL entry point ───────────────────────────────────────────── */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL;
    (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        subauth_log("loaded (pid=%lu)", GetCurrentProcessId());
    }
    return TRUE;
}
