/*
 * TideSSP — SSPI function implementations with NegoExtender (NEGOEX) support.
 *
 * Wire protocol tokens:
 *   TOKEN_JWT  [0x04][JWT bytes (ASCII)]
 *
 * Flow (server side — AcceptSecurityContext):
 *   1. Receive TOKEN_JWT → verify JWT EdDSA signature against hardcoded JWK
 *      → extract username → derive session key → logon user → return SEC_E_OK
 *
 * NegoEx integration:
 *   - SECPKG_FLAG_NEGOTIABLE2 flag in SpGetInfo tells NegoExtender to include us
 *   - SpGetExtendedInformation returns our AuthScheme GUID for NEGOEX negotiation
 *   - Session key derived from SHA-256(jwt_signature_bytes) for VERIFY
 */

#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#include <sspi.h>
#include <ntsecapi.h>
#include <ntsecpkg.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <sddl.h>   /* ConvertSidToStringSidW */

#include <lm.h>       /* NetUserSetInfo, USER_INFO_1003 */
#include "ed25519.h"

/* OBJECT_ATTRIBUTES — needed for NtCreateToken, may not be in MinGW headers */
#ifndef InitializeObjectAttributes
typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PVOID           ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
#define InitializeObjectAttributes(p,n,a,r,s) \
    { (p)->Length = sizeof(OBJECT_ATTRIBUTES); (p)->RootDirectory = (r); \
      (p)->Attributes = (a); (p)->ObjectName = (n); \
      (p)->SecurityDescriptor = (s); (p)->SecurityQualityOfService = NULL; }
#endif

/* ── Package identity ─────────────────────────────────────────── */

#define TIDESSP_NAME      L"TideSSP"
#define TIDESSP_NAME_A    "TideSSP"
#define TIDESSP_COMMENT   L"Tide Ed25519 Authentication"
#define TIDESSP_VERSION   1

/* NegoEx flag — tells NegoExtender to discover this package */
#ifndef SECPKG_FLAG_NEGOTIABLE2
#define SECPKG_FLAG_NEGOTIABLE2 0x00200000
#endif

#ifndef SECPKG_INTERFACE_VERSION
#define SECPKG_INTERFACE_VERSION 0x00010000
#endif

/* ── TideSSP AuthScheme GUID for NEGOEX ──────────────────────── */
/* {7A4E8B2C-1F3D-4A5E-9C6B-8D7E0F1A2B3C} */
static const GUID TIDESSP_AUTH_SCHEME = {
    0x7A4E8B2C, 0x1F3D, 0x4A5E,
    {0x9C, 0x6B, 0x8D, 0x7E, 0x0F, 0x1A, 0x2B, 0x3C}
};

/* ── Token types ──────────────────────────────────────────────── */

#define TOKEN_JWT          0x04

#define SESSION_KEY_SIZE   16
#define MAX_USERNAME_LEN   256

/* AES-128-GCM wire format sizes */
#define TIDE_GCM_NONCE_SIZE  12
#define TIDE_GCM_TAG_SIZE    16
#define TIDE_TOKEN_SIZE      (TIDE_GCM_NONCE_SIZE + TIDE_GCM_TAG_SIZE)  /* 28 */

#ifndef SECBUFFER_STREAM
#define SECBUFFER_STREAM 10
#endif

/* ── JWK Ed25519 public key — loaded from file at init ─────────── */
/* Reads tidecloak.json from System32\tidecloak.json (installed alongside DLLs),
 * extracts jwk.keys[0].x (base64url), and decodes to 32 bytes. */
#define TIDESSP_CONFIG_FILENAME L"tidecloak.json"

static UCHAR g_PublicKey[32];
static BOOLEAN g_PublicKeyLoaded = FALSE;

/* ── LSA dispatch table — set by SpInitialize ─────────────────── */

static PLSA_SECPKG_FUNCTION_TABLE LsaDispatch = NULL;

/* Forward declaration — defined below after context struct */
static void tide_log(const char *fmt, ...);

/* ── NLA Session Map — links NLA sessions to SubAuth verification ── */
/*
 * When AcceptLsaModeContext succeeds (JWT verified), we store
 * {sessionKey, ntHash, username} here.  The SubAuth DLL (TideSubAuth)
 * calls our exported TideNlaVerifyNtHash() during MSV1_0 logon to
 * approve the desktop session without a real password.
 *
 * The gateway sends hex(sessionKey) as the "password" in TSCredentials
 * (credType=1).  MSV1_0 hashes it → NT OWF.  SubAuth calls us with
 * that hash, we compare against stored ntHash → approve.
 */
#define MAX_NLA_SESSIONS 32
#define NLA_SESSION_TTL_MS 60000  /* 60 seconds */

typedef struct {
    UCHAR   SessionKey[SESSION_KEY_SIZE];
    UCHAR   NtHash[16];    /* MD4(UTF16LE(hex(SessionKey))) — pre-computed */
    WCHAR   Username[MAX_USERNAME_LEN + 1];
    LONG64  Timestamp;     /* GetTickCount64() */
    BOOLEAN InUse;
} TIDE_NLA_SESSION;

static TIDE_NLA_SESSION g_NlaSessions[MAX_NLA_SESSIONS];
static CRITICAL_SECTION g_NlaSessionLock;
static BOOLEAN g_NlaSessionLockInit = FALSE;

/* Compute NT OWF hash: MD4(UTF-16LE(password)) via ntdll */
static BOOLEAN TideComputeNtHash(const WCHAR *password, USHORT charLen, UCHAR hash[16])
{
    /* NT OWF hash = MD4(UTF-16LE(password)), computed via BCrypt */
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BOOLEAN result = FALSE;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_MD4_ALGORITHM, NULL, 0) != 0) {
        tide_log("TideComputeNtHash: BCrypt MD4 provider unavailable");
        return FALSE;
    }
    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }
    if (BCryptHashData(hHash, (PUCHAR)password, charLen * sizeof(WCHAR), 0) == 0 &&
        BCryptFinishHash(hHash, hash, 16, 0) == 0) {
        result = TRUE;
    }
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

static void TideNlaSessionInit(void)
{
    if (!g_NlaSessionLockInit) {
        InitializeCriticalSection(&g_NlaSessionLock);
        memset(g_NlaSessions, 0, sizeof(g_NlaSessions));
        g_NlaSessionLockInit = TRUE;
    }
}

static void TideNlaSessionStore(const UCHAR sessionKey[SESSION_KEY_SIZE],
                                 const WCHAR *username)
{
    LONG64 now = (LONG64)GetTickCount64();

    /* Pre-compute NT hash of hex(sessionKey) — this is what the gateway
       sends as the "password" and MSV1_0 hashes before calling SubAuth. */
    WCHAR hexKey[SESSION_KEY_SIZE * 2 + 1];
    for (int j = 0; j < SESSION_KEY_SIZE; j++)
        swprintf(&hexKey[j * 2], 3, L"%02x", sessionKey[j]);
    hexKey[SESSION_KEY_SIZE * 2] = L'\0';

    UCHAR ntHash[16];
    if (!TideComputeNtHash(hexKey, SESSION_KEY_SIZE * 2, ntHash)) {
        tide_log("NLA session store: failed to compute NT hash");
        return;
    }

    EnterCriticalSection(&g_NlaSessionLock);
    int slot = -1;
    for (int i = 0; i < MAX_NLA_SESSIONS; i++) {
        if (!g_NlaSessions[i].InUse ||
            (now - g_NlaSessions[i].Timestamp > NLA_SESSION_TTL_MS)) {
            slot = i;
            break;
        }
    }
    if (slot < 0) slot = 0;
    memcpy(g_NlaSessions[slot].SessionKey, sessionKey, SESSION_KEY_SIZE);
    memcpy(g_NlaSessions[slot].NtHash, ntHash, 16);
    wcsncpy(g_NlaSessions[slot].Username, username, MAX_USERNAME_LEN);
    g_NlaSessions[slot].Username[MAX_USERNAME_LEN] = L'\0';
    g_NlaSessions[slot].Timestamp = now;
    g_NlaSessions[slot].InUse = TRUE;
    LeaveCriticalSection(&g_NlaSessionLock);
    tide_log("NLA session stored for '%ls' (slot %d), ntHash=%02x%02x%02x%02x...",
             username, slot, ntHash[0], ntHash[1], ntHash[2], ntHash[3]);
}

/*
 * TideNlaVerifyNtHash — exported for SubAuth DLL to call.
 * Returns TRUE if the given 16-byte NT OWF hash matches any live NLA session.
 * Consumes the session (one-time use).
 */
__declspec(dllexport)
BOOLEAN NTAPI TideNlaVerifyNtHash(const void *ntHash, ULONG hashLen)
{
    if (!ntHash || hashLen < 16 || !g_NlaSessionLockInit) return FALSE;

    BOOLEAN found = FALSE;
    LONG64 now = (LONG64)GetTickCount64();
    EnterCriticalSection(&g_NlaSessionLock);
    for (int i = 0; i < MAX_NLA_SESSIONS; i++) {
        if (g_NlaSessions[i].InUse &&
            (now - g_NlaSessions[i].Timestamp <= NLA_SESSION_TTL_MS) &&
            memcmp(g_NlaSessions[i].NtHash, ntHash, 16) == 0) {
            tide_log("TideNlaVerifyNtHash: MATCH for '%ls' (slot %d)",
                     g_NlaSessions[i].Username, i);
            g_NlaSessions[i].InUse = FALSE;   /* one-time use */
            found = TRUE;
            break;
        }
    }
    LeaveCriticalSection(&g_NlaSessionLock);
    if (!found)
        tide_log("TideNlaVerifyNtHash: no match (hash=%02x%02x%02x%02x...)",
                 ((const UCHAR*)ntHash)[0], ((const UCHAR*)ntHash)[1],
                 ((const UCHAR*)ntHash)[2], ((const UCHAR*)ntHash)[3]);
    return found;
}

/* ── Context state for in-progress authentication ─────────────── */

typedef struct _TIDE_CONTEXT {
    ULONG_PTR ContextHandle;
    UCHAR     SessionKey[SESSION_KEY_SIZE]; /* derived from JWT signature */
    BOOLEAN   SessionKeyValid;
    WCHAR     Username[MAX_USERNAME_LEN + 1];
    USHORT    UsernameLen;
    int       State;  /* 0 = initial, 2 = done */
    HANDLE    LogonToken;  /* S4U logon token for passwordless RDP */
} TIDE_CONTEXT, *PTIDE_CONTEXT;

/* ── Forward declarations ─────────────────────────────────────── */

extern NTSTATUS TideLogonUser(
    PLSA_SECPKG_FUNCTION_TABLE LsaDispatch,
    const WCHAR *username,
    PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
    PVOID *TokenInformation,
    PULONG TokenInfoSize);

/* ── NtCreateToken — dynamically loaded from ntdll ───────────── */

typedef NTSTATUS (NTAPI *PFN_NtCreateToken)(
    PHANDLE TokenHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,     /* OBJECT_ATTRIBUTES* — use PVOID for portability */
    TOKEN_TYPE TokenType,
    PLUID AuthenticationId,
    PLARGE_INTEGER ExpirationTime,
    PTOKEN_USER User,
    PTOKEN_GROUPS Groups,
    PTOKEN_PRIVILEGES Privileges,
    PTOKEN_OWNER Owner,
    PTOKEN_PRIMARY_GROUP PrimaryGroup,
    PTOKEN_DEFAULT_DACL DefaultDacl,
    PTOKEN_SOURCE Source);

#ifndef LsaTokenInformationV2
#define LsaTokenInformationV2 ((LSA_TOKEN_INFORMATION_TYPE)2)
#endif

#ifndef SECURITY_REMOTE_INTERACTIVE_LOGON_RID
#define SECURITY_REMOTE_INTERACTIVE_LOGON_RID 14
#endif

#ifndef SECURITY_INTERACTIVE_LOGON_RID
#define SECURITY_INTERACTIVE_LOGON_RID 4
#endif

/* ── Debug logging to file ────────────────────────────────────── */

#include <stdio.h>
static void tide_log(const char *fmt, ...)
{
    FILE *f = fopen("C:\\TideSSP_debug.log", "a");
    if (!f) return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fprintf(f, "\n");
    fclose(f);
}

/* ── Add logon SIDs to a token ────────────────────────────────── */

/*
 * ConvertAuthDataToToken doesn't add logon-type SIDs (S-1-5-14 for
 * RemoteInteractive, S-1-5-4 for Interactive).  RDP's Early User
 * Authorization check requires S-1-5-14 in the token's groups.
 *
 * This function recreates the token via NtCreateToken with the
 * missing SIDs added.
 */
static HANDLE TideAddLogonSids(HANDLE oldToken)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) { tide_log("AddLogonSids: no ntdll"); return oldToken; }

    PFN_NtCreateToken pNtCreateToken =
        (PFN_NtCreateToken)GetProcAddress(ntdll, "NtCreateToken");
    if (!pNtCreateToken) { tide_log("AddLogonSids: no NtCreateToken"); return oldToken; }

    NTSTATUS st;
    DWORD sz = 0;
    PTOKEN_USER       pUser   = NULL;
    PTOKEN_GROUPS     pGroups = NULL;
    PTOKEN_PRIVILEGES pPrivs  = NULL;
    PTOKEN_OWNER      pOwner  = NULL;
    PTOKEN_PRIMARY_GROUP pPG  = NULL;
    PTOKEN_DEFAULT_DACL  pDacl = NULL;
    TOKEN_STATISTICS  stats;
    TOKEN_SOURCE      source;
    HANDLE            newToken = NULL;

#define QUERY_TOKEN(cls, var) do {                                         \
        GetTokenInformation(oldToken, cls, NULL, 0, &sz);                  \
        var = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);           \
        if (!var || !GetTokenInformation(oldToken, cls, var, sz, &sz)) {   \
            tide_log("AddLogonSids: query " #cls " failed (%lu)", GetLastError()); \
            goto cleanup;                                                  \
        }                                                                  \
    } while (0)

    QUERY_TOKEN(TokenUser,         pUser);
    QUERY_TOKEN(TokenGroups,       pGroups);
    QUERY_TOKEN(TokenPrivileges,   pPrivs);
    QUERY_TOKEN(TokenOwner,        pOwner);
    QUERY_TOKEN(TokenPrimaryGroup, pPG);
    QUERY_TOKEN(TokenDefaultDacl,  pDacl);
#undef QUERY_TOKEN

    if (!GetTokenInformation(oldToken, TokenStatistics, &stats, sizeof(stats), &sz) ||
        !GetTokenInformation(oldToken, TokenSource, &source, sizeof(source), &sz)) {
        tide_log("AddLogonSids: query stats/source failed");
        goto cleanup;
    }

    /* Log existing groups */
    tide_log("AddLogonSids: token has %lu groups", pGroups->GroupCount);
    {
        DWORD i;
        BOOL hasRemoteInteractive = FALSE;
        for (i = 0; i < pGroups->GroupCount; i++) {
            LPWSTR pStr = NULL;
            if (ConvertSidToStringSidW(pGroups->Groups[i].Sid, &pStr)) {
                tide_log("  group[%lu]: %ls (attr=0x%lx)", i, pStr, pGroups->Groups[i].Attributes);
                if (wcscmp(pStr, L"S-1-5-14") == 0)
                    hasRemoteInteractive = TRUE;
                LocalFree(pStr);
            }
        }
        if (hasRemoteInteractive) {
            tide_log("AddLogonSids: S-1-5-14 already present, no change needed");
            goto cleanup;  /* oldToken is fine */
        }
    }

    /* Build new groups = old groups + S-1-5-14 + S-1-5-4 */
    {
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        PSID pSid14 = NULL, pSid4 = NULL;
        DWORD extraCount = 2;
        DWORD newCount = pGroups->GroupCount + extraCount;
        DWORD newSize = sizeof(TOKEN_GROUPS) + (newCount - 1) * sizeof(SID_AND_ATTRIBUTES);
        PTOKEN_GROUPS pNew;
        DWORD i;
        SECURITY_QUALITY_OF_SERVICE sqos;
        OBJECT_ATTRIBUTES oa;

        pNew = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, newSize);
        if (!pNew) { tide_log("AddLogonSids: alloc failed"); goto cleanup; }

        /* Allocate SIDs using Win32 API */
        AllocateAndInitializeSid(&ntAuth, 1, SECURITY_REMOTE_INTERACTIVE_LOGON_RID,
            0, 0, 0, 0, 0, 0, 0, &pSid14);
        AllocateAndInitializeSid(&ntAuth, 1, SECURITY_INTERACTIVE_LOGON_RID,
            0, 0, 0, 0, 0, 0, 0, &pSid4);
        if (!pSid14 || !pSid4) {
            tide_log("AddLogonSids: AllocateAndInitializeSid failed");
            if (pSid14) FreeSid(pSid14);
            if (pSid4) FreeSid(pSid4);
            HeapFree(GetProcessHeap(), 0, pNew);
            goto cleanup;
        }

        pNew->GroupCount = newCount;
        for (i = 0; i < pGroups->GroupCount; i++)
            pNew->Groups[i] = pGroups->Groups[i];

        /* S-1-5-14 (SECURITY_REMOTE_INTERACTIVE_LOGON) */
        pNew->Groups[pGroups->GroupCount].Sid = pSid14;
        pNew->Groups[pGroups->GroupCount].Attributes =
            SE_GROUP_ENABLED | SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT;

        /* S-1-5-4 (SECURITY_INTERACTIVE_LOGON) */
        pNew->Groups[pGroups->GroupCount + 1].Sid = pSid4;
        pNew->Groups[pGroups->GroupCount + 1].Attributes =
            SE_GROUP_ENABLED | SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT;

        memset(&sqos, 0, sizeof(sqos));
        sqos.Length = sizeof(sqos);
        sqos.ImpersonationLevel = SecurityImpersonation;
        sqos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
        sqos.EffectiveOnly = FALSE;

        memset(&oa, 0, sizeof(oa));
        oa.Length = sizeof(oa);
        oa.SecurityQualityOfService = &sqos;

        st = pNtCreateToken(
            &newToken,
            TOKEN_ALL_ACCESS,
            &oa,
            TokenPrimary,
            &stats.AuthenticationId,
            &stats.ExpirationTime,
            pUser,
            pNew,
            pPrivs,
            pOwner,
            pPG,
            pDacl,
            &source);

        HeapFree(GetProcessHeap(), 0, pNew);
        FreeSid(pSid14);
        FreeSid(pSid4);

        if (NT_SUCCESS(st) && newToken) {
            tide_log("AddLogonSids: new token %p with S-1-5-14 + S-1-5-4 (status 0x%08X)", newToken, st);
            CloseHandle(oldToken);
            /* Fall through — return newToken */
        } else {
            tide_log("AddLogonSids: NtCreateToken failed 0x%08X", st);
            newToken = NULL;  /* fall through to cleanup, return oldToken */
        }
    }

cleanup:
    if (pUser)   HeapFree(GetProcessHeap(), 0, pUser);
    if (pGroups) HeapFree(GetProcessHeap(), 0, pGroups);
    if (pPrivs)  HeapFree(GetProcessHeap(), 0, pPrivs);
    if (pOwner)  HeapFree(GetProcessHeap(), 0, pOwner);
    if (pPG)     HeapFree(GetProcessHeap(), 0, pPG);
    if (pDacl)   HeapFree(GetProcessHeap(), 0, pDacl);
    return newToken ? newToken : oldToken;
}

/* ── Base64url decode ─────────────────────────────────────────── */

static const signed char B64URL_TABLE[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,
     52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,63,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

/* Decode base64url (no padding required). Returns decoded length, or -1 on error. */
static int base64url_decode(const char *src, int srcLen, UCHAR *dst, int dstCapacity)
{
    int i, j = 0;
    unsigned int accum = 0;
    int bits = 0;
    for (i = 0; i < srcLen; i++) {
        if (src[i] == '=' || src[i] == '\0') break;
        signed char val = B64URL_TABLE[(unsigned char)src[i]];
        if (val < 0) return -1;
        accum = (accum << 6) | (unsigned int)val;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (j >= dstCapacity) return -1;
            dst[j++] = (UCHAR)((accum >> bits) & 0xFF);
        }
    }
    return j;
}

/* ── Minimal JSON string extraction ──────────────────────────── */
/* Find "key":"value" in JSON and copy value to dst. Returns length or -1. */

static int json_extract_string(const char *json, int jsonLen,
                               const char *key, char *dst, int dstCapacity)
{
    /* Build search pattern: "key":" */
    char pattern[128];
    int keyLen = (int)strlen(key);
    if (keyLen + 4 > (int)sizeof(pattern)) return -1;
    pattern[0] = '"';
    memcpy(pattern + 1, key, keyLen);
    pattern[keyLen + 1] = '"';
    pattern[keyLen + 2] = ':';
    pattern[keyLen + 3] = '\0';

    /* Search for pattern */
    const char *pos = NULL;
    int i;
    int patLen = keyLen + 3;
    for (i = 0; i <= jsonLen - patLen; i++) {
        if (memcmp(json + i, pattern, patLen) == 0) {
            pos = json + i + patLen;
            break;
        }
    }
    if (!pos) return -1;

    /* Skip whitespace */
    while (pos < json + jsonLen && (*pos == ' ' || *pos == '\t')) pos++;
    if (pos >= json + jsonLen || *pos != '"') return -1;
    pos++; /* skip opening quote */

    /* Copy until closing quote */
    int len = 0;
    while (pos < json + jsonLen && *pos != '"' && len < dstCapacity - 1) {
        dst[len++] = *pos++;
    }
    dst[len] = '\0';
    return len;
}

/* Extract integer value for "key":number */
static long long json_extract_int(const char *json, int jsonLen, const char *key)
{
    char pattern[128];
    int keyLen = (int)strlen(key);
    if (keyLen + 4 > (int)sizeof(pattern)) return -1;
    pattern[0] = '"';
    memcpy(pattern + 1, key, keyLen);
    pattern[keyLen + 1] = '"';
    pattern[keyLen + 2] = ':';
    pattern[keyLen + 3] = '\0';

    const char *pos = NULL;
    int i;
    int patLen = keyLen + 3;
    for (i = 0; i <= jsonLen - patLen; i++) {
        if (memcmp(json + i, pattern, patLen) == 0) {
            pos = json + i + patLen;
            break;
        }
    }
    if (!pos) return -1;
    while (pos < json + jsonLen && (*pos == ' ' || *pos == '\t')) pos++;
    return _atoi64(pos);
}

/* ── Helper: derive session key from JWT signature ───────────── */
/* SHA-256(jwt_signature_bytes), truncated to 16 bytes */
/* Must match the gateway's derivation exactly */

static void deriveSessionKeyFromSig(
    const UCHAR *sigBytes, ULONG sigLen,
    UCHAR outKey[SESSION_KEY_SIZE])
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    UCHAR hash[32]; /* SHA-256 output */

    memset(outKey, 0, SESSION_KEY_SIZE);
    if (BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
        if (BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0))) {
            BCryptHashData(hHash, (PUCHAR)sigBytes, sigLen, 0);
            BCryptFinishHash(hHash, hash, sizeof(hash), 0);
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    memcpy(outKey, hash, SESSION_KEY_SIZE);
    SecureZeroMemory(hash, sizeof(hash));
}

/* ══════════════════════════════════════════════════════════════════
 *  SSP Package Functions
 * ══════════════════════════════════════════════════════════════════ */

/* ── Load Ed25519 public key from tidecloak.json ─────────────── */
/* Reads %SystemRoot%\System32\tidecloak.json, extracts jwk.keys[0].x,
 * base64url-decodes to 32 bytes. */
static BOOLEAN TideLoadPublicKey(void)
{
    /* Build path: %SystemRoot%\System32\tidecloak.json */
    WCHAR path[MAX_PATH];
    UINT sysLen = GetSystemDirectoryW(path, MAX_PATH);
    if (sysLen == 0 || sysLen >= MAX_PATH - 20) {
        tide_log("LoadPublicKey: GetSystemDirectory failed");
        return FALSE;
    }
    wcscat_s(path, MAX_PATH, L"\\");
    wcscat_s(path, MAX_PATH, TIDESSP_CONFIG_FILENAME);

    /* Read file */
    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        tide_log("LoadPublicKey: cannot open %ls (err=%lu)", path, GetLastError());
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0 || fileSize > 65536) {
        tide_log("LoadPublicKey: bad file size %lu", fileSize);
        CloseHandle(hFile);
        return FALSE;
    }

    char *json = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize + 1);
    if (!json) { CloseHandle(hFile); return FALSE; }

    DWORD bytesRead = 0;
    ReadFile(hFile, json, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);
    json[bytesRead] = '\0';

    tide_log("LoadPublicKey: read %ls (%lu bytes)", path, bytesRead);

    /* Extract "x" value from jwk.keys[0] */
    char xValue[64];
    int xLen = json_extract_string(json, (int)bytesRead, "x", xValue, sizeof(xValue));
    if (xLen <= 0) {
        tide_log("LoadPublicKey: 'x' field not found in JSON");
        HeapFree(GetProcessHeap(), 0, json);
        return FALSE;
    }
    HeapFree(GetProcessHeap(), 0, json);

    tide_log("LoadPublicKey: x=%s (%d chars)", xValue, xLen);

    int decoded = base64url_decode(xValue, xLen, g_PublicKey, 32);
    if (decoded != 32) {
        tide_log("LoadPublicKey: base64url decode failed (got %d bytes, expected 32)", decoded);
        return FALSE;
    }

    tide_log("LoadPublicKey: OK — %02x%02x%02x%02x...",
             g_PublicKey[0], g_PublicKey[1], g_PublicKey[2], g_PublicKey[3]);
    return TRUE;
}

static NTSTATUS NTAPI TideSsp_Initialize(
    ULONG_PTR PackageId,
    PSECPKG_PARAMETERS Parameters,
    PLSA_SECPKG_FUNCTION_TABLE FunctionTable)
{
    (void)PackageId;
    (void)Parameters;
    LsaDispatch = FunctionTable;
    TideNlaSessionInit();

    g_PublicKeyLoaded = TideLoadPublicKey();
    if (!g_PublicKeyLoaded) {
        tide_log("TideSSP Initialize: WARNING — no public key, JWT verification will fail");
    }

    tide_log("TideSSP Initialize: PackageId=%llu, LsaDispatch=%p, keyLoaded=%d",
             (unsigned long long)PackageId, (void*)FunctionTable, g_PublicKeyLoaded);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI TideSsp_Shutdown(void)
{
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI TideSsp_GetInfo(PSecPkgInfoW PackageInfo)
{
    tide_log("GetInfo called");
    PackageInfo->fCapabilities = SECPKG_FLAG_INTEGRITY |
                                SECPKG_FLAG_PRIVACY |
                                SECPKG_FLAG_MUTUAL_AUTH |
                                SECPKG_FLAG_ACCEPT_WIN32_NAME |
                                SECPKG_FLAG_CONNECTION |
                                SECPKG_FLAG_NEGOTIABLE2;
    PackageInfo->wVersion = TIDESSP_VERSION;
    PackageInfo->wRPCID = SECPKG_ID_NONE;
    PackageInfo->cbMaxToken = 4096; /* JWT token size */
    PackageInfo->Name = TIDESSP_NAME;
    PackageInfo->Comment = TIDESSP_COMMENT;
    return STATUS_SUCCESS;
}

/* ── AcceptSecurityContext — server-side context establishment ─── */

static NTSTATUS NTAPI TideSsp_AcceptLsaModeContext(
    LSA_SEC_HANDLE CredentialHandle,
    LSA_SEC_HANDLE ContextHandle,
    PSecBufferDesc InputMessage,
    ULONG ContextReq,
    ULONG TargetDataRep,
    PLSA_SEC_HANDLE NewContextHandle,
    PSecBufferDesc OutputMessage,
    PULONG ContextAttr,
    PTimeStamp ExpirationTime,
    PBOOLEAN MappedContext,
    PSecBuffer ContextData)
{
    (void)CredentialHandle;
    (void)ContextReq;
    (void)TargetDataRep;
    (void)ContextData;

    PTIDE_CONTEXT ctx = NULL;
    PSecBuffer inBuf = NULL;
    PSecBuffer outBuf = NULL;
    ULONG i;

    /* Find input token buffer */
    if (InputMessage) {
        for (i = 0; i < InputMessage->cBuffers; i++) {
            if (InputMessage->pBuffers[i].BufferType == SECBUFFER_TOKEN) {
                inBuf = &InputMessage->pBuffers[i];
                break;
            }
        }
    }

    /* Find output token buffer */
    if (OutputMessage) {
        for (i = 0; i < OutputMessage->cBuffers; i++) {
            if (OutputMessage->pBuffers[i].BufferType == SECBUFFER_TOKEN) {
                outBuf = &OutputMessage->pBuffers[i];
                break;
            }
        }
    }

    if (!inBuf || !inBuf->pvBuffer || inBuf->cbBuffer < 2)
        return SEC_E_INVALID_TOKEN;

    PUCHAR token = (PUCHAR)inBuf->pvBuffer;

    tide_log("AcceptLsaModeContext: token[0]=0x%02X, cbBuffer=%u", token[0], inBuf->cbBuffer);

    if (token[0] == TOKEN_JWT) {
        /* ── JWT verification (single round, no challenge) ── */
        const char *jwt = (const char *)(token + 1);
        int jwtLen = (int)(inBuf->cbBuffer - 1);

        /* Check for null-separated gateway:endpoint hint after JWT.
         * Token format: [0x04][JWT]\0[gateway:endpoint] */
        const char *endpointHint = NULL;
        int endpointHintLen = 0;
        {
            const char *nulPos = (const char *)memchr(jwt, '\0', jwtLen);
            if (nulPos && nulPos < jwt + jwtLen - 1) {
                endpointHint = nulPos + 1;
                endpointHintLen = (int)(jwtLen - (int)(endpointHint - jwt));
                jwtLen = (int)(nulPos - jwt); /* truncate to just the JWT */
                tide_log("Endpoint hint: '%.*s'", endpointHintLen, endpointHint);
            }
        }

        tide_log("JWT token received, len=%d", jwtLen);

        /* Find the three parts: header.payload.signature */
        const char *dot1 = NULL, *dot2 = NULL;
        int k;
        for (k = 0; k < jwtLen; k++) {
            if (jwt[k] == '.') {
                if (!dot1) dot1 = jwt + k;
                else { dot2 = jwt + k; break; }
            }
        }
        if (!dot1 || !dot2) {
            tide_log("JWT parse failed: missing dots");
            return SEC_E_INVALID_TOKEN;
        }

        /* Signed data = header.payload (raw ASCII bytes before last dot) */
        int signedDataLen = (int)(dot2 - jwt);
        const char *sigB64 = dot2 + 1;
        int sigB64Len = jwtLen - (int)(sigB64 - jwt);

        tide_log("JWT parts: signedDataLen=%d, sigB64Len=%d", signedDataLen, sigB64Len);

        /* Decode the signature (should be 64 bytes for Ed25519) */
        UCHAR sigBytes[64];
        int sigLen = base64url_decode(sigB64, sigB64Len, sigBytes, sizeof(sigBytes));
        if (sigLen != 64) {
            tide_log("JWT sig decode failed: got %d bytes (expected 64)", sigLen);
            return SEC_E_INVALID_TOKEN;
        }

        tide_log("JWT sig decoded OK (64 bytes), verifying Ed25519...");

        if (!g_PublicKeyLoaded) {
            tide_log("No public key loaded — cannot verify JWT");
            return SEC_E_INVALID_TOKEN;
        }

        tide_log("JWK pubkey: %02x%02x%02x%02x...", g_PublicKey[0], g_PublicKey[1], g_PublicKey[2], g_PublicKey[3]);

        /* Verify Ed25519 signature against public key from registry */
        int verifyResult = ed25519_verify(sigBytes, (const uint8_t *)jwt, (size_t)signedDataLen, g_PublicKey);
        if (verifyResult != 0) {
            tide_log("Ed25519 VERIFY FAILED (result=%d)", verifyResult);
            return (NTSTATUS)0xC0040002L; /* unique: Ed25519 verify failed */
        }
        tide_log("Ed25519 VERIFY OK");

        /* Decode payload to extract username and expiry */
        const char *payloadB64 = dot1 + 1;
        int payloadB64Len = (int)(dot2 - dot1 - 1);
        char payloadJson[2048];
        int payloadLen = base64url_decode(payloadB64, payloadB64Len,
                                          (UCHAR *)payloadJson, sizeof(payloadJson) - 1);
        if (payloadLen <= 0)
            return SEC_E_INVALID_TOKEN;
        payloadJson[payloadLen] = '\0';

        /* Check token expiry */
        long long exp = json_extract_int(payloadJson, payloadLen, "exp");
        if (exp > 0) {
            FILETIME ft;
            GetSystemTimeAsFileTime(&ft);
            /* FILETIME is 100ns intervals since 1601-01-01. Unix epoch offset: */
            ULARGE_INTEGER uli;
            uli.LowPart = ft.dwLowDateTime;
            uli.HighPart = ft.dwHighDateTime;
            long long unixNow = (long long)((uli.QuadPart - 116444736000000000ULL) / 10000000ULL);
            if (unixNow > exp)
                return SEC_E_CONTEXT_EXPIRED;
        }

        /* Extract username from dest: roles if gateway:endpoint hint is present.
         * Look for role "dest:<gateway>:<endpoint>:<username>" in the JWT payload. */
        char usernameUtf8[MAX_USERNAME_LEN + 1];
        int usernameLen = -1;

        if (endpointHint && endpointHintLen > 0) {
            /* Build search prefix "dest:<gateway>:<endpoint>:" */
            char prefix[512];
            int prefixLen = snprintf(prefix, sizeof(prefix), "dest:%.*s:", endpointHintLen, endpointHint);
            if (prefixLen > 0 && prefixLen < (int)sizeof(prefix)) {
                tide_log("Looking for role with prefix '%s' in JWT", prefix);
                /* Scan raw JSON for "dest:gw:ep:username" strings */
                int pi;
                for (pi = 0; pi < payloadLen - prefixLen; pi++) {
                    if (payloadJson[pi] == '"' && memcmp(payloadJson + pi + 1, prefix, prefixLen) == 0) {
                        /* Found the prefix after a quote -- extract username until closing quote */
                        const char *uStart = payloadJson + pi + 1 + prefixLen;
                        const char *uEnd = uStart;
                        while (uEnd < payloadJson + payloadLen && *uEnd != '"') uEnd++;
                        int uLen = (int)(uEnd - uStart);
                        if (uLen > 0 && uLen < MAX_USERNAME_LEN) {
                            memcpy(usernameUtf8, uStart, uLen);
                            usernameUtf8[uLen] = '\0';
                            usernameLen = uLen;
                            tide_log("Extracted RDP username from dest role: '%s'", usernameUtf8);
                        }
                        break;
                    }
                }
            }
        }

        if (usernameLen <= 0 && endpointHint && endpointHintLen > 0) {
            /* Endpoint hint was provided but no matching dest: role found -- reject */
            tide_log("No dest:%.*s:<username> role found in JWT -- access denied",
                     endpointHintLen, endpointHint);
            return SEC_E_NO_CREDENTIALS;
        }

        /* Fallback for tokens without endpoint hint (non-EdDSA path) */
        if (usernameLen <= 0)
            usernameLen = json_extract_string(payloadJson, payloadLen,
                                              "preferred_username",
                                              usernameUtf8, sizeof(usernameUtf8));
        if (usernameLen <= 0)
            usernameLen = json_extract_string(payloadJson, payloadLen,
                                              "sub", usernameUtf8, sizeof(usernameUtf8));
        if (usernameLen <= 0)
            return SEC_E_INVALID_TOKEN;

        /* Allocate or reuse context */
        if (ContextHandle) {
            ctx = (PTIDE_CONTEXT)ContextHandle;
        } else {
            ctx = (PTIDE_CONTEXT)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TIDE_CONTEXT));
            if (!ctx) return SEC_E_INSUFFICIENT_MEMORY;
        }

        /* Store username (UTF-8 → UTF-16) */
        int wLen = MultiByteToWideChar(CP_UTF8, 0,
            usernameUtf8, usernameLen,
            ctx->Username, MAX_USERNAME_LEN);
        if (wLen <= 0) {
            HeapFree(GetProcessHeap(), 0, ctx);
            return SEC_E_INVALID_TOKEN;
        }
        ctx->Username[wLen] = L'\0';
        ctx->UsernameLen = (USHORT)wLen;

        /* Derive session key from JWT signature for NEGOEX VERIFY */
        deriveSessionKeyFromSig(sigBytes, 64, ctx->SessionKey);
        ctx->SessionKeyValid = TRUE;

        tide_log("Session key: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                 ctx->SessionKey[0],ctx->SessionKey[1],ctx->SessionKey[2],ctx->SessionKey[3],
                 ctx->SessionKey[4],ctx->SessionKey[5],ctx->SessionKey[6],ctx->SessionKey[7],
                 ctx->SessionKey[8],ctx->SessionKey[9],ctx->SessionKey[10],ctx->SessionKey[11],
                 ctx->SessionKey[12],ctx->SessionKey[13],ctx->SessionKey[14],ctx->SessionKey[15]);

        /* Also log the raw signature bytes being hashed */
        tide_log("JWT sig bytes: %02x%02x%02x%02x%02x%02x%02x%02x...%02x%02x%02x%02x",
                 sigBytes[0],sigBytes[1],sigBytes[2],sigBytes[3],
                 sigBytes[4],sigBytes[5],sigBytes[6],sigBytes[7],
                 sigBytes[60],sigBytes[61],sigBytes[62],sigBytes[63]);

        /* Create a Windows logon session via S4U (Service-for-User).
         * This gives termsrv a valid token so it doesn't need the password
         * from TSCredentials. Without this, termsrv tries LogonUser with
         * an empty password and fails. */
        {
            HANDLE tokenHandle = NULL;
            ULONG tokenSize = 0;
            LSA_TOKEN_INFORMATION_TYPE tokenType = LsaTokenInformationV2;
            NTSTATUS logonStatus = TideLogonUser(
                LsaDispatch,
                ctx->Username,
                &tokenType,
                &tokenHandle,
                &tokenSize);
            if (NT_SUCCESS(logonStatus) && tokenHandle) {
                tide_log("JWT auth OK for '%ls' — S4U base token: %p",
                         ctx->Username, tokenHandle);
                tokenHandle = TideAddLogonSids(tokenHandle);
                ctx->LogonToken = tokenHandle;
                tide_log("JWT auth OK for '%ls' — final token: %p",
                         ctx->Username, tokenHandle);
            } else {
                tide_log("JWT auth OK for '%ls' — S4U logon FAILED (0x%08X), proceeding without token",
                         ctx->Username, logonStatus);
                ctx->LogonToken = NULL;
            }
        }

        /* No output token — single round, auth complete */
        if (outBuf) outBuf->cbBuffer = 0;

        *NewContextHandle = (LSA_SEC_HANDLE)ctx;
        *ContextAttr = ASC_RET_MUTUAL_AUTH | ASC_RET_CONNECTION | ASC_RET_CONFIDENTIALITY;
        if (ExpirationTime) {
            ExpirationTime->LowPart = 0xFFFFFFFF;
            ExpirationTime->HighPart = 0x7FFFFFFF;
        }
        /* Marshal session key + token handle to user mode.
         * Layout: [session_key (16 bytes)] [token_handle (8 bytes on x64)]
         * The token handle is duplicated to the client process so termsrv
         * can use it for QuerySecurityContextToken(). */
        if (MappedContext) *MappedContext = TRUE;
        if (ContextData) {
            ULONG ctxDataSize = SESSION_KEY_SIZE + sizeof(HANDLE);
            PVOID ctxBuf = NULL;
            if (LsaDispatch && LsaDispatch->AllocateLsaHeap) {
                ctxBuf = LsaDispatch->AllocateLsaHeap(ctxDataSize);
            } else {
                ctxBuf = HeapAlloc(GetProcessHeap(), 0, ctxDataSize);
            }
            if (ctxBuf) {
                memcpy(ctxBuf, ctx->SessionKey, SESSION_KEY_SIZE);

                /* Duplicate token handle to client process (termsrv) */
                HANDLE clientToken = NULL;
                if (ctx->LogonToken && LsaDispatch && LsaDispatch->DuplicateHandle) {
                    NTSTATUS dupStatus = LsaDispatch->DuplicateHandle(ctx->LogonToken, &clientToken);
                    if (NT_SUCCESS(dupStatus)) {
                        tide_log("ContextData: duplicated token %p → %p (client process)",
                                 ctx->LogonToken, clientToken);
                    } else {
                        tide_log("ContextData: DuplicateHandle failed 0x%08X", dupStatus);
                        clientToken = NULL;
                    }
                }
                memcpy((PUCHAR)ctxBuf + SESSION_KEY_SIZE, &clientToken, sizeof(HANDLE));

                ContextData->BufferType = SECBUFFER_TOKEN;
                ContextData->cbBuffer = ctxDataSize;
                ContextData->pvBuffer = ctxBuf;
                tide_log("ContextData: marshaled %u bytes (key + token) to user mode", ctxDataSize);
            }
        }

        ctx->State = 2;
        tide_log("AcceptLsaModeContext: SUCCESS for '%ls' (MappedContext=TRUE)", ctx->Username);
        return SEC_E_OK;
    }

    tide_log("AcceptLsaModeContext: unknown token type 0x%02X", token[0]);
    return SEC_E_INVALID_TOKEN;
}

static NTSTATUS NTAPI TideSsp_DeleteContext(LSA_SEC_HANDLE ContextHandle)
{
    if (ContextHandle) {
        PTIDE_CONTEXT ctx = (PTIDE_CONTEXT)ContextHandle;
        if (ctx->LogonToken) {
            CloseHandle(ctx->LogonToken);
            ctx->LogonToken = NULL;
        }
        SecureZeroMemory(ctx->SessionKey, SESSION_KEY_SIZE);
        HeapFree(GetProcessHeap(), 0, ctx);
    }
    return STATUS_SUCCESS;
}

/* ══════════════════════════════════════════════════════════════════
 *  NegoEx-specific functions
 * ══════════════════════════════════════════════════════════════════ */

/*
 * SpGetExtendedInformation — called by NegoExtender at boot to discover
 * our AuthScheme GUID. This is how NegoExtender knows to include TideSSP
 * in SPNEGO NEGOEX negotiation.
 */
static NTSTATUS NTAPI TideSsp_GetExtendedInformation(
    SECPKG_EXTENDED_INFORMATION_CLASS InfoClass,
    PSECPKG_EXTENDED_INFORMATION *ppInfo)
{
    tide_log("GetExtendedInformation: InfoClass=%d", (int)InfoClass);
    if (InfoClass == SecpkgNego2Info) {
        /* Allocate from LSA heap — required by the LSA API contract */
        PSECPKG_EXTENDED_INFORMATION info = NULL;
        if (LsaDispatch && LsaDispatch->AllocateLsaHeap) {
            info = (PSECPKG_EXTENDED_INFORMATION)LsaDispatch->AllocateLsaHeap(
                sizeof(SECPKG_EXTENDED_INFORMATION));
        } else {
            info = (PSECPKG_EXTENDED_INFORMATION)HeapAlloc(
                GetProcessHeap(), HEAP_ZERO_MEMORY,
                sizeof(SECPKG_EXTENDED_INFORMATION));
        }
        if (!info) return SEC_E_INSUFFICIENT_MEMORY;

        info->Class = SecpkgNego2Info;
        memcpy(info->Info.Nego2Info.AuthScheme, &TIDESSP_AUTH_SCHEME, 16);
        info->Info.Nego2Info.PackageFlags = 0;
        *ppInfo = info;
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

/*
 * SpQueryMetaData — NegoExtender calls during initial negotiation.
 * TideSSP doesn't need metadata exchange, so return success with no data.
 */
static NTSTATUS NTAPI TideSsp_QueryMetaData(
    LSA_SEC_HANDLE CredentialHandle,
    PUNICODE_STRING TargetName,
    ULONG ContextRequirements,
    PULONG MetaDataLength,
    PUCHAR *MetaData,
    PLSA_SEC_HANDLE ContextHandle)
{
    (void)CredentialHandle;
    (void)TargetName;
    (void)ContextRequirements;

    tide_log("QueryMetaData called");

    /* MS-NEGOEX: QueryMetaData should create a security context handle.
     * NegoExtender uses it for subsequent calls (QueryContextAttributes, etc.) */
    if (ContextHandle) {
        PTIDE_CONTEXT ctx = (PTIDE_CONTEXT)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TIDE_CONTEXT));
        if (ctx) {
            ctx->State = 0; /* awaiting NEGOTIATE */
            *ContextHandle = (LSA_SEC_HANDLE)ctx;
        }
    }

    if (MetaDataLength) *MetaDataLength = 0;
    if (MetaData) *MetaData = NULL;
    return STATUS_SUCCESS;
}

/*
 * SpExchangeMetaData — accept and ignore metadata from the peer.
 */
static NTSTATUS NTAPI TideSsp_ExchangeMetaData(
    LSA_SEC_HANDLE CredentialHandle,
    PUNICODE_STRING TargetName,
    ULONG ContextRequirements,
    ULONG MetaDataLength,
    PUCHAR MetaData,
    PLSA_SEC_HANDLE ContextHandle)
{
    (void)CredentialHandle;
    (void)TargetName;
    (void)ContextRequirements;
    (void)MetaDataLength;
    (void)MetaData;
    (void)ContextHandle;
    tide_log("ExchangeMetaData called: MetaDataLength=%u", MetaDataLength);
    return STATUS_SUCCESS;
}

/* ══════════════════════════════════════════════════════════════════
 *  Query/Set Context Attributes (with session key support)
 * ══════════════════════════════════════════════════════════════════ */

/* SECPKG_ATTR_NEGO_KEYS — queried by NegoExtender for NEGOEX VERIFY checksum */
#ifndef SECPKG_ATTR_NEGO_KEYS
#define SECPKG_ATTR_NEGO_KEYS 22
#endif

#ifndef SECPKG_ATTR_PACKAGE_INFO
#define SECPKG_ATTR_PACKAGE_INFO 10
#endif

#ifndef SECPKG_ATTR_NEGOTIATION_INFO
#define SECPKG_ATTR_NEGOTIATION_INFO 12
#endif

#ifndef SECPKG_ATTR_FLAGS
#define SECPKG_ATTR_FLAGS 14
#endif

#ifndef SECPKG_ATTR_ACCESS_TOKEN
#define SECPKG_ATTR_ACCESS_TOKEN 18
#endif

#ifndef SECPKG_NEGOTIATION_COMPLETE
#define SECPKG_NEGOTIATION_COMPLETE 0
#endif

/*
 * SECPKG_ATTR_NEGO_KEYS buffer layout (x64, 32 bytes).
 * Written at raw byte offsets to avoid any struct padding ambiguity.
 *
 *   Offset 0:  KeyType        (ULONG, 4 bytes)
 *   Offset 4:  KeyLength      (ULONG, 4 bytes)
 *   Offset 8:  KeyValue       (pointer, 8 bytes)
 *   Offset 16: VerifyKeyType  (ULONG, 4 bytes)
 *   Offset 20: VerifyKeyLength (ULONG, 4 bytes)
 *   Offset 24: VerifyKeyValue (pointer, 8 bytes)
 */

static NTSTATUS NTAPI TideSsp_QueryContextAttributes(LSA_SEC_HANDLE h, ULONG attr, PVOID buf) {
    tide_log("QueryContextAttributes: attr=%u (0x%X), handle=%p, buf=%p", attr, attr, (void*)h, buf);

    if (!buf) {
        tide_log("QueryContextAttributes: buf is NULL!");
        return SEC_E_INVALID_TOKEN;
    }

    if (attr == SECPKG_ATTR_SIZES) {
        PSecPkgContext_Sizes sizes = (PSecPkgContext_Sizes)buf;
        sizes->cbMaxToken = 4096;
        sizes->cbMaxSignature = 16;           /* HMAC-SHA-256 truncated */
        sizes->cbBlockSize = 1;               /* GCM has no block alignment */
        sizes->cbSecurityTrailer = TIDE_TOKEN_SIZE;  /* 28 = nonce(12) + tag(16) */
        tide_log("LSA SIZES: trailer=%u, sig=%u", TIDE_TOKEN_SIZE, 16);
        return STATUS_SUCCESS;
    }
    if (attr == SECPKG_ATTR_NEGO_KEYS) {
        PTIDE_CONTEXT ctx = (PTIDE_CONTEXT)h;
        tide_log("NEGO_KEYS: ctx=%p, valid=%d", (void*)ctx, ctx ? ctx->SessionKeyValid : -1);

        if (!ctx || !ctx->SessionKeyValid) {
            tide_log("NEGO_KEYS: no session key available");
            return SEC_E_NO_CREDENTIALS;
        }

        /* Allocate key buffers from process heap */
        PUCHAR key1 = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SESSION_KEY_SIZE);
        PUCHAR key2 = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SESSION_KEY_SIZE);
        if (!key1 || !key2) return SEC_E_INSUFFICIENT_MEMORY;

        memcpy(key1, ctx->SessionKey, SESSION_KEY_SIZE);
        memcpy(key2, ctx->SessionKey, SESSION_KEY_SIZE);

        tide_log("NEGO_KEYS: key bytes: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                 key1[0],key1[1],key1[2],key1[3],key1[4],key1[5],key1[6],key1[7],
                 key1[8],key1[9],key1[10],key1[11],key1[12],key1[13],key1[14],key1[15]);

        /* Write at raw byte offsets — zero the buffer first to eliminate
         * any padding garbage that could confuse NegoExtender. */
        PUCHAR p = (PUCHAR)buf;
        memset(p, 0, 32);

        *(ULONG  *)(p + 0)  = 17;              /* KeyType: aes128-cts-hmac-sha1-96 */
        *(ULONG  *)(p + 4)  = SESSION_KEY_SIZE; /* KeyLength */
        *(PUCHAR *)(p + 8)  = key1;             /* KeyValue */
        *(ULONG  *)(p + 16) = 17;              /* VerifyKeyType: aes128-cts-hmac-sha1-96 */
        *(ULONG  *)(p + 20) = SESSION_KEY_SIZE; /* VerifyKeyLength */
        *(PUCHAR *)(p + 24) = key2;             /* VerifyKeyValue */

        tide_log("NEGO_KEYS: wrote 32 bytes at raw offsets, key1=%p, key2=%p", (void*)key1, (void*)key2);

        return STATUS_SUCCESS;
    }
    if (attr == SECPKG_ATTR_SESSION_KEY) {
        PTIDE_CONTEXT ctx = (PTIDE_CONTEXT)h;
        SecPkgContext_SessionKey *sk = (SecPkgContext_SessionKey *)buf;
        if (!ctx || !ctx->SessionKeyValid) {
            sk->SessionKeyLength = 0;
            sk->SessionKey = NULL;
            return STATUS_SUCCESS;
        }
        PUCHAR key = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SESSION_KEY_SIZE);
        if (!key) return SEC_E_INSUFFICIENT_MEMORY;
        memcpy(key, ctx->SessionKey, SESSION_KEY_SIZE);
        sk->SessionKeyLength = SESSION_KEY_SIZE;
        sk->SessionKey = key;
        tide_log("SESSION_KEY: returned 16-byte key");
        return STATUS_SUCCESS;
    }
    if (attr == SECPKG_ATTR_PACKAGE_INFO) {
        tide_log("PACKAGE_INFO: returning TideSSP package info");
        /* Allocate SecPkgInfoW + string buffers */
        PSecPkgInfoW info = (PSecPkgInfoW)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
            sizeof(SecPkgInfoW) + 64 * sizeof(WCHAR));
        if (!info) return SEC_E_INSUFFICIENT_MEMORY;
        WCHAR *nameStr = (WCHAR*)((PUCHAR)info + sizeof(SecPkgInfoW));
        WCHAR *commentStr = nameStr + 16;
        wcscpy(nameStr, TIDESSP_NAME);
        wcscpy(commentStr, TIDESSP_COMMENT);
        info->fCapabilities = SECPKG_FLAG_INTEGRITY |
                              SECPKG_FLAG_PRIVACY |
                              SECPKG_FLAG_MUTUAL_AUTH |
                              SECPKG_FLAG_ACCEPT_WIN32_NAME |
                              SECPKG_FLAG_CONNECTION |
                              SECPKG_FLAG_NEGOTIABLE2;
        info->wVersion = TIDESSP_VERSION;
        info->wRPCID = SECPKG_ID_NONE;
        info->cbMaxToken = 4096;
        info->Name = nameStr;
        info->Comment = commentStr;
        /* SecPkgContext_PackageInfoW is just a pointer to SecPkgInfoW */
        *(PSecPkgInfoW *)buf = info;
        return STATUS_SUCCESS;
    }
    if (attr == SECPKG_ATTR_NEGOTIATION_INFO) {
        tide_log("NEGOTIATION_INFO: returning complete");
        /* SecPkgContext_NegotiationInfoW: { PSecPkgInfoW PackageInfo; ULONG NegotiationState; } */
        PSecPkgInfoW info = (PSecPkgInfoW)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
            sizeof(SecPkgInfoW) + 64 * sizeof(WCHAR));
        if (!info) return SEC_E_INSUFFICIENT_MEMORY;
        WCHAR *nameStr = (WCHAR*)((PUCHAR)info + sizeof(SecPkgInfoW));
        WCHAR *commentStr = nameStr + 16;
        wcscpy(nameStr, TIDESSP_NAME);
        wcscpy(commentStr, TIDESSP_COMMENT);
        info->fCapabilities = SECPKG_FLAG_INTEGRITY |
                              SECPKG_FLAG_PRIVACY |
                              SECPKG_FLAG_MUTUAL_AUTH |
                              SECPKG_FLAG_ACCEPT_WIN32_NAME |
                              SECPKG_FLAG_CONNECTION |
                              SECPKG_FLAG_NEGOTIABLE2;
        info->wVersion = TIDESSP_VERSION;
        info->wRPCID = SECPKG_ID_NONE;
        info->cbMaxToken = 4096;
        info->Name = nameStr;
        info->Comment = commentStr;
        /* Write at raw offsets: pointer(8) + ULONG(4) */
        PUCHAR p = (PUCHAR)buf;
        *(PSecPkgInfoW *)(p + 0) = info;
        *(ULONG *)(p + sizeof(void*)) = SECPKG_NEGOTIATION_COMPLETE;
        return STATUS_SUCCESS;
    }
    if (attr == SECPKG_ATTR_FLAGS) {
        tide_log("FLAGS: returning 0");
        *(ULONG *)buf = 0;
        return STATUS_SUCCESS;
    }
    if (attr == SECPKG_ATTR_ACCESS_TOKEN) {
        PTIDE_CONTEXT ctx = (PTIDE_CONTEXT)h;
        if (ctx && ctx->LogonToken) {
            /* SecPkgContext_AccessToken: { void *AccessToken; } */
            *(HANDLE *)buf = ctx->LogonToken;
            tide_log("ACCESS_TOKEN: returning logon token %p", ctx->LogonToken);
            return STATUS_SUCCESS;
        }
        tide_log("ACCESS_TOKEN: no logon token available");
        return SEC_E_NO_CREDENTIALS;
    }
    tide_log("QueryContextAttributes: UNKNOWN attr=%u (0x%X) — returning SEC_E_UNSUPPORTED_FUNCTION", attr, attr);
    return SEC_E_UNSUPPORTED_FUNCTION;
}

/* ══════════════════════════════════════════════════════════════════
 *  LogonUserEx2 — passwordless desktop logon via credType=6
 *
 *  Called by LSA when termsrv receives TSRemoteGuardCreds with
 *  packageName="TideSSP".  We look up the username from the NLA
 *  session map (keyed by session key in the credential buffer),
 *  then create a logon token via GetAuthDataForUser + ConvertAuthDataToToken.
 *  LSA uses the returned TOKEN_INFORMATION_V2 to create the desktop session.
 * ══════════════════════════════════════════════════════════════════ */

/* ══════════════════════════════════════════════════════════════════
 *  Stubs for required but unused functions
 *
 *  Each returns a UNIQUE error code so we can identify which function
 *  NegoExtender is calling from the CredSSP errorCode in gateway logs.
 *  Map: errorCode → function name, to debug the failing call.
 * ══════════════════════════════════════════════════════════════════ */

/* 0x80090301 */ static NTSTATUS NTAPI TideSsp_LogonUser(void *a,void *b,void *c,void *d,void *e,void *f,void *g,void *h,void *i,void *j,void *k,void *l,void *m,void *n) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j;(void)k;(void)l;(void)m;(void)n;
    tide_log("LogonUser (V1) called — not implemented");
    return (NTSTATUS)0x80090301L; /* SEC_E_INVALID_HANDLE → LogonUser */
}

/* 0x80090306 */ static NTSTATUS NTAPI TideSsp_CallPackage(void *a, void *b, void *c, void *d, void *e, void *f) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;
    return (NTSTATUS)0x80090306L; /* SEC_E_NOT_OWNER → CallPackage */
}

static void NTAPI TideSsp_LogonTerminated(PLUID LogonId) {
    (void)LogonId;
}

/* 0x80090307 */ static NTSTATUS NTAPI TideSsp_CallPackageUntrusted(void *a, void *b, void *c, void *d, void *e, void *f) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;
    return (NTSTATUS)0x80090307L; /* SEC_E_CANNOT_INSTALL → CallPackageUntrusted */
}

/* 0x80090309 */ static NTSTATUS NTAPI TideSsp_CallPackagePassthrough(void *a, void *b, void *c, void *d, void *e, void *f) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;
    return (NTSTATUS)0x80090309L; /* SEC_E_CANNOT_PACK → CallPackagePassthrough */
}

/* 0x8009030A */ static NTSTATUS NTAPI TideSsp_LogonUserEx(void *a,void *b,void *c,void *d,void *e,void *f,void *g,void *h,void *i,void *j,void *k,void *l,void *m,void *n,void *o) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j;(void)k;(void)l;(void)m;(void)n;(void)o;
    return (NTSTATUS)0x8009030AL; /* SEC_E_QOP_NOT_SUPPORTED → LogonUserEx */
}

/* 0x8009030B */ static NTSTATUS NTAPI TideSsp_LogonUserEx2(void *a,void *b,void *c,void *d,void *e,void *f,void *g,void *h,void *i,void *j,void *k,void *l,void *m,void *n,void *o,void *p) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j;(void)k;(void)l;(void)m;(void)n;(void)o;(void)p;
    return (NTSTATUS)0x8009030BL; /* SEC_E_NO_IMPERSONATION → LogonUserEx2 */
}

/* unique: 0xC0040001 → InitLsaModeContext was called (shouldn't happen on server) */
static NTSTATUS NTAPI TideSsp_InitLsaModeContext(
    LSA_SEC_HANDLE a, LSA_SEC_HANDLE b, PUNICODE_STRING c,
    ULONG d, ULONG e, PSecBufferDesc f, PLSA_SEC_HANDLE g,
    PSecBufferDesc h, PULONG i, PTimeStamp j, PBOOLEAN k, PSecBuffer l)
{
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j;(void)k;(void)l;
    tide_log("InitLsaModeContext CALLED (unexpected!)");
    return (NTSTATUS)0xC0040001L;
}

static NTSTATUS NTAPI TideSsp_AcquireCredentialsHandle(
    PUNICODE_STRING a, ULONG b, PLUID c, PVOID d, PVOID e,
    PVOID f, PLSA_SEC_HANDLE g, PTimeStamp h)
{
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;
    *g = 1;
    if (h) { h->LowPart = 0xFFFFFFFF; h->HighPart = 0x7FFFFFFF; }
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI TideSsp_FreeCredentialsHandle(LSA_SEC_HANDLE h) {
    (void)h;
    return STATUS_SUCCESS;
}

/* 0x8009030D */ static NTSTATUS NTAPI TideSsp_QueryCredentialsAttributes(LSA_SEC_HANDLE h, ULONG a, PVOID b) {
    (void)h;(void)a;(void)b;
    return (NTSTATUS)0x8009030DL; /* SEC_E_UNKNOWN_CREDENTIALS → QueryCredentialsAttributes */
}

/* 0x80090310 */ static NTSTATUS NTAPI TideSsp_SaveCredentials(LSA_SEC_HANDLE a, PSecBuffer b) {
    (void)a;(void)b;
    return (NTSTATUS)0x80090310L; /* SEC_E_OUT_OF_SEQUENCE → SaveCredentials */
}

/* 0x80090311 */ static NTSTATUS NTAPI TideSsp_GetCredentials(LSA_SEC_HANDLE a, PSecBuffer b) {
    (void)a;(void)b;
    return (NTSTATUS)0x80090311L; /* SEC_E_NO_AUTHENTICATING_AUTHORITY → GetCredentials */
}

/* 0x80090312 */ static NTSTATUS NTAPI TideSsp_DeleteCredentials(LSA_SEC_HANDLE a, PSecBuffer b) {
    (void)a;(void)b;
    return (NTSTATUS)0x80090312L; /* SEC_E_BAD_PKGID → DeleteCredentials */
}

/* 0x80090313 */ static NTSTATUS NTAPI TideSsp_SetContextAttributes(LSA_SEC_HANDLE h, ULONG a, PVOID b, ULONG c) {
    (void)h;(void)a;(void)b;(void)c;
    return (NTSTATUS)0x80090313L; /* SEC_E_CONTEXT_EXPIRED → SetContextAttributes */
}

/* 0x80090317 */ static NTSTATUS NTAPI TideSsp_ApplyControlToken(LSA_SEC_HANDLE h, PSecBufferDesc b) {
    (void)h;(void)b;
    return (NTSTATUS)0x80090317L; /* SEC_E_INCOMPLETE_MESSAGE → ApplyControlToken */
}

/* ══════════════════════════════════════════════════════════════════
 *  User-mode component — SealMessage/UnsealMessage for CredSSP
 *
 *  After NEGOEX auth completes, CredSSP calls EncryptMessage /
 *  DecryptMessage via the Negotiate SSP. Negotiate dispatches to
 *  our user-mode SealMessage/UnsealMessage.
 *
 *  Encryption: AES-128-GCM with random 12-byte nonce.
 *  Wire format (must match gateway's TypeScript implementation):
 *    SECBUFFER_TOKEN (28 bytes): [12-byte nonce] [16-byte GCM tag]
 *    SECBUFFER_DATA:             AES-GCM ciphertext (same length)
 * ══════════════════════════════════════════════════════════════════ */

/* User-mode context: holds session key for encryption */
typedef struct _TIDE_USER_CONTEXT {
    UCHAR  SessionKey[SESSION_KEY_SIZE];
    ULONG  SeqNum;
    HANDLE LogonToken;  /* S4U token duplicated from lsass */
} TIDE_USER_CONTEXT, *PTIDE_USER_CONTEXT;

/* Simple context table (max 16 concurrent sessions) */
#define MAX_USER_CTX 16
static struct {
    ULONG_PTR        Handle;
    TIDE_USER_CONTEXT Ctx;
    BOOLEAN          Valid;
} g_UserCtxTable[MAX_USER_CTX];
static CRITICAL_SECTION g_UserCtxLock;
static BOOLEAN g_UserCtxLockInit = FALSE;

static void tide_user_ctx_init(void) {
    if (!g_UserCtxLockInit) {
        InitializeCriticalSection(&g_UserCtxLock);
        g_UserCtxLockInit = TRUE;
    }
}

static PTIDE_USER_CONTEXT tide_user_ctx_create(ULONG_PTR handle, const UCHAR *key) {
    tide_user_ctx_init();
    EnterCriticalSection(&g_UserCtxLock);
    for (int i = 0; i < MAX_USER_CTX; i++) {
        if (!g_UserCtxTable[i].Valid) {
            g_UserCtxTable[i].Handle = handle;
            memcpy(g_UserCtxTable[i].Ctx.SessionKey, key, SESSION_KEY_SIZE);
            g_UserCtxTable[i].Ctx.SeqNum = 0;
            g_UserCtxTable[i].Valid = TRUE;
            LeaveCriticalSection(&g_UserCtxLock);
            return &g_UserCtxTable[i].Ctx;
        }
    }
    LeaveCriticalSection(&g_UserCtxLock);
    return NULL;
}

static PTIDE_USER_CONTEXT tide_user_ctx_find(ULONG_PTR handle) {
    tide_user_ctx_init();
    EnterCriticalSection(&g_UserCtxLock);
    for (int i = 0; i < MAX_USER_CTX; i++) {
        if (g_UserCtxTable[i].Valid && g_UserCtxTable[i].Handle == handle) {
            LeaveCriticalSection(&g_UserCtxLock);
            return &g_UserCtxTable[i].Ctx;
        }
    }
    LeaveCriticalSection(&g_UserCtxLock);
    return NULL;
}

static void tide_user_ctx_delete(ULONG_PTR handle) {
    tide_user_ctx_init();
    EnterCriticalSection(&g_UserCtxLock);
    for (int i = 0; i < MAX_USER_CTX; i++) {
        if (g_UserCtxTable[i].Valid && g_UserCtxTable[i].Handle == handle) {
            SecureZeroMemory(&g_UserCtxTable[i].Ctx, sizeof(TIDE_USER_CONTEXT));
            g_UserCtxTable[i].Valid = FALSE;
            break;
        }
    }
    LeaveCriticalSection(&g_UserCtxLock);
}

/* ── AES-128-GCM encrypt ─────────────────────────────────────── */

static NTSTATUS tide_gcm_encrypt(
    const UCHAR key[SESSION_KEY_SIZE],
    PUCHAR plaintext, ULONG cbPlaintext,
    UCHAR nonce[TIDE_GCM_NONCE_SIZE],
    UCHAR tag[TIDE_GCM_TAG_SIZE])
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return status;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return status; }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
        (PUCHAR)key, SESSION_KEY_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return status; }

    /* Generate random nonce */
    BCryptGenRandom(NULL, nonce, TIDE_GCM_NONCE_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = TIDE_GCM_NONCE_SIZE;
    authInfo.pbTag = tag;
    authInfo.cbTag = TIDE_GCM_TAG_SIZE;

    ULONG cbResult = 0;
    /* Encrypt in place */
    status = BCryptEncrypt(hKey, plaintext, cbPlaintext, &authInfo,
        NULL, 0, plaintext, cbPlaintext, &cbResult, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return status;
}

/* ── AES-128-GCM decrypt ─────────────────────────────────────── */

static NTSTATUS tide_gcm_decrypt(
    const UCHAR key[SESSION_KEY_SIZE],
    PUCHAR ciphertext, ULONG cbCiphertext,
    const UCHAR nonce[TIDE_GCM_NONCE_SIZE],
    const UCHAR tag[TIDE_GCM_TAG_SIZE])
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return status;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return status; }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
        (PUCHAR)key, SESSION_KEY_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return status; }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = TIDE_GCM_NONCE_SIZE;
    authInfo.pbTag = (PUCHAR)tag;
    authInfo.cbTag = TIDE_GCM_TAG_SIZE;

    ULONG cbResult = 0;
    status = BCryptDecrypt(hKey, ciphertext, cbCiphertext, &authInfo,
        NULL, 0, ciphertext, cbCiphertext, &cbResult, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return status;
}

/* ── User-mode: SpInstanceInit ──────────────────────────────────── */

static NTSTATUS NTAPI TideSsp_InstanceInit(
    ULONG Version,
    PSECPKG_DLL_FUNCTIONS DllFunctionTable,
    PVOID *UserFunctionTable)
{
    (void)Version; (void)DllFunctionTable; (void)UserFunctionTable;
    tide_log("InstanceInit (user-mode)");
    tide_user_ctx_init();
    return STATUS_SUCCESS;
}

/* ── User-mode: SpInitUserModeContext ───────────────────────────── */

static NTSTATUS NTAPI TideSsp_InitUserModeContext(
    ULONG_PTR ContextHandle,
    PSecBuffer PackedContext)
{
    tide_log("InitUserModeContext: handle=%p, cbBuffer=%u",
             (void*)ContextHandle, PackedContext ? PackedContext->cbBuffer : 0);

    if (!PackedContext || !PackedContext->pvBuffer ||
        PackedContext->cbBuffer < SESSION_KEY_SIZE) {
        tide_log("InitUserModeContext: invalid packed context");
        return SEC_E_INVALID_TOKEN;
    }

    PTIDE_USER_CONTEXT uctx = tide_user_ctx_create(
        ContextHandle, (const UCHAR *)PackedContext->pvBuffer);
    if (!uctx) {
        tide_log("InitUserModeContext: too many contexts");
        return SEC_E_INSUFFICIENT_MEMORY;
    }

    /* Extract duplicated token handle if present */
    if (PackedContext->cbBuffer >= SESSION_KEY_SIZE + sizeof(HANDLE)) {
        memcpy(&uctx->LogonToken,
               (const UCHAR *)PackedContext->pvBuffer + SESSION_KEY_SIZE,
               sizeof(HANDLE));
        tide_log("InitUserModeContext: logon token=%p", uctx->LogonToken);
    } else {
        uctx->LogonToken = NULL;
    }

    tide_log("InitUserModeContext: created user-mode context, key=%02x%02x%02x%02x...",
             uctx->SessionKey[0], uctx->SessionKey[1],
             uctx->SessionKey[2], uctx->SessionKey[3]);
    return STATUS_SUCCESS;
}

/* ── User-mode: SealMessage (EncryptMessage) ────────────────────── */

static NTSTATUS NTAPI TideSsp_SealMessage(
    ULONG_PTR ContextHandle,
    ULONG QualityOfProtection,
    PSecBufferDesc MessageBuffers,
    ULONG MessageSequenceNumber)
{
    (void)QualityOfProtection;
    (void)MessageSequenceNumber;

    PTIDE_USER_CONTEXT uctx = tide_user_ctx_find(ContextHandle);
    if (!uctx) {
        tide_log("SealMessage: context not found for handle=%p", (void*)ContextHandle);
        return SEC_E_INVALID_HANDLE;
    }

    /* Log all buffer types */
    tide_log("SealMessage: %u buffers", MessageBuffers->cBuffers);
    for (ULONG i = 0; i < MessageBuffers->cBuffers; i++) {
        tide_log("  buf[%u]: type=%u, cb=%u, pv=%p",
                 i, MessageBuffers->pBuffers[i].BufferType,
                 MessageBuffers->pBuffers[i].cbBuffer,
                 MessageBuffers->pBuffers[i].pvBuffer);
    }

    /* Find TOKEN, DATA, and PADDING buffers */
    PSecBuffer tokenBuf = NULL, dataBuf = NULL, paddingBuf = NULL;
    for (ULONG i = 0; i < MessageBuffers->cBuffers; i++) {
        ULONG btype = MessageBuffers->pBuffers[i].BufferType & 0x0FFFFFFF;
        if (btype == SECBUFFER_TOKEN)
            tokenBuf = &MessageBuffers->pBuffers[i];
        else if (btype == SECBUFFER_DATA)
            dataBuf = &MessageBuffers->pBuffers[i];
        else if (btype == SECBUFFER_PADDING)
            paddingBuf = &MessageBuffers->pBuffers[i];
    }

    if (!tokenBuf || !dataBuf || !tokenBuf->pvBuffer || !dataBuf->pvBuffer) {
        tide_log("SealMessage: missing TOKEN or DATA buffer");
        return SEC_E_INVALID_TOKEN;
    }
    if (tokenBuf->cbBuffer < TIDE_TOKEN_SIZE) {
        tide_log("SealMessage: TOKEN buffer too small (%u < %u)",
                 tokenBuf->cbBuffer, TIDE_TOKEN_SIZE);
        return SEC_E_BUFFER_TOO_SMALL;
    }

    PUCHAR token = (PUCHAR)tokenBuf->pvBuffer;
    PUCHAR nonce = token;            /* first 12 bytes */
    PUCHAR tag   = token + TIDE_GCM_NONCE_SIZE;  /* next 16 bytes */

    tide_log("SealMessage: encrypting %u bytes", dataBuf->cbBuffer);

    NTSTATUS status = tide_gcm_encrypt(
        uctx->SessionKey,
        (PUCHAR)dataBuf->pvBuffer, dataBuf->cbBuffer,
        nonce, tag);

    if (BCRYPT_SUCCESS(status)) {
        tokenBuf->cbBuffer = TIDE_TOKEN_SIZE;
        /* AES-GCM is a stream cipher — no padding needed.
         * Set PADDING buffer to 0 so CredSSP doesn't include extra bytes. */
        if (paddingBuf) {
            paddingBuf->cbBuffer = 0;
        }
        tide_log("SealMessage: OK, nonce=%02x%02x%02x%02x, tag=%02x%02x%02x%02x",
                 nonce[0],nonce[1],nonce[2],nonce[3],
                 tag[0],tag[1],tag[2],tag[3]);
    } else {
        tide_log("SealMessage: GCM encrypt failed 0x%08X", status);
    }
    return status;
}

/* ── User-mode: UnsealMessage (DecryptMessage) ──────────────────── */

static NTSTATUS NTAPI TideSsp_UnsealMessage(
    ULONG_PTR ContextHandle,
    PSecBufferDesc MessageBuffers,
    ULONG MessageSequenceNumber,
    PULONG QualityOfProtection)
{
    (void)MessageSequenceNumber;
    if (QualityOfProtection) *QualityOfProtection = 0;

    PTIDE_USER_CONTEXT uctx = tide_user_ctx_find(ContextHandle);
    if (!uctx) {
        tide_log("UnsealMessage: context not found for handle=%p", (void*)ContextHandle);
        return SEC_E_INVALID_HANDLE;
    }

    /* Log all buffer types for debugging */
    tide_log("UnsealMessage: %u buffers", MessageBuffers->cBuffers);
    for (ULONG i = 0; i < MessageBuffers->cBuffers; i++) {
        tide_log("  buf[%u]: type=%u, cb=%u, pv=%p",
                 i, MessageBuffers->pBuffers[i].BufferType,
                 MessageBuffers->pBuffers[i].cbBuffer,
                 MessageBuffers->pBuffers[i].pvBuffer);
    }

    PSecBuffer tokenBuf = NULL, dataBuf = NULL, streamBuf = NULL;
    for (ULONG i = 0; i < MessageBuffers->cBuffers; i++) {
        ULONG btype = MessageBuffers->pBuffers[i].BufferType & 0x0FFFFFFF;
        if (btype == SECBUFFER_TOKEN)
            tokenBuf = &MessageBuffers->pBuffers[i];
        else if (btype == SECBUFFER_DATA)
            dataBuf = &MessageBuffers->pBuffers[i];
        else if (btype == SECBUFFER_STREAM)
            streamBuf = &MessageBuffers->pBuffers[i];
    }

    /* SECBUFFER_STREAM mode: entire encrypted blob in one buffer */
    if (streamBuf && streamBuf->pvBuffer && streamBuf->cbBuffer >= TIDE_TOKEN_SIZE) {
        PUCHAR stream = (PUCHAR)streamBuf->pvBuffer;
        ULONG cbStream = streamBuf->cbBuffer;
        const UCHAR *nonce = stream;
        const UCHAR *tag   = stream + TIDE_GCM_NONCE_SIZE;
        PUCHAR ciphertext  = stream + TIDE_TOKEN_SIZE;
        ULONG cbCiphertext = cbStream - TIDE_TOKEN_SIZE;

        tide_log("UnsealMessage STREAM: total=%u, ciphertext=%u", cbStream, cbCiphertext);

        NTSTATUS status = tide_gcm_decrypt(uctx->SessionKey,
            ciphertext, cbCiphertext, nonce, tag);

        if (BCRYPT_SUCCESS(status)) {
            /* Point DATA buffer to decrypted plaintext within the stream */
            if (dataBuf) {
                dataBuf->pvBuffer = ciphertext;
                dataBuf->cbBuffer = cbCiphertext;
                dataBuf->BufferType = SECBUFFER_DATA;
            }
            /* Shrink STREAM to just the token portion */
            streamBuf->cbBuffer = TIDE_TOKEN_SIZE;
            tide_log("UnsealMessage STREAM: OK, plaintext=%u bytes", cbCiphertext);
            /* Log decrypted bytes for pubKeyAuth hash debugging */
            if (cbCiphertext <= 64) {
                char hex[129]; hex[0] = '\0';
                for (ULONG j = 0; j < cbCiphertext && j < 64; j++) {
                    char tmp[4]; sprintf(tmp, "%02x", ciphertext[j]);
                    strcat(hex, tmp);
                }
                tide_log("UnsealMessage STREAM: plaintext hex: %s", hex);
            }
        } else {
            tide_log("UnsealMessage STREAM: GCM decrypt failed 0x%08X", status);
            return (NTSTATUS)SEC_E_MESSAGE_ALTERED;
        }
        return STATUS_SUCCESS;
    }

    /* TOKEN+DATA mode */
    if (!tokenBuf || !dataBuf || !tokenBuf->pvBuffer || !dataBuf->pvBuffer) {
        tide_log("UnsealMessage: missing TOKEN or DATA buffer");
        return SEC_E_INVALID_TOKEN;
    }
    if (tokenBuf->cbBuffer < TIDE_TOKEN_SIZE) {
        tide_log("UnsealMessage: TOKEN too small (%u < %u)", tokenBuf->cbBuffer, TIDE_TOKEN_SIZE);
        return SEC_E_INVALID_TOKEN;
    }

    PUCHAR token = (PUCHAR)tokenBuf->pvBuffer;
    const UCHAR *nonce = token;
    const UCHAR *tag   = token + TIDE_GCM_NONCE_SIZE;

    tide_log("UnsealMessage TOKEN+DATA: decrypting %u bytes", dataBuf->cbBuffer);

    NTSTATUS status = tide_gcm_decrypt(
        uctx->SessionKey,
        (PUCHAR)dataBuf->pvBuffer, dataBuf->cbBuffer,
        nonce, tag);

    if (BCRYPT_SUCCESS(status)) {
        tide_log("UnsealMessage: OK");
    } else {
        tide_log("UnsealMessage: GCM decrypt failed 0x%08X", status);
        return (NTSTATUS)SEC_E_MESSAGE_ALTERED;
    }
    return STATUS_SUCCESS;
}

/* ── User-mode: MakeSignature ───────────────────────────────────── */

static NTSTATUS NTAPI TideSsp_MakeSignature(
    ULONG_PTR ContextHandle,
    ULONG QualityOfProtection,
    PSecBufferDesc MessageBuffers,
    ULONG MessageSequenceNumber)
{
    (void)QualityOfProtection;
    (void)MessageSequenceNumber;
    /* Use SealMessage with zero-length data trick: encrypt empty, sign the data as AAD.
     * For simplicity, just use HMAC-SHA-256 truncated to 16 bytes. */
    PTIDE_USER_CONTEXT uctx = tide_user_ctx_find(ContextHandle);
    if (!uctx) return SEC_E_INVALID_HANDLE;

    PSecBuffer tokenBuf = NULL, dataBuf = NULL;
    for (ULONG i = 0; i < MessageBuffers->cBuffers; i++) {
        if (MessageBuffers->pBuffers[i].BufferType == SECBUFFER_TOKEN)
            tokenBuf = &MessageBuffers->pBuffers[i];
        else if (MessageBuffers->pBuffers[i].BufferType == SECBUFFER_DATA)
            dataBuf = &MessageBuffers->pBuffers[i];
    }
    if (!tokenBuf || !dataBuf) return SEC_E_INVALID_TOKEN;
    if (tokenBuf->cbBuffer < 16) return SEC_E_BUFFER_TOO_SMALL;

    /* HMAC-SHA-256(session_key, data)[0:16] */
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    UCHAR hmac[32];

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    BCryptCreateHash(hAlg, &hHash, NULL, 0, uctx->SessionKey, SESSION_KEY_SIZE, 0);
    BCryptHashData(hHash, (PUCHAR)dataBuf->pvBuffer, dataBuf->cbBuffer, 0);
    BCryptFinishHash(hHash, hmac, 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    memcpy(tokenBuf->pvBuffer, hmac, 16);
    tokenBuf->cbBuffer = 16;
    tide_log("MakeSignature: HMAC over %u bytes", dataBuf->cbBuffer);
    return STATUS_SUCCESS;
}

/* ── User-mode: VerifySignature ─────────────────────────────────── */

static NTSTATUS NTAPI TideSsp_VerifySignature(
    ULONG_PTR ContextHandle,
    PSecBufferDesc MessageBuffers,
    ULONG MessageSequenceNumber,
    PULONG QualityOfProtection)
{
    (void)MessageSequenceNumber;
    if (QualityOfProtection) *QualityOfProtection = 0;

    PTIDE_USER_CONTEXT uctx = tide_user_ctx_find(ContextHandle);
    if (!uctx) return SEC_E_INVALID_HANDLE;

    PSecBuffer tokenBuf = NULL, dataBuf = NULL;
    for (ULONG i = 0; i < MessageBuffers->cBuffers; i++) {
        if (MessageBuffers->pBuffers[i].BufferType == SECBUFFER_TOKEN)
            tokenBuf = &MessageBuffers->pBuffers[i];
        else if (MessageBuffers->pBuffers[i].BufferType == SECBUFFER_DATA)
            dataBuf = &MessageBuffers->pBuffers[i];
    }
    if (!tokenBuf || !dataBuf) return SEC_E_INVALID_TOKEN;
    if (tokenBuf->cbBuffer < 16) return SEC_E_MESSAGE_ALTERED;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    UCHAR hmac[32];

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    BCryptCreateHash(hAlg, &hHash, NULL, 0, uctx->SessionKey, SESSION_KEY_SIZE, 0);
    BCryptHashData(hHash, (PUCHAR)dataBuf->pvBuffer, dataBuf->cbBuffer, 0);
    BCryptFinishHash(hHash, hmac, 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (memcmp(tokenBuf->pvBuffer, hmac, 16) != 0) {
        tide_log("VerifySignature: MISMATCH");
        return (NTSTATUS)SEC_E_MESSAGE_ALTERED;
    }
    tide_log("VerifySignature: OK");
    return STATUS_SUCCESS;
}

/* ── User-mode: QueryContextAttributes ──────────────────────────── */

static NTSTATUS NTAPI TideSsp_UserQueryContextAttributes(
    ULONG_PTR ContextHandle,
    ULONG Attribute,
    PVOID Buffer)
{
    (void)ContextHandle;
    tide_log("User QueryContextAttributes: attr=%u", Attribute);

    if (Attribute == SECPKG_ATTR_SIZES) {
        PSecPkgContext_Sizes sizes = (PSecPkgContext_Sizes)Buffer;
        sizes->cbMaxToken = 4096;
        sizes->cbMaxSignature = 16;           /* HMAC-SHA-256 truncated */
        sizes->cbBlockSize = 1;               /* GCM has no block alignment */
        sizes->cbSecurityTrailer = TIDE_TOKEN_SIZE;  /* 28 bytes: nonce+tag */
        tide_log("User SIZES: trailer=%u, sig=%u", TIDE_TOKEN_SIZE, 16);
        return STATUS_SUCCESS;
    }
    if (Attribute == SECPKG_ATTR_SESSION_KEY) {
        PTIDE_USER_CONTEXT uctx = tide_user_ctx_find(ContextHandle);
        if (!uctx) return SEC_E_INVALID_HANDLE;
        SecPkgContext_SessionKey *sk = (SecPkgContext_SessionKey *)Buffer;
        PUCHAR key = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, SESSION_KEY_SIZE);
        if (!key) return SEC_E_INSUFFICIENT_MEMORY;
        memcpy(key, uctx->SessionKey, SESSION_KEY_SIZE);
        sk->SessionKeyLength = SESSION_KEY_SIZE;
        sk->SessionKey = key;
        return STATUS_SUCCESS;
    }
    if (Attribute == SECPKG_ATTR_ACCESS_TOKEN) {
        PTIDE_USER_CONTEXT uctx = tide_user_ctx_find(ContextHandle);
        if (!uctx) return SEC_E_INVALID_HANDLE;
        if (uctx->LogonToken) {
            HANDLE dup = NULL;
            if (!DuplicateHandle(GetCurrentProcess(), uctx->LogonToken,
                                 GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                tide_log("User ACCESS_TOKEN: DuplicateHandle failed");
                return SEC_E_INTERNAL_ERROR;
            }
            *(HANDLE *)Buffer = dup;
            tide_log("User ACCESS_TOKEN: returning %p (dup of %p)", dup, uctx->LogonToken);
            return STATUS_SUCCESS;
        }
        tide_log("User ACCESS_TOKEN: no token");
        return SEC_E_NO_CREDENTIALS;
    }
    if (Attribute == SECPKG_ATTR_PACKAGE_INFO) {
        tide_log("User PACKAGE_INFO: returning TideSSP info");
        PSecPkgInfoW info = (PSecPkgInfoW)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
            sizeof(SecPkgInfoW) + 64 * sizeof(WCHAR));
        if (!info) return SEC_E_INSUFFICIENT_MEMORY;
        WCHAR *nameStr = (WCHAR*)((PUCHAR)info + sizeof(SecPkgInfoW));
        WCHAR *commentStr = nameStr + 16;
        wcscpy(nameStr, TIDESSP_NAME);
        wcscpy(commentStr, TIDESSP_COMMENT);
        info->fCapabilities = SECPKG_FLAG_INTEGRITY |
                              SECPKG_FLAG_PRIVACY |
                              SECPKG_FLAG_MUTUAL_AUTH |
                              SECPKG_FLAG_ACCEPT_WIN32_NAME |
                              SECPKG_FLAG_CONNECTION |
                              SECPKG_FLAG_NEGOTIABLE2;
        info->wVersion = TIDESSP_VERSION;
        info->wRPCID = SECPKG_ID_NONE;
        info->cbMaxToken = 4096;
        info->Name = nameStr;
        info->Comment = commentStr;
        *(PSecPkgInfoW *)Buffer = info;
        return STATUS_SUCCESS;
    }
    if (Attribute == SECPKG_ATTR_NEGOTIATION_INFO) {
        tide_log("User NEGOTIATION_INFO: returning complete");
        PSecPkgInfoW info = (PSecPkgInfoW)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
            sizeof(SecPkgInfoW) + 64 * sizeof(WCHAR));
        if (!info) return SEC_E_INSUFFICIENT_MEMORY;
        WCHAR *nameStr = (WCHAR*)((PUCHAR)info + sizeof(SecPkgInfoW));
        WCHAR *commentStr = nameStr + 16;
        wcscpy(nameStr, TIDESSP_NAME);
        wcscpy(commentStr, TIDESSP_COMMENT);
        info->fCapabilities = SECPKG_FLAG_INTEGRITY |
                              SECPKG_FLAG_PRIVACY |
                              SECPKG_FLAG_MUTUAL_AUTH |
                              SECPKG_FLAG_ACCEPT_WIN32_NAME |
                              SECPKG_FLAG_CONNECTION |
                              SECPKG_FLAG_NEGOTIABLE2;
        info->wVersion = TIDESSP_VERSION;
        info->wRPCID = SECPKG_ID_NONE;
        info->cbMaxToken = 4096;
        info->Name = nameStr;
        info->Comment = commentStr;
        PUCHAR p = (PUCHAR)Buffer;
        *(PSecPkgInfoW *)(p + 0) = info;
        *(ULONG *)(p + sizeof(void*)) = SECPKG_NEGOTIATION_COMPLETE;
        return STATUS_SUCCESS;
    }
    if (Attribute == SECPKG_ATTR_FLAGS) {
        tide_log("User FLAGS: returning 0");
        *(ULONG *)Buffer = 0;
        return STATUS_SUCCESS;
    }
    tide_log("User QueryContextAttributes: UNKNOWN attr=%u (0x%X)", Attribute, Attribute);
    return SEC_E_UNSUPPORTED_FUNCTION;
}

/* ── User-mode: GetContextToken ─────────────────────────────────── */

static NTSTATUS NTAPI TideSsp_GetContextToken(
    ULONG_PTR ContextHandle,
    PHANDLE Token)
{
    tide_log("GetContextToken: handle=%p", (void*)ContextHandle);
    PTIDE_USER_CONTEXT uctx = tide_user_ctx_find(ContextHandle);
    if (!uctx) return SEC_E_INVALID_HANDLE;
    if (!uctx->LogonToken) {
        tide_log("GetContextToken: no logon token");
        return SEC_E_NO_CREDENTIALS;
    }
    /* Duplicate so caller owns the handle (survives DeleteUserModeContext) */
    HANDLE dup = NULL;
    if (!DuplicateHandle(GetCurrentProcess(), uctx->LogonToken,
                         GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        tide_log("GetContextToken: DuplicateHandle failed (%lu)", GetLastError());
        return SEC_E_INTERNAL_ERROR;
    }
    *Token = dup;
    tide_log("GetContextToken: returning %p (dup of %p)", dup, uctx->LogonToken);
    return STATUS_SUCCESS;
}

/* ── User-mode: DeleteContext ───────────────────────────────────── */

static NTSTATUS NTAPI TideSsp_DeleteUserModeContext(ULONG_PTR ContextHandle)
{
    tide_log("DeleteUserModeContext: handle=%p", (void*)ContextHandle);
    /* Close the duplicated token before deleting context */
    PTIDE_USER_CONTEXT uctx = tide_user_ctx_find(ContextHandle);
    if (uctx && uctx->LogonToken) {
        CloseHandle(uctx->LogonToken);
        uctx->LogonToken = NULL;
    }
    tide_user_ctx_delete(ContextHandle);
    return STATUS_SUCCESS;
}

/* ── User-mode function table ───────────────────────────────────── */

static SECPKG_USER_FUNCTION_TABLE TideSSP_UserFunctionTable = {
    (SpInstanceInitFn *)TideSsp_InstanceInit,
    (SpInitUserModeContextFn *)TideSsp_InitUserModeContext,
    (SpMakeSignatureFn *)TideSsp_MakeSignature,
    (SpVerifySignatureFn *)TideSsp_VerifySignature,
    (SpSealMessageFn *)TideSsp_SealMessage,
    (SpUnsealMessageFn *)TideSsp_UnsealMessage,
    (SpGetContextTokenFn *)TideSsp_GetContextToken,
    (SpQueryContextAttributesFn *)TideSsp_UserQueryContextAttributes,
    NULL, /* CompleteAuthToken */
    (SpDeleteContextFn *)TideSsp_DeleteUserModeContext,
    NULL, /* FormatCredentials */
    NULL, /* MarshallSupplementalCreds */
    NULL, /* ExportContext */
    NULL, /* ImportContext */
};

/* ── SpUserModeInitialize export ────────────────────────────────── */

NTSTATUS NTAPI SpUserModeInitialize(
    ULONG LsaVersion,
    PULONG PackageVersion,
    PSECPKG_USER_FUNCTION_TABLE *ppTables,
    PULONG pcTables)
{
    (void)LsaVersion;
    tide_log("SpUserModeInitialize called");
    *PackageVersion = SECPKG_INTERFACE_VERSION;
    *ppTables = &TideSSP_UserFunctionTable;
    *pcTables = 1;
    return STATUS_SUCCESS;
}

/* ══════════════════════════════════════════════════════════════════
 *  Function table — V5+ layout for NegoExtender compatibility
 *
 *  The struct must have ALL fields in order through V5 so that
 *  NegoExtender can find QueryMetaData/ExchangeMetaData at the
 *  correct offsets.
 * ══════════════════════════════════════════════════════════════════ */

SECPKG_FUNCTION_TABLE TideSSP_FunctionTable = {
    /* V1 — basic SSP */
    .InitializePackage          = NULL,
    .LogonUser                  = NULL,
    .CallPackage                = (PLSA_AP_CALL_PACKAGE)TideSsp_CallPackage,
    .LogonTerminated            = (PLSA_AP_LOGON_TERMINATED)TideSsp_LogonTerminated,
    .CallPackageUntrusted       = (PLSA_AP_CALL_PACKAGE_PASSTHROUGH)TideSsp_CallPackageUntrusted,
    .CallPackagePassthrough     = (PLSA_AP_CALL_PACKAGE_PASSTHROUGH)TideSsp_CallPackagePassthrough,
    .LogonUserEx                = NULL,
    .LogonUserEx2               = NULL,
    .Initialize                 = (SpInitializeFn *)TideSsp_Initialize,
    .Shutdown                   = (SpShutdownFn *)TideSsp_Shutdown,
    .GetInfo                    = (SpGetInfoFn *)TideSsp_GetInfo,
    .AcceptCredentials          = NULL,
    .AcquireCredentialsHandle   = (SpAcquireCredentialsHandleFn *)TideSsp_AcquireCredentialsHandle,
    .QueryCredentialsAttributes = (SpQueryCredentialsAttributesFn *)TideSsp_QueryCredentialsAttributes,
    .FreeCredentialsHandle      = (SpFreeCredentialsHandleFn *)TideSsp_FreeCredentialsHandle,
    .SaveCredentials            = (SpSaveCredentialsFn *)TideSsp_SaveCredentials,
    .GetCredentials             = (SpGetCredentialsFn *)TideSsp_GetCredentials,
    .DeleteCredentials          = (SpDeleteCredentialsFn *)TideSsp_DeleteCredentials,
    .InitLsaModeContext         = (SpInitLsaModeContextFn *)TideSsp_InitLsaModeContext,
    .AcceptLsaModeContext       = (SpAcceptLsaModeContextFn *)TideSsp_AcceptLsaModeContext,
    .DeleteContext              = (SpDeleteContextFn *)TideSsp_DeleteContext,
    .ApplyControlToken          = (SpApplyControlTokenFn *)TideSsp_ApplyControlToken,
    .GetUserInfo                = NULL,
    /* V2 */
    .GetExtendedInformation     = (SpGetExtendedInformationFn *)TideSsp_GetExtendedInformation,
    .QueryContextAttributes     = (SpQueryContextAttributesFn *)TideSsp_QueryContextAttributes,
    /* V3 */
    .AddCredentials             = NULL,
    .SetExtendedInformation     = NULL,
    /* V4 */
    .SetContextAttributes       = (SpSetContextAttributesFn *)TideSsp_SetContextAttributes,
    /* V5 — NegoExtender */
    .SetCredentialsAttributes   = NULL,
    .ChangeAccountPassword      = NULL,
    .QueryMetaData              = (SpQueryMetaDataFn *)TideSsp_QueryMetaData,
    .ExchangeMetaData           = (SpExchangeMetaDataFn *)TideSsp_ExchangeMetaData,
    .GetCredUIContext            = NULL,
    .UpdateCredentials           = NULL,
};
