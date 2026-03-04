/*
 * TideSSP — SSPI function implementations with NegoExtender (NEGOEX) support.
 *
 * Wire protocol tokens:
 *   NEGOTIATE  [0x01][version:u8][username_len:u16LE][username:UTF-8]
 *   CHALLENGE  [0x02][challenge:32 bytes]
 *   AUTHENTICATE [0x03][signature:64 bytes][pubkey:32 bytes]
 *
 * Flow (server side — AcceptSecurityContext):
 *   1. Receive NEGOTIATE → extract username, generate challenge → return CHALLENGE
 *   2. Receive AUTHENTICATE → verify Ed25519(pubkey, challenge, sig) → logon user
 *
 * NegoEx integration:
 *   - SECPKG_FLAG_NEGOTIABLE2 flag in SpGetInfo tells NegoExtender to include us
 *   - SpGetExtendedInformation returns our AuthScheme GUID for NEGOEX negotiation
 *   - Session key derived from SHA-256(challenge || signature || pubkey) for VERIFY
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
#include <wincrypt.h>
#include <bcrypt.h>

#include "ed25519.h"

/* ── Package identity ─────────────────────────────────────────── */

#define TIDESSP_NAME      L"TideSSP"
#define TIDESSP_NAME_A    "TideSSP"
#define TIDESSP_COMMENT   L"Tide Ed25519 Authentication"
#define TIDESSP_VERSION   1

/* NegoEx flag — tells NegoExtender to discover this package */
#ifndef SECPKG_FLAG_NEGOTIABLE2
#define SECPKG_FLAG_NEGOTIABLE2 0x00200000
#endif

/* ── TideSSP AuthScheme GUID for NEGOEX ──────────────────────── */
/* {7A4E8B2C-1F3D-4A5E-9C6B-8D7E0F1A2B3C} */
static const GUID TIDESSP_AUTH_SCHEME = {
    0x7A4E8B2C, 0x1F3D, 0x4A5E,
    {0x9C, 0x6B, 0x8D, 0x7E, 0x0F, 0x1A, 0x2B, 0x3C}
};

/* ── Token types ──────────────────────────────────────────────── */

#define TOKEN_NEGOTIATE    0x01
#define TOKEN_CHALLENGE    0x02
#define TOKEN_AUTHENTICATE 0x03

#define CHALLENGE_SIZE     32
#define SESSION_KEY_SIZE   16
#define MAX_USERNAME_LEN   256

/* ── LSA dispatch table — set by SpInitialize ─────────────────── */

static PLSA_SECPKG_FUNCTION_TABLE LsaDispatch = NULL;

/* ── Context state for in-progress authentication ─────────────── */

typedef struct _TIDE_CONTEXT {
    ULONG_PTR ContextHandle;
    UCHAR     Challenge[CHALLENGE_SIZE];
    UCHAR     SessionKey[SESSION_KEY_SIZE]; /* derived after AUTHENTICATE */
    BOOLEAN   SessionKeyValid;
    WCHAR     Username[MAX_USERNAME_LEN + 1];
    USHORT    UsernameLen;
    int       State;  /* 0 = awaiting NEGOTIATE, 1 = awaiting AUTHENTICATE, 2 = done */
} TIDE_CONTEXT, *PTIDE_CONTEXT;

/* ── Forward declarations ─────────────────────────────────────── */

extern NTSTATUS TideLogonUser(
    PLSA_SECPKG_FUNCTION_TABLE LsaDispatch,
    const WCHAR *username,
    PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
    PVOID *TokenInformation,
    PULONG TokenInfoSize);

/* ── Helper: derive session key ───────────────────────────────── */
/* SHA-256(challenge || signature || pubkey), truncated to 16 bytes */
/* Must match the gateway's derivation exactly */

static void deriveSessionKey(
    const UCHAR challenge[CHALLENGE_SIZE],
    const UCHAR signature[64],
    const UCHAR pubkey[32],
    UCHAR outKey[SESSION_KEY_SIZE])
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    UCHAR hash[32]; /* SHA-256 output */

    if (BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
        if (BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0))) {
            BCryptHashData(hHash, (PUCHAR)challenge, CHALLENGE_SIZE, 0);
            BCryptHashData(hHash, (PUCHAR)signature, 64, 0);
            BCryptHashData(hHash, (PUCHAR)pubkey, 32, 0);
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

static NTSTATUS NTAPI TideSsp_Initialize(
    ULONG_PTR PackageId,
    PSECPKG_PARAMETERS Parameters,
    PLSA_SECPKG_FUNCTION_TABLE FunctionTable)
{
    (void)PackageId;
    (void)Parameters;
    LsaDispatch = FunctionTable;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI TideSsp_Shutdown(void)
{
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI TideSsp_GetInfo(PSecPkgInfoW PackageInfo)
{
    PackageInfo->fCapabilities = SECPKG_FLAG_ACCEPT_WIN32_NAME |
                                SECPKG_FLAG_CONNECTION |
                                SECPKG_FLAG_NEGOTIABLE2;
    PackageInfo->wVersion = TIDESSP_VERSION;
    PackageInfo->wRPCID = SECPKG_ID_NONE;
    PackageInfo->cbMaxToken = 1 + 1 + 64 + 32; /* AUTHENTICATE token size */
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

    if (token[0] == TOKEN_NEGOTIATE) {
        /* ── Step 1: NEGOTIATE ── */
        if (inBuf->cbBuffer < 4)
            return SEC_E_INVALID_TOKEN;

        UCHAR version = token[1];
        (void)version;

        USHORT usernameLen = (USHORT)(token[2] | ((USHORT)token[3] << 8));
        if (usernameLen > MAX_USERNAME_LEN || (ULONG)(4 + usernameLen) > inBuf->cbBuffer)
            return SEC_E_INVALID_TOKEN;

        /* Allocate context */
        ctx = (PTIDE_CONTEXT)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TIDE_CONTEXT));
        if (!ctx) return SEC_E_INSUFFICIENT_MEMORY;

        /* Store username (UTF-8 → UTF-16) */
        int wLen = MultiByteToWideChar(CP_UTF8, 0,
            (LPCSTR)(token + 4), usernameLen,
            ctx->Username, MAX_USERNAME_LEN);
        if (wLen <= 0) {
            HeapFree(GetProcessHeap(), 0, ctx);
            return SEC_E_INVALID_TOKEN;
        }
        ctx->Username[wLen] = L'\0';
        ctx->UsernameLen = (USHORT)wLen;

        /* Generate random challenge */
        if (!BCRYPT_SUCCESS(BCryptGenRandom(
                NULL, ctx->Challenge, CHALLENGE_SIZE,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
            HeapFree(GetProcessHeap(), 0, ctx);
            return SEC_E_INTERNAL_ERROR;
        }

        ctx->State = 1;
        ctx->SessionKeyValid = FALSE;

        /* Build CHALLENGE output token */
        if (!outBuf || outBuf->cbBuffer < 1 + CHALLENGE_SIZE) {
            HeapFree(GetProcessHeap(), 0, ctx);
            return SEC_E_BUFFER_TOO_SMALL;
        }

        PUCHAR out = (PUCHAR)outBuf->pvBuffer;
        out[0] = TOKEN_CHALLENGE;
        memcpy(out + 1, ctx->Challenge, CHALLENGE_SIZE);
        outBuf->cbBuffer = 1 + CHALLENGE_SIZE;

        *NewContextHandle = (LSA_SEC_HANDLE)ctx;
        *ContextAttr = 0;
        if (ExpirationTime) {
            ExpirationTime->LowPart = 0xFFFFFFFF;
            ExpirationTime->HighPart = 0x7FFFFFFF;
        }
        if (MappedContext) *MappedContext = FALSE;

        return SEC_I_CONTINUE_NEEDED;
    }
    else if (token[0] == TOKEN_AUTHENTICATE) {
        /* ── Step 2: AUTHENTICATE ── */
        if (inBuf->cbBuffer < 1 + 64 + 32)
            return SEC_E_INVALID_TOKEN;

        ctx = (PTIDE_CONTEXT)ContextHandle;
        if (!ctx || ctx->State != 1)
            return SEC_E_INVALID_HANDLE;

        const uint8_t *signature = token + 1;
        const uint8_t *pubkey = token + 1 + 64;

        /* Verify Ed25519 signature over the challenge */
        if (ed25519_verify(signature, ctx->Challenge, CHALLENGE_SIZE, pubkey) != 0) {
            HeapFree(GetProcessHeap(), 0, ctx);
            return SEC_E_LOGON_DENIED;
        }

        /* Derive session key for NEGOEX VERIFY */
        deriveSessionKey(ctx->Challenge, signature, pubkey, ctx->SessionKey);
        ctx->SessionKeyValid = TRUE;

        /* Create Windows logon session */
        if (LsaDispatch) {
            LSA_TOKEN_INFORMATION_TYPE tokenType;
            PVOID tokenInfo = NULL;
            ULONG tokenInfoSize = 0;
            NTSTATUS status = TideLogonUser(
                LsaDispatch,
                ctx->Username,
                &tokenType,
                &tokenInfo,
                &tokenInfoSize);
            if (!NT_SUCCESS(status)) {
                HeapFree(GetProcessHeap(), 0, ctx);
                return SEC_E_LOGON_DENIED;
            }
            if (tokenInfo && LsaDispatch->FreeLsaHeap)
                LsaDispatch->FreeLsaHeap(tokenInfo);
        }

        if (outBuf) outBuf->cbBuffer = 0;

        *NewContextHandle = (LSA_SEC_HANDLE)ctx;
        *ContextAttr = 0;
        if (ExpirationTime) {
            ExpirationTime->LowPart = 0xFFFFFFFF;
            ExpirationTime->HighPart = 0x7FFFFFFF;
        }
        if (MappedContext) *MappedContext = TRUE;

        ctx->State = 2;
        return SEC_E_OK;
    }

    return SEC_E_INVALID_TOKEN;
}

static NTSTATUS NTAPI TideSsp_DeleteContext(LSA_SEC_HANDLE ContextHandle)
{
    if (ContextHandle) {
        PTIDE_CONTEXT ctx = (PTIDE_CONTEXT)ContextHandle;
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
    (void)ContextHandle;
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
    return STATUS_SUCCESS;
}

/* ══════════════════════════════════════════════════════════════════
 *  Query/Set Context Attributes (with session key support)
 * ══════════════════════════════════════════════════════════════════ */

static NTSTATUS NTAPI TideSsp_QueryContextAttributes(LSA_SEC_HANDLE h, ULONG attr, PVOID buf) {
    if (attr == SECPKG_ATTR_SIZES) {
        PSecPkgContext_Sizes sizes = (PSecPkgContext_Sizes)buf;
        sizes->cbMaxToken = 1 + 64 + 32;
        sizes->cbMaxSignature = 0;
        sizes->cbBlockSize = 0;
        sizes->cbSecurityTrailer = 0;
        return STATUS_SUCCESS;
    }
    if (attr == SECPKG_ATTR_SESSION_KEY) {
        PTIDE_CONTEXT ctx = (PTIDE_CONTEXT)h;
        if (!ctx || !ctx->SessionKeyValid)
            return SEC_E_INVALID_HANDLE;
        SecPkgContext_SessionKey *sk = (SecPkgContext_SessionKey *)buf;
        sk->SessionKeyLength = SESSION_KEY_SIZE;
        /* Allocate key buffer from LSA heap */
        if (LsaDispatch && LsaDispatch->AllocateLsaHeap) {
            sk->SessionKey = (PUCHAR)LsaDispatch->AllocateLsaHeap(SESSION_KEY_SIZE);
        } else {
            sk->SessionKey = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, SESSION_KEY_SIZE);
        }
        if (!sk->SessionKey) return SEC_E_INSUFFICIENT_MEMORY;
        memcpy(sk->SessionKey, ctx->SessionKey, SESSION_KEY_SIZE);
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_IMPLEMENTED;
}

/* ══════════════════════════════════════════════════════════════════
 *  Stubs for required but unused functions
 * ══════════════════════════════════════════════════════════════════ */

static NTSTATUS NTAPI TideSsp_LogonUser(void *a,void *b,void *c,void *d,void *e,void *f,void *g,void *h,void *i,void *j,void *k,void *l,void *m,void *n) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j;(void)k;(void)l;(void)m;(void)n;
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS NTAPI TideSsp_CallPackage(void *a, void *b, void *c, void *d, void *e, void *f) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;
    return STATUS_NOT_IMPLEMENTED;
}

static void NTAPI TideSsp_LogonTerminated(PLUID LogonId) {
    (void)LogonId;
}

static NTSTATUS NTAPI TideSsp_CallPackageUntrusted(void *a, void *b, void *c, void *d, void *e, void *f) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS NTAPI TideSsp_CallPackagePassthrough(void *a, void *b, void *c, void *d, void *e, void *f) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS NTAPI TideSsp_LogonUserEx(void *a,void *b,void *c,void *d,void *e,void *f,void *g,void *h,void *i,void *j,void *k,void *l,void *m,void *n,void *o) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j;(void)k;(void)l;(void)m;(void)n;(void)o;
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS NTAPI TideSsp_LogonUserEx2(void *a,void *b,void *c,void *d,void *e,void *f,void *g,void *h,void *i,void *j,void *k,void *l,void *m,void *n,void *o,void *p) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j;(void)k;(void)l;(void)m;(void)n;(void)o;(void)p;
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS NTAPI TideSsp_InitLsaModeContext(
    LSA_SEC_HANDLE a, LSA_SEC_HANDLE b, PUNICODE_STRING c,
    ULONG d, ULONG e, PSecBufferDesc f, PLSA_SEC_HANDLE g,
    PSecBufferDesc h, PULONG i, PTimeStamp j, PBOOLEAN k, PSecBuffer l)
{
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j;(void)k;(void)l;
    return STATUS_NOT_IMPLEMENTED;
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

static NTSTATUS NTAPI TideSsp_QueryCredentialsAttributes(LSA_SEC_HANDLE h, ULONG a, PVOID b) {
    (void)h;(void)a;(void)b;
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS NTAPI TideSsp_SaveCredentials(LSA_SEC_HANDLE a, PSecBuffer b) {
    (void)a;(void)b;
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS NTAPI TideSsp_GetCredentials(LSA_SEC_HANDLE a, PSecBuffer b) {
    (void)a;(void)b;
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS NTAPI TideSsp_DeleteCredentials(LSA_SEC_HANDLE a, PSecBuffer b) {
    (void)a;(void)b;
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS NTAPI TideSsp_SetContextAttributes(LSA_SEC_HANDLE h, ULONG a, PVOID b, ULONG c) {
    (void)h;(void)a;(void)b;(void)c;
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS NTAPI TideSsp_ApplyControlToken(LSA_SEC_HANDLE h, PSecBufferDesc b) {
    (void)h;(void)b;
    return STATUS_NOT_IMPLEMENTED;
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
