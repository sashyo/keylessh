/*
 * TideSSP — SSPI function implementations.
 *
 * Wire protocol tokens:
 *   NEGOTIATE  [0x01][version:u8][username_len:u16LE][username:UTF-8]
 *   CHALLENGE  [0x02][challenge:32 bytes]
 *   AUTHENTICATE [0x03][signature:64 bytes][pubkey:32 bytes]
 *
 * Flow (server side — AcceptSecurityContext):
 *   1. Receive NEGOTIATE → extract username, generate challenge → return CHALLENGE
 *   2. Receive AUTHENTICATE → verify Ed25519(pubkey, challenge, sig) → logon user
 */

#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

/* NT_SUCCESS may not be defined in user-mode headers */
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#include <sspi.h>
#include <ntsecapi.h>
#include <ntsecpkg.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>

#include "ed25519.h"

/* Package identity */
#define TIDESSP_NAME      L"TideSSP"
#define TIDESSP_NAME_A    "TideSSP"
#define TIDESSP_COMMENT   L"Tide Ed25519 Authentication"
#define TIDESSP_VERSION   1

/* Token types */
#define TOKEN_NEGOTIATE    0x01
#define TOKEN_CHALLENGE    0x02
#define TOKEN_AUTHENTICATE 0x03

/* Challenge size */
#define CHALLENGE_SIZE     32

/* Max username length */
#define MAX_USERNAME_LEN   256

/* LSA dispatch table — set by SpInitialize */
static PLSA_SECPKG_FUNCTION_TABLE LsaDispatch = NULL;

/* Context state for an in-progress authentication */
typedef struct _TIDE_CONTEXT {
    ULONG_PTR ContextHandle;
    UCHAR     Challenge[CHALLENGE_SIZE];
    WCHAR     Username[MAX_USERNAME_LEN + 1];
    USHORT    UsernameLen;
    int       State;  /* 0 = awaiting NEGOTIATE, 1 = awaiting AUTHENTICATE */
} TIDE_CONTEXT, *PTIDE_CONTEXT;

/* Forward declarations */
extern NTSTATUS TideLogonUser(
    PLSA_SECPKG_FUNCTION_TABLE LsaDispatch,
    const WCHAR *username,
    PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
    PVOID *TokenInformation,
    PULONG TokenInfoSize);

/* ---- SSP Package Functions ---- */

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
                                SECPKG_FLAG_CONNECTION;
    PackageInfo->wVersion = TIDESSP_VERSION;
    PackageInfo->wRPCID = SECPKG_ID_NONE;
    PackageInfo->cbMaxToken = 1 + 1 + 64 + 32; /* largest token: AUTHENTICATE */
    PackageInfo->Name = TIDESSP_NAME;
    PackageInfo->Comment = TIDESSP_COMMENT;
    return STATUS_SUCCESS;
}

/*
 * AcceptSecurityContext — server-side context establishment.
 * Called by CredSSP/NLA to process incoming tokens.
 */
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
        /* ---- Step 1: NEGOTIATE ---- */
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

        /* Store username (convert UTF-8 → UTF-16) */
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

        ctx->State = 1; /* next: expect AUTHENTICATE */

        /* Build CHALLENGE output token: [0x02][challenge:32] */
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
        /* ---- Step 2: AUTHENTICATE ---- */
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

        /* Create Windows logon session for the user */
        if (LsaDispatch) {
            /* Use S4U logon to create a token for the username */
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

        /* No output token needed — auth complete */
        if (outBuf) outBuf->cbBuffer = 0;

        *NewContextHandle = (LSA_SEC_HANDLE)ctx;
        *ContextAttr = 0;
        if (ExpirationTime) {
            ExpirationTime->LowPart = 0xFFFFFFFF;
            ExpirationTime->HighPart = 0x7FFFFFFF;
        }
        if (MappedContext) *MappedContext = TRUE;

        ctx->State = 2; /* done */

        return SEC_E_OK;
    }

    return SEC_E_INVALID_TOKEN;
}

static NTSTATUS NTAPI TideSsp_DeleteContext(LSA_SEC_HANDLE ContextHandle)
{
    if (ContextHandle) {
        HeapFree(GetProcessHeap(), 0, (PVOID)ContextHandle);
    }
    return STATUS_SUCCESS;
}

/* Stubs for required but unused functions */
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
    /* Return a dummy credential handle */
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

static NTSTATUS NTAPI TideSsp_QueryContextAttributes(LSA_SEC_HANDLE h, ULONG attr, PVOID buf) {
    (void)h;
    if (attr == SECPKG_ATTR_SIZES) {
        PSecPkgContext_Sizes sizes = (PSecPkgContext_Sizes)buf;
        sizes->cbMaxToken = 1 + 64 + 32;
        sizes->cbMaxSignature = 0;
        sizes->cbBlockSize = 0;
        sizes->cbSecurityTrailer = 0;
        return STATUS_SUCCESS;
    }
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

/* Function table exported to LSA */
SECPKG_FUNCTION_TABLE TideSSP_FunctionTable = {
    .InitializePackage = (PLSA_AP_INITIALIZE_PACKAGE)TideSsp_Initialize,
    .LogonUser = NULL,
    .CallPackage = (PLSA_AP_CALL_PACKAGE)TideSsp_CallPackage,
    .LogonTerminated = (PLSA_AP_LOGON_TERMINATED)TideSsp_LogonTerminated,
    .CallPackageUntrusted = (PLSA_AP_CALL_PACKAGE_PASSTHROUGH)TideSsp_CallPackageUntrusted,
    .CallPackagePassthrough = (PLSA_AP_CALL_PACKAGE_PASSTHROUGH)TideSsp_CallPackagePassthrough,
    .LogonUserEx = NULL,
    .LogonUserEx2 = NULL,
    .Initialize = (SpInitializeFn *)TideSsp_Initialize,
    .Shutdown = (SpShutdownFn *)TideSsp_Shutdown,
    .GetInfo = (SpGetInfoFn *)TideSsp_GetInfo,
    .AcceptLsaModeContext = (SpAcceptLsaModeContextFn *)TideSsp_AcceptLsaModeContext,
    .AcquireCredentialsHandle = (SpAcquireCredentialsHandleFn *)TideSsp_AcquireCredentialsHandle,
    .QueryCredentialsAttributes = (SpQueryCredentialsAttributesFn *)TideSsp_QueryCredentialsAttributes,
    .FreeCredentialsHandle = (SpFreeCredentialsHandleFn *)TideSsp_FreeCredentialsHandle,
    .SaveCredentials = (SpSaveCredentialsFn *)TideSsp_SaveCredentials,
    .GetCredentials = (SpGetCredentialsFn *)TideSsp_GetCredentials,
    .DeleteCredentials = (SpDeleteCredentialsFn *)TideSsp_DeleteCredentials,
    .InitLsaModeContext = (SpInitLsaModeContextFn *)TideSsp_InitLsaModeContext,
    .DeleteContext = (SpDeleteContextFn *)TideSsp_DeleteContext,
    .ApplyControlToken = (SpApplyControlTokenFn *)TideSsp_ApplyControlToken,
    .QueryContextAttributes = (SpQueryContextAttributesFn *)TideSsp_QueryContextAttributes,
    .SetContextAttributes = (SpSetContextAttributesFn *)TideSsp_SetContextAttributes,
};
