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

#define TOKEN_JWT          0x04

#define SESSION_KEY_SIZE   16
#define MAX_USERNAME_LEN   256

/* ── JWK Ed25519 public key (from tidecloak.json) ────────────── */
/* kid: TPlidYX-_Jaw8wTsthyDEQIwIxqbJkyoJBW6qN4InTQ               */
/* x (base64url): 75TGtIj59SC5jCYJFMkuq-bjhdbHFXWniyZ1dc3BV2E     */
static const UCHAR JWK_PUBLIC_KEY[32] = {
    0xef, 0x94, 0xc6, 0xb4, 0x88, 0xf9, 0xf5, 0x20,
    0xb9, 0x8c, 0x26, 0x09, 0x14, 0xc9, 0x2e, 0xab,
    0xe6, 0xe3, 0x85, 0xd6, 0xc7, 0x15, 0x75, 0xa7,
    0x8b, 0x26, 0x75, 0x75, 0xcd, 0xc1, 0x57, 0x61,
};

/* ── LSA dispatch table — set by SpInitialize ─────────────────── */

static PLSA_SECPKG_FUNCTION_TABLE LsaDispatch = NULL;

/* ── Context state for in-progress authentication ─────────────── */

typedef struct _TIDE_CONTEXT {
    ULONG_PTR ContextHandle;
    UCHAR     SessionKey[SESSION_KEY_SIZE]; /* derived from JWT signature */
    BOOLEAN   SessionKeyValid;
    WCHAR     Username[MAX_USERNAME_LEN + 1];
    USHORT    UsernameLen;
    int       State;  /* 0 = initial, 2 = done */
} TIDE_CONTEXT, *PTIDE_CONTEXT;

/* ── Forward declarations ─────────────────────────────────────── */

extern NTSTATUS TideLogonUser(
    PLSA_SECPKG_FUNCTION_TABLE LsaDispatch,
    const WCHAR *username,
    PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
    PVOID *TokenInformation,
    PULONG TokenInfoSize);

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

static NTSTATUS NTAPI TideSsp_Initialize(
    ULONG_PTR PackageId,
    PSECPKG_PARAMETERS Parameters,
    PLSA_SECPKG_FUNCTION_TABLE FunctionTable)
{
    (void)PackageId;
    (void)Parameters;
    LsaDispatch = FunctionTable;
    tide_log("TideSSP Initialize: PackageId=%llu, LsaDispatch=%p", (unsigned long long)PackageId, (void*)FunctionTable);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI TideSsp_Shutdown(void)
{
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI TideSsp_GetInfo(PSecPkgInfoW PackageInfo)
{
    tide_log("GetInfo called");
    PackageInfo->fCapabilities = SECPKG_FLAG_ACCEPT_WIN32_NAME |
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
        tide_log("JWK pubkey: %02x%02x%02x%02x...", JWK_PUBLIC_KEY[0], JWK_PUBLIC_KEY[1], JWK_PUBLIC_KEY[2], JWK_PUBLIC_KEY[3]);

        /* Verify Ed25519 signature against JWK public key */
        int verifyResult = ed25519_verify(sigBytes, (const uint8_t *)jwt, (size_t)signedDataLen, JWK_PUBLIC_KEY);
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

        /* Extract username (preferred_username or sub) */
        char usernameUtf8[MAX_USERNAME_LEN + 1];
        int usernameLen = json_extract_string(payloadJson, payloadLen,
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

        /* Skip Windows logon session creation for now.
         * CredSSP only needs SPNEGO auth to succeed — the actual Windows
         * logon happens when termsrv processes the authInfo credentials.
         * TideLogonUser was failing because the JWT username may not match
         * a local Windows account exactly. */
        tide_log("JWT auth OK for '%ls' — skipping TideLogonUser (not needed for CredSSP)", ctx->Username);

        /* No output token — single round, auth complete */
        if (outBuf) outBuf->cbBuffer = 0;

        *NewContextHandle = (LSA_SEC_HANDLE)ctx;
        *ContextAttr = 0;
        if (ExpirationTime) {
            ExpirationTime->LowPart = 0xFFFFFFFF;
            ExpirationTime->HighPart = 0x7FFFFFFF;
        }
        if (MappedContext) *MappedContext = FALSE;

        ctx->State = 2;
        tide_log("AcceptLsaModeContext: SUCCESS for '%ls'", ctx->Username);
        return SEC_E_OK;
    }

    tide_log("AcceptLsaModeContext: unknown token type 0x%02X", token[0]);
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
        sizes->cbMaxSignature = 0;
        sizes->cbBlockSize = 0;
        sizes->cbSecurityTrailer = 0;
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

        *(ULONG  *)(p + 0)  = 23;              /* KeyType: rc4-hmac */
        *(ULONG  *)(p + 4)  = SESSION_KEY_SIZE; /* KeyLength */
        *(PUCHAR *)(p + 8)  = key1;             /* KeyValue */
        *(ULONG  *)(p + 16) = 23;              /* VerifyKeyType: rc4-hmac */
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
    tide_log("QueryContextAttributes: UNKNOWN attr=%u (0x%X)", attr, attr);
    return (NTSTATUS)(0xC0090000L | (attr & 0xFFFF));
}

/* ══════════════════════════════════════════════════════════════════
 *  Stubs for required but unused functions
 *
 *  Each returns a UNIQUE error code so we can identify which function
 *  NegoExtender is calling from the CredSSP errorCode in gateway logs.
 *  Map: errorCode → function name, to debug the failing call.
 * ══════════════════════════════════════════════════════════════════ */

/* 0x80090301 */ static NTSTATUS NTAPI TideSsp_LogonUser(void *a,void *b,void *c,void *d,void *e,void *f,void *g,void *h,void *i,void *j,void *k,void *l,void *m,void *n) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j;(void)k;(void)l;(void)m;(void)n;
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
