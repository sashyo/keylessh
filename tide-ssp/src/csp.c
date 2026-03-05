/*
 * TideSSP CSP — Minimal Cryptographic Service Provider for browser-based
 * smart card emulation.
 *
 * This CSP is registered as "TideSSP CSP" and is referenced by the
 * CERT_KEY_PROV_INFO on the browser-signed certificate installed by
 * the TideSSP SSP during NLA.
 *
 * When termsrv calls CryptAcquireContext("TideSSP CSP"), this DLL:
 *   1. Reads the gateway signing relay address from registry
 *   2. Opens a TCP connection to the gateway
 *   3. Sends HELLO with the session token
 *   4. On CPSignHash: sends the hash to the gateway, which relays to the
 *      browser for signing with the RSA private key
 *   5. Returns the signature to Windows
 *
 * The private key NEVER leaves the browser.
 *
 * Wire protocol (TCP, binary):
 *   [4 bytes: message length (LE)][1 byte: type][payload]
 *   Type 0x01: HELLO  — payload: [16 bytes session token]
 *   Type 0x02: SIGN   — payload: [4 bytes hash length][hash bytes][4 bytes algId]
 *   Type 0x03: RESULT — payload: [4 bytes sig length][signature bytes]
 *   Type 0x04: ACK    — payload: (empty)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

/* ── Debug logging ───────────────────────────────────────────── */

static void csp_log(const char *fmt, ...)
{
    FILE *f = fopen("C:\\Windows\\Temp\\TideCSP_debug.log", "a");
    if (!f) return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f, "[%02d:%02d:%02d.%03d] ",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list args;
    va_start(args, fmt);
    vfprintf(f, fmt, args);
    va_end(args);
    fprintf(f, "\n");
    fclose(f);
}

/* ── Relay message types ─────────────────────────────────────── */

#define MSG_HELLO   0x01
#define MSG_SIGN    0x02
#define MSG_RESULT  0x03
#define MSG_ACK     0x04

/* ── CSP context ─────────────────────────────────────────────── */

typedef struct {
    DWORD       dwMagic;            /* 0xC5B00001 */
    WCHAR       ContainerName[256];
    UCHAR       SessionToken[16];
    SOCKET      GatewaySocket;
    BOOL        Connected;
    /* Public key from registry (set by TideSSP SSP during NLA) */
    UCHAR       PublicKeyBlob[1024];
    DWORD       PublicKeyBlobLen;
} CSP_CONTEXT;

#define CSP_MAGIC 0xC5B00001

/* ── Hash context ────────────────────────────────────────────── */

typedef struct {
    DWORD       dwMagic;            /* 0xC5B00002 */
    CSP_CONTEXT *pCtx;
    ALG_ID      AlgId;
    UCHAR       HashData[4096];     /* accumulated data to hash */
    DWORD       HashDataLen;
    UCHAR       HashValue[64];      /* computed hash */
    DWORD       HashValueLen;
    BOOL        Finalized;
} CSP_HASH;

#define HASH_MAGIC 0xC5B00002

/* ── Key handle (virtual — no actual key material) ───────────── */

typedef struct {
    DWORD       dwMagic;            /* 0xC5B00003 */
    CSP_CONTEXT *pCtx;
    DWORD       dwKeySpec;
} CSP_KEY;

#define KEY_MAGIC 0xC5B00003

/* ── TCP helpers ─────────────────────────────────────────────── */

static BOOL wsa_initialized = FALSE;

static void ensure_wsa(void)
{
    if (!wsa_initialized) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
        wsa_initialized = TRUE;
    }
}

/* Send a relay message: [4 bytes len][1 byte type][payload] */
static BOOL relay_send(SOCKET s, UCHAR type, const UCHAR *payload, DWORD payloadLen)
{
    DWORD msgLen = 1 + payloadLen;
    UCHAR header[5];
    header[0] = (UCHAR)(msgLen & 0xFF);
    header[1] = (UCHAR)((msgLen >> 8) & 0xFF);
    header[2] = (UCHAR)((msgLen >> 16) & 0xFF);
    header[3] = (UCHAR)((msgLen >> 24) & 0xFF);
    header[4] = type;

    if (send(s, (const char *)header, 5, 0) != 5)
        return FALSE;
    if (payloadLen > 0 && send(s, (const char *)payload, payloadLen, 0) != (int)payloadLen)
        return FALSE;
    return TRUE;
}

/* Receive exactly n bytes */
static BOOL relay_recv(SOCKET s, UCHAR *buf, DWORD n)
{
    DWORD got = 0;
    while (got < n) {
        int r = recv(s, (char *)(buf + got), n - got, 0);
        if (r <= 0) return FALSE;
        got += r;
    }
    return TRUE;
}

/* Read one relay message, returns type and malloc'd payload */
static BOOL relay_read_msg(SOCKET s, UCHAR *outType, UCHAR **outPayload, DWORD *outLen)
{
    UCHAR header[5];
    if (!relay_recv(s, header, 5)) return FALSE;

    DWORD msgLen = header[0] | (header[1] << 8) | (header[2] << 16) | (header[3] << 24);
    *outType = header[4];
    DWORD payloadLen = msgLen - 1;
    *outLen = payloadLen;

    if (payloadLen == 0) {
        *outPayload = NULL;
        return TRUE;
    }

    *outPayload = (UCHAR *)malloc(payloadLen);
    if (!*outPayload) return FALSE;
    if (!relay_recv(s, *outPayload, payloadLen)) {
        free(*outPayload);
        *outPayload = NULL;
        return FALSE;
    }
    return TRUE;
}

/* Connect to gateway signing relay */
static BOOL connect_to_relay(CSP_CONTEXT *ctx)
{
    ensure_wsa();

    /* Read relay address from registry */
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\TideSSP\\SigningRelay", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        csp_log("connect_to_relay: cannot open registry key");
        return FALSE;
    }

    char address[256] = {0};
    DWORD addrLen = sizeof(address);
    DWORD type = REG_SZ;
    RegQueryValueExA(hKey, "Address", NULL, &type, (LPBYTE)address, &addrLen);

    UCHAR tokenBuf[16];
    DWORD tokenLen = sizeof(tokenBuf);
    type = REG_BINARY;
    RegQueryValueExA(hKey, "SessionToken", NULL, &type, tokenBuf, &tokenLen);
    RegCloseKey(hKey);

    if (address[0] == '\0') {
        csp_log("connect_to_relay: empty address");
        return FALSE;
    }

    memcpy(ctx->SessionToken, tokenBuf, 16);
    csp_log("connect_to_relay: address=%s, token=%02x%02x%02x%02x...",
            address, tokenBuf[0], tokenBuf[1], tokenBuf[2], tokenBuf[3]);

    /* Parse host:port */
    char host[128] = {0};
    char port[16] = "35890";
    char *colon = strrchr(address, ':');
    if (colon) {
        strncpy(host, address, colon - address);
        strncpy(port, colon + 1, sizeof(port) - 1);
    } else {
        strncpy(host, address, sizeof(host) - 1);
    }

    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &result) != 0) {
        csp_log("connect_to_relay: getaddrinfo failed for %s:%s", host, port);
        return FALSE;
    }

    ctx->GatewaySocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ctx->GatewaySocket == INVALID_SOCKET) {
        freeaddrinfo(result);
        return FALSE;
    }

    if (connect(ctx->GatewaySocket, result->ai_addr, (int)result->ai_addrlen) != 0) {
        csp_log("connect_to_relay: connect failed (WSA %d)", WSAGetLastError());
        closesocket(ctx->GatewaySocket);
        ctx->GatewaySocket = INVALID_SOCKET;
        freeaddrinfo(result);
        return FALSE;
    }
    freeaddrinfo(result);

    /* Send HELLO with session token */
    if (!relay_send(ctx->GatewaySocket, MSG_HELLO, ctx->SessionToken, 16)) {
        csp_log("connect_to_relay: HELLO send failed");
        closesocket(ctx->GatewaySocket);
        ctx->GatewaySocket = INVALID_SOCKET;
        return FALSE;
    }

    /* Wait for ACK */
    UCHAR ackType;
    UCHAR *ackPayload = NULL;
    DWORD ackLen;
    if (!relay_read_msg(ctx->GatewaySocket, &ackType, &ackPayload, &ackLen) || ackType != MSG_ACK) {
        csp_log("connect_to_relay: ACK not received (type=%d)", ackType);
        free(ackPayload);
        closesocket(ctx->GatewaySocket);
        ctx->GatewaySocket = INVALID_SOCKET;
        return FALSE;
    }
    free(ackPayload);

    ctx->Connected = TRUE;
    csp_log("connect_to_relay: connected to %s:%s", host, port);
    return TRUE;
}

/* ══════════════════════════════════════════════════════════════════
 *  CSP Entry Points (CryptoSPI)
 * ══════════════════════════════════════════════════════════════════ */

BOOL WINAPI CPAcquireContext(
    HCRYPTPROV *phProv,
    LPCSTR szContainer,
    DWORD dwFlags,
    PVTableProvStruc pVTable)
{
    (void)pVTable;

    csp_log("CPAcquireContext: container='%s', flags=0x%08X",
            szContainer ? szContainer : "(null)", dwFlags);

    if (dwFlags & CRYPT_VERIFYCONTEXT) {
        /* Verification-only context — no container needed */
        CSP_CONTEXT *ctx = (CSP_CONTEXT *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CSP_CONTEXT));
        if (!ctx) {
            SetLastError(NTE_NO_MEMORY);
            return FALSE;
        }
        ctx->dwMagic = CSP_MAGIC;
        ctx->GatewaySocket = INVALID_SOCKET;
        *phProv = (HCRYPTPROV)ctx;
        return TRUE;
    }

    CSP_CONTEXT *ctx = (CSP_CONTEXT *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CSP_CONTEXT));
    if (!ctx) {
        SetLastError(NTE_NO_MEMORY);
        return FALSE;
    }
    ctx->dwMagic = CSP_MAGIC;
    ctx->GatewaySocket = INVALID_SOCKET;

    if (szContainer) {
        MultiByteToWideChar(CP_ACP, 0, szContainer, -1, ctx->ContainerName, 256);
    }

    /* Connect to signing relay */
    if (!connect_to_relay(ctx)) {
        csp_log("CPAcquireContext: relay connection failed — proceeding offline");
    }

    *phProv = (HCRYPTPROV)ctx;
    csp_log("CPAcquireContext: OK, phProv=%p", (void *)*phProv);
    return TRUE;
}

BOOL WINAPI CPReleaseContext(HCRYPTPROV hProv, DWORD dwFlags)
{
    (void)dwFlags;
    CSP_CONTEXT *ctx = (CSP_CONTEXT *)hProv;
    if (!ctx || ctx->dwMagic != CSP_MAGIC) return TRUE;

    csp_log("CPReleaseContext: hProv=%p", (void *)hProv);

    if (ctx->GatewaySocket != INVALID_SOCKET) {
        closesocket(ctx->GatewaySocket);
    }

    SecureZeroMemory(ctx, sizeof(CSP_CONTEXT));
    HeapFree(GetProcessHeap(), 0, ctx);
    return TRUE;
}

BOOL WINAPI CPGetProvParam(
    HCRYPTPROV hProv,
    DWORD dwParam,
    BYTE *pbData,
    DWORD *pdwDataLen,
    DWORD dwFlags)
{
    (void)dwFlags;
    CSP_CONTEXT *ctx = (CSP_CONTEXT *)hProv;
    if (!ctx || ctx->dwMagic != CSP_MAGIC) {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }

    csp_log("CPGetProvParam: dwParam=0x%08X", dwParam);

    switch (dwParam) {
    case PP_NAME: {
        const char *name = "TideSSP CSP";
        DWORD len = (DWORD)strlen(name) + 1;
        if (!pbData) { *pdwDataLen = len; return TRUE; }
        if (*pdwDataLen < len) { *pdwDataLen = len; SetLastError(ERROR_MORE_DATA); return FALSE; }
        memcpy(pbData, name, len);
        *pdwDataLen = len;
        return TRUE;
    }
    case PP_CONTAINER: {
        char container[512];
        WideCharToMultiByte(CP_ACP, 0, ctx->ContainerName, -1, container, sizeof(container), NULL, NULL);
        DWORD len = (DWORD)strlen(container) + 1;
        if (!pbData) { *pdwDataLen = len; return TRUE; }
        if (*pdwDataLen < len) { *pdwDataLen = len; SetLastError(ERROR_MORE_DATA); return FALSE; }
        memcpy(pbData, container, len);
        *pdwDataLen = len;
        return TRUE;
    }
    case PP_PROVTYPE: {
        if (!pbData) { *pdwDataLen = sizeof(DWORD); return TRUE; }
        if (*pdwDataLen < sizeof(DWORD)) { SetLastError(ERROR_MORE_DATA); return FALSE; }
        *(DWORD *)pbData = PROV_RSA_FULL;
        *pdwDataLen = sizeof(DWORD);
        return TRUE;
    }
    case PP_IMPTYPE: {
        if (!pbData) { *pdwDataLen = sizeof(DWORD); return TRUE; }
        if (*pdwDataLen < sizeof(DWORD)) { SetLastError(ERROR_MORE_DATA); return FALSE; }
        *(DWORD *)pbData = CRYPT_IMPL_SOFTWARE;
        *pdwDataLen = sizeof(DWORD);
        return TRUE;
    }
    case PP_VERSION: {
        if (!pbData) { *pdwDataLen = sizeof(DWORD); return TRUE; }
        if (*pdwDataLen < sizeof(DWORD)) { SetLastError(ERROR_MORE_DATA); return FALSE; }
        *(DWORD *)pbData = 0x0200; /* version 2.0 */
        *pdwDataLen = sizeof(DWORD);
        return TRUE;
    }
    default:
        csp_log("CPGetProvParam: unsupported param 0x%08X", dwParam);
        SetLastError(NTE_BAD_TYPE);
        return FALSE;
    }
}

BOOL WINAPI CPSetProvParam(HCRYPTPROV hProv, DWORD dwParam, const BYTE *pbData, DWORD dwFlags)
{
    (void)hProv; (void)dwParam; (void)pbData; (void)dwFlags;
    csp_log("CPSetProvParam: dwParam=0x%08X", dwParam);
    SetLastError(NTE_BAD_TYPE);
    return FALSE;
}

BOOL WINAPI CPGetUserKey(HCRYPTPROV hProv, DWORD dwKeySpec, HCRYPTKEY *phUserKey)
{
    CSP_CONTEXT *ctx = (CSP_CONTEXT *)hProv;
    if (!ctx || ctx->dwMagic != CSP_MAGIC) {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }

    csp_log("CPGetUserKey: dwKeySpec=%u", dwKeySpec);

    CSP_KEY *key = (CSP_KEY *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CSP_KEY));
    if (!key) { SetLastError(NTE_NO_MEMORY); return FALSE; }
    key->dwMagic = KEY_MAGIC;
    key->pCtx = ctx;
    key->dwKeySpec = dwKeySpec;
    *phUserKey = (HCRYPTKEY)key;
    return TRUE;
}

BOOL WINAPI CPGetKeyParam(
    HCRYPTPROV hProv,
    HCRYPTKEY hKey,
    DWORD dwParam,
    BYTE *pbData,
    DWORD *pdwDataLen,
    DWORD dwFlags)
{
    (void)hProv; (void)dwFlags;
    CSP_KEY *key = (CSP_KEY *)hKey;
    if (!key || key->dwMagic != KEY_MAGIC) {
        SetLastError(NTE_BAD_KEY);
        return FALSE;
    }

    csp_log("CPGetKeyParam: dwParam=0x%08X", dwParam);

    switch (dwParam) {
    case KP_ALGID: {
        if (!pbData) { *pdwDataLen = sizeof(ALG_ID); return TRUE; }
        if (*pdwDataLen < sizeof(ALG_ID)) { SetLastError(ERROR_MORE_DATA); return FALSE; }
        *(ALG_ID *)pbData = CALG_RSA_KEYX;
        *pdwDataLen = sizeof(ALG_ID);
        return TRUE;
    }
    case KP_KEYLEN: {
        if (!pbData) { *pdwDataLen = sizeof(DWORD); return TRUE; }
        if (*pdwDataLen < sizeof(DWORD)) { SetLastError(ERROR_MORE_DATA); return FALSE; }
        *(DWORD *)pbData = 2048; /* RSA-2048 */
        *pdwDataLen = sizeof(DWORD);
        return TRUE;
    }
    default:
        csp_log("CPGetKeyParam: unsupported param 0x%08X", dwParam);
        SetLastError(NTE_BAD_TYPE);
        return FALSE;
    }
}

BOOL WINAPI CPExportKey(
    HCRYPTPROV hProv,
    HCRYPTKEY hKey,
    HCRYPTKEY hExpKey,
    DWORD dwBlobType,
    DWORD dwFlags,
    BYTE *pbData,
    DWORD *pdwDataLen)
{
    (void)hProv; (void)hExpKey; (void)dwFlags;
    CSP_KEY *key = (CSP_KEY *)hKey;
    if (!key || key->dwMagic != KEY_MAGIC) {
        SetLastError(NTE_BAD_KEY);
        return FALSE;
    }

    csp_log("CPExportKey: blobType=%u", dwBlobType);

    if (dwBlobType == PUBLICKEYBLOB) {
        CSP_CONTEXT *ctx = key->pCtx;
        if (ctx->PublicKeyBlobLen == 0) {
            csp_log("CPExportKey: no public key blob available");
            SetLastError(NTE_NO_KEY);
            return FALSE;
        }
        if (!pbData) {
            *pdwDataLen = ctx->PublicKeyBlobLen;
            return TRUE;
        }
        if (*pdwDataLen < ctx->PublicKeyBlobLen) {
            *pdwDataLen = ctx->PublicKeyBlobLen;
            SetLastError(ERROR_MORE_DATA);
            return FALSE;
        }
        memcpy(pbData, ctx->PublicKeyBlob, ctx->PublicKeyBlobLen);
        *pdwDataLen = ctx->PublicKeyBlobLen;
        return TRUE;
    }

    SetLastError(NTE_BAD_TYPE);
    return FALSE;
}

BOOL WINAPI CPDestroyKey(HCRYPTPROV hProv, HCRYPTKEY hKey)
{
    (void)hProv;
    CSP_KEY *key = (CSP_KEY *)hKey;
    if (key && key->dwMagic == KEY_MAGIC) {
        SecureZeroMemory(key, sizeof(CSP_KEY));
        HeapFree(GetProcessHeap(), 0, key);
    }
    return TRUE;
}

BOOL WINAPI CPGenKey(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY *phKey)
{
    (void)hProv; (void)Algid; (void)dwFlags; (void)phKey;
    csp_log("CPGenKey: not supported");
    SetLastError(NTE_BAD_ALGID);
    return FALSE;
}

BOOL WINAPI CPDeriveKey(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hHash, DWORD dwFlags, HCRYPTKEY *phKey)
{
    (void)hProv; (void)Algid; (void)hHash; (void)dwFlags; (void)phKey;
    SetLastError(NTE_BAD_ALGID);
    return FALSE;
}

BOOL WINAPI CPImportKey(HCRYPTPROV hProv, const BYTE *pbData, DWORD dwDataLen,
                        HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY *phKey)
{
    (void)hProv; (void)pbData; (void)dwDataLen; (void)hPubKey; (void)dwFlags; (void)phKey;
    SetLastError(NTE_BAD_ALGID);
    return FALSE;
}

/* ── Hash operations ─────────────────────────────────────────── */

BOOL WINAPI CPCreateHash(
    HCRYPTPROV hProv,
    ALG_ID Algid,
    HCRYPTKEY hKey,
    DWORD dwFlags,
    HCRYPTHASH *phHash)
{
    (void)hKey; (void)dwFlags;
    CSP_CONTEXT *ctx = (CSP_CONTEXT *)hProv;
    if (!ctx || ctx->dwMagic != CSP_MAGIC) {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }

    csp_log("CPCreateHash: AlgId=0x%04X", Algid);

    CSP_HASH *hash = (CSP_HASH *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CSP_HASH));
    if (!hash) { SetLastError(NTE_NO_MEMORY); return FALSE; }
    hash->dwMagic = HASH_MAGIC;
    hash->pCtx = ctx;
    hash->AlgId = Algid;
    *phHash = (HCRYPTHASH)hash;
    return TRUE;
}

BOOL WINAPI CPHashData(
    HCRYPTPROV hProv,
    HCRYPTHASH hHash,
    const BYTE *pbData,
    DWORD dwDataLen,
    DWORD dwFlags)
{
    (void)hProv; (void)dwFlags;
    CSP_HASH *hash = (CSP_HASH *)hHash;
    if (!hash || hash->dwMagic != HASH_MAGIC) {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }
    if (hash->Finalized) {
        SetLastError(NTE_BAD_HASH_STATE);
        return FALSE;
    }

    /* Accumulate data */
    if (hash->HashDataLen + dwDataLen > sizeof(hash->HashData)) {
        SetLastError(NTE_BAD_LEN);
        return FALSE;
    }
    memcpy(hash->HashData + hash->HashDataLen, pbData, dwDataLen);
    hash->HashDataLen += dwDataLen;
    return TRUE;
}

BOOL WINAPI CPGetHashParam(
    HCRYPTPROV hProv,
    HCRYPTHASH hHash,
    DWORD dwParam,
    BYTE *pbData,
    DWORD *pdwDataLen,
    DWORD dwFlags)
{
    (void)hProv; (void)dwFlags;
    CSP_HASH *hash = (CSP_HASH *)hHash;
    if (!hash || hash->dwMagic != HASH_MAGIC) {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }

    csp_log("CPGetHashParam: dwParam=0x%08X, AlgId=0x%04X", dwParam, hash->AlgId);

    switch (dwParam) {
    case HP_ALGID: {
        if (!pbData) { *pdwDataLen = sizeof(ALG_ID); return TRUE; }
        if (*pdwDataLen < sizeof(ALG_ID)) { SetLastError(ERROR_MORE_DATA); return FALSE; }
        *(ALG_ID *)pbData = hash->AlgId;
        *pdwDataLen = sizeof(ALG_ID);
        return TRUE;
    }
    case HP_HASHSIZE: {
        DWORD hashSize;
        switch (hash->AlgId) {
        case CALG_SHA1: hashSize = 20; break;
        case CALG_SHA_256: hashSize = 32; break;
        case CALG_MD5: hashSize = 16; break;
        default: hashSize = 32; break;
        }
        if (!pbData) { *pdwDataLen = sizeof(DWORD); return TRUE; }
        if (*pdwDataLen < sizeof(DWORD)) { SetLastError(ERROR_MORE_DATA); return FALSE; }
        *(DWORD *)pbData = hashSize;
        *pdwDataLen = sizeof(DWORD);
        return TRUE;
    }
    case HP_HASHVAL: {
        /* Finalize hash using BCrypt */
        if (!hash->Finalized) {
            BCRYPT_ALG_HANDLE hAlg = NULL;
            BCRYPT_HASH_HANDLE hBCHash = NULL;
            LPCWSTR algName;
            DWORD hashLen;

            switch (hash->AlgId) {
            case CALG_SHA1:    algName = BCRYPT_SHA1_ALGORITHM;   hashLen = 20; break;
            case CALG_SHA_256: algName = BCRYPT_SHA256_ALGORITHM; hashLen = 32; break;
            case CALG_MD5:     algName = BCRYPT_MD5_ALGORITHM;    hashLen = 16; break;
            default:           algName = BCRYPT_SHA256_ALGORITHM; hashLen = 32; break;
            }

            if (BCryptOpenAlgorithmProvider(&hAlg, algName, NULL, 0) == 0) {
                if (BCryptCreateHash(hAlg, &hBCHash, NULL, 0, NULL, 0, 0) == 0) {
                    BCryptHashData(hBCHash, hash->HashData, hash->HashDataLen, 0);
                    BCryptFinishHash(hBCHash, hash->HashValue, hashLen, 0);
                    hash->HashValueLen = hashLen;
                    BCryptDestroyHash(hBCHash);
                }
                BCryptCloseAlgorithmProvider(hAlg, 0);
            }
            hash->Finalized = TRUE;
        }
        if (!pbData) { *pdwDataLen = hash->HashValueLen; return TRUE; }
        if (*pdwDataLen < hash->HashValueLen) { SetLastError(ERROR_MORE_DATA); return FALSE; }
        memcpy(pbData, hash->HashValue, hash->HashValueLen);
        *pdwDataLen = hash->HashValueLen;
        return TRUE;
    }
    default:
        SetLastError(NTE_BAD_TYPE);
        return FALSE;
    }
}

BOOL WINAPI CPSetHashParam(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwParam,
                           const BYTE *pbData, DWORD dwFlags)
{
    (void)hProv; (void)dwFlags;
    CSP_HASH *hash = (CSP_HASH *)hHash;
    if (!hash || hash->dwMagic != HASH_MAGIC) {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }

    csp_log("CPSetHashParam: dwParam=0x%08X", dwParam);

    if (dwParam == HP_HASHVAL) {
        /* Allow setting hash value directly (pre-computed hash) */
        DWORD hashLen;
        switch (hash->AlgId) {
        case CALG_SHA1: hashLen = 20; break;
        case CALG_SHA_256: hashLen = 32; break;
        case CALG_MD5: hashLen = 16; break;
        default: hashLen = 32; break;
        }
        memcpy(hash->HashValue, pbData, hashLen);
        hash->HashValueLen = hashLen;
        hash->Finalized = TRUE;
        return TRUE;
    }

    SetLastError(NTE_BAD_TYPE);
    return FALSE;
}

BOOL WINAPI CPDestroyHash(HCRYPTPROV hProv, HCRYPTHASH hHash)
{
    (void)hProv;
    CSP_HASH *hash = (CSP_HASH *)hHash;
    if (hash && hash->dwMagic == HASH_MAGIC) {
        SecureZeroMemory(hash, sizeof(CSP_HASH));
        HeapFree(GetProcessHeap(), 0, hash);
    }
    return TRUE;
}

/* ── The critical function: CPSignHash ───────────────────────── */

BOOL WINAPI CPSignHash(
    HCRYPTPROV hProv,
    HCRYPTHASH hHash,
    DWORD dwKeySpec,
    LPCWSTR szDescription,
    DWORD dwFlags,
    BYTE *pbSignature,
    DWORD *pdwSigLen)
{
    (void)hProv; (void)dwKeySpec; (void)szDescription; (void)dwFlags;

    CSP_HASH *hash = (CSP_HASH *)hHash;
    if (!hash || hash->dwMagic != HASH_MAGIC) {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }

    CSP_CONTEXT *ctx = hash->pCtx;
    csp_log("CPSignHash: AlgId=0x%04X, connected=%d", hash->AlgId, ctx->Connected);

    /* Size query */
    if (!pbSignature) {
        *pdwSigLen = 256; /* RSA-2048 = 256 bytes */
        return TRUE;
    }

    if (*pdwSigLen < 256) {
        *pdwSigLen = 256;
        SetLastError(ERROR_MORE_DATA);
        return FALSE;
    }

    if (!ctx->Connected) {
        csp_log("CPSignHash: not connected to relay");
        SetLastError(NTE_FAIL);
        return FALSE;
    }

    /* Finalize hash if needed */
    if (!hash->Finalized) {
        DWORD dummy = sizeof(hash->HashValue);
        CPGetHashParam(hProv, hHash, HP_HASHVAL, hash->HashValue, &dummy, 0);
    }

    csp_log("CPSignHash: sending hash (%u bytes) to gateway", hash->HashValueLen);

    /* Build SIGN payload: [4 bytes hash length][hash][4 bytes algId] */
    DWORD payloadLen = 4 + hash->HashValueLen + 4;
    UCHAR *payload = (UCHAR *)malloc(payloadLen);
    if (!payload) { SetLastError(NTE_NO_MEMORY); return FALSE; }

    payload[0] = (UCHAR)(hash->HashValueLen & 0xFF);
    payload[1] = (UCHAR)((hash->HashValueLen >> 8) & 0xFF);
    payload[2] = (UCHAR)((hash->HashValueLen >> 16) & 0xFF);
    payload[3] = (UCHAR)((hash->HashValueLen >> 24) & 0xFF);
    memcpy(payload + 4, hash->HashValue, hash->HashValueLen);
    /* Map ALG_ID to our wire format */
    DWORD wireAlgId = (hash->AlgId == CALG_SHA_256) ? 0x800c : 0x8004;
    payload[4 + hash->HashValueLen] = (UCHAR)(wireAlgId & 0xFF);
    payload[5 + hash->HashValueLen] = (UCHAR)((wireAlgId >> 8) & 0xFF);
    payload[6 + hash->HashValueLen] = (UCHAR)((wireAlgId >> 16) & 0xFF);
    payload[7 + hash->HashValueLen] = (UCHAR)((wireAlgId >> 24) & 0xFF);

    if (!relay_send(ctx->GatewaySocket, MSG_SIGN, payload, payloadLen)) {
        free(payload);
        csp_log("CPSignHash: SIGN send failed");
        SetLastError(NTE_FAIL);
        return FALSE;
    }
    free(payload);

    /* Wait for RESULT from gateway (blocking) */
    UCHAR resultType;
    UCHAR *resultPayload = NULL;
    DWORD resultLen;
    if (!relay_read_msg(ctx->GatewaySocket, &resultType, &resultPayload, &resultLen)) {
        csp_log("CPSignHash: RESULT recv failed");
        SetLastError(NTE_FAIL);
        return FALSE;
    }

    if (resultType != MSG_RESULT || resultLen < 4) {
        csp_log("CPSignHash: unexpected response type=%d, len=%u", resultType, resultLen);
        free(resultPayload);
        SetLastError(NTE_FAIL);
        return FALSE;
    }

    DWORD sigLen = resultPayload[0] | (resultPayload[1] << 8) | (resultPayload[2] << 16) | (resultPayload[3] << 24);
    if (sigLen > *pdwSigLen || 4 + sigLen > resultLen) {
        csp_log("CPSignHash: signature too large: %u", sigLen);
        free(resultPayload);
        SetLastError(ERROR_MORE_DATA);
        return FALSE;
    }

    /* CryptoAPI expects the signature in little-endian byte order,
     * but Web Crypto produces big-endian. Reverse the bytes. */
    for (DWORD i = 0; i < sigLen; i++) {
        pbSignature[i] = resultPayload[4 + sigLen - 1 - i];
    }
    *pdwSigLen = sigLen;

    free(resultPayload);
    csp_log("CPSignHash: signature received (%u bytes)", sigLen);
    return TRUE;
}

BOOL WINAPI CPVerifySignature(
    HCRYPTPROV hProv, HCRYPTHASH hHash, const BYTE *pbSignature,
    DWORD dwSigLen, HCRYPTKEY hPubKey, LPCWSTR szDescription, DWORD dwFlags)
{
    (void)hProv; (void)hHash; (void)pbSignature; (void)dwSigLen;
    (void)hPubKey; (void)szDescription; (void)dwFlags;
    csp_log("CPVerifySignature: not implemented");
    SetLastError(NTE_BAD_SIGNATURE);
    return FALSE;
}

BOOL WINAPI CPGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer)
{
    (void)hProv;
    return RtlGenRandom(pbBuffer, dwLen);
}

BOOL WINAPI CPEncrypt(HCRYPTPROV hProv, HCRYPTKEY hKey, HCRYPTHASH hHash,
                      BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen)
{
    (void)hProv; (void)hKey; (void)hHash; (void)Final; (void)dwFlags;
    (void)pbData; (void)pdwDataLen; (void)dwBufLen;
    SetLastError(NTE_BAD_ALGID);
    return FALSE;
}

BOOL WINAPI CPDecrypt(HCRYPTPROV hProv, HCRYPTKEY hKey, HCRYPTHASH hHash,
                      BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen)
{
    (void)hProv; (void)hKey; (void)hHash; (void)Final; (void)dwFlags;
    (void)pbData; (void)pdwDataLen;
    SetLastError(NTE_BAD_ALGID);
    return FALSE;
}

BOOL WINAPI CPDuplicateHash(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD *pdwReserved,
                            DWORD dwFlags, HCRYPTHASH *phHash)
{
    (void)hProv; (void)pdwReserved; (void)dwFlags;
    CSP_HASH *src = (CSP_HASH *)hHash;
    if (!src || src->dwMagic != HASH_MAGIC) {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }
    CSP_HASH *dst = (CSP_HASH *)HeapAlloc(GetProcessHeap(), 0, sizeof(CSP_HASH));
    if (!dst) { SetLastError(NTE_NO_MEMORY); return FALSE; }
    memcpy(dst, src, sizeof(CSP_HASH));
    *phHash = (HCRYPTHASH)dst;
    return TRUE;
}

BOOL WINAPI CPDuplicateKey(HCRYPTPROV hProv, HCRYPTKEY hKey, DWORD *pdwReserved,
                           DWORD dwFlags, HCRYPTKEY *phKey)
{
    (void)hProv; (void)pdwReserved; (void)dwFlags;
    CSP_KEY *src = (CSP_KEY *)hKey;
    if (!src || src->dwMagic != KEY_MAGIC) {
        SetLastError(NTE_BAD_KEY);
        return FALSE;
    }
    CSP_KEY *dst = (CSP_KEY *)HeapAlloc(GetProcessHeap(), 0, sizeof(CSP_KEY));
    if (!dst) { SetLastError(NTE_NO_MEMORY); return FALSE; }
    memcpy(dst, src, sizeof(CSP_KEY));
    *phKey = (HCRYPTKEY)dst;
    return TRUE;
}

/* ── DLL Entry Point ─────────────────────────────────────────── */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    (void)hinstDLL; (void)lpReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        csp_log("TideSSP CSP loaded (DLL_PROCESS_ATTACH)");
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        csp_log("TideSSP CSP unloaded (DLL_PROCESS_DETACH)");
        if (wsa_initialized) WSACleanup();
    }
    return TRUE;
}
