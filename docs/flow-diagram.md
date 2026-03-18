# KeyleSSH: STUN → WebRTC → EdDSA → RDP Connection Flow

## High-Level Architecture

```
┌──────────┐     ┌───────────────┐     ┌─────────────┐     ┌────────────┐
│  Browser  │────▶│ Signal Server │◀────│   Gateway   │────▶│ RDP Server │
│ (IronRDP) │     │  (STUN+Relay) │     │ (punchd-    │     │ (TideSSP)  │
│           │◄═════════════════════════▶│  bridge)    │     │            │
└──────────┘  WebRTC DataChannel (P2P)  └─────────────┘     └────────────┘
```

---

## Detailed Step-by-Step Flow

### Phase 1: Gateway Registration (startup)

```
Gateway                          Signal Server
   │                                  │
   │──── WS connect ─────────────────▶│
   │                                  │
   │──── { type: "register",          │
   │       role: "gateway",           │
   │       id: gatewayId,             │
   │       secret: API_SECRET,        │  timing-safe comparison
   │       addresses: [...],          │  of API_SECRET
   │       metadata: {backends} } ───▶│
   │                                  │
   │◀─── { type: "registered" } ──────│
   │                                  │
   │  Creates PeerHandler with        │
   │  ICE servers config              │
   │                                  │
```

*Source: [stun-client.ts:59-108](bridges/punchd-bridge/gateway/src/registration/stun-client.ts#L59-L108)*
*Source: [signal index.ts:736-776](signal-server/src/index.ts#L736-L776)*

---

### Phase 2: Client Registration & Pairing

```
Browser                          Signal Server                    Gateway
   │                                  │                              │
   │──── WS connect ─────────────────▶│                              │
   │                                  │                              │
   │──── { type: "register",          │                              │
   │       role: "client",            │                              │
   │       id: clientId,              │  Pairs client with           │
   │       token: JWT,                │  least-loaded gateway        │
   │       targetGatewayId? } ───────▶│  (or explicit target)        │
   │                                  │                              │
   │◀─── { type: "registered" } ──────│                              │
   │                                  │                              │
   │◀─── { type: "paired",            │──── { type: "paired",        │
   │       client: {...} } ───────────│      client: {id,            │
   │                                  │      reflexiveAddress} } ───▶│
```

*Source: [signal index.ts:759-773](signal-server/src/index.ts#L759-L773)*

---

### Phase 3: WebRTC SDP/ICE Exchange (NAT Traversal)

```
Browser                          Signal Server                    Gateway
   │                                  │                              │
   │──── { type: "sdp_offer",         │                              │
   │       fromId: clientId,          │  Forwards to                 │
   │       targetId: gatewayId,       │  paired peer                 │
   │       sdp: localDesc } ─────────▶│──── sdp_offer ──────────────▶│
   │                                  │                              │
   │                                  │  Gateway creates             │
   │                                  │  PeerConnection with         │
   │                                  │  ICE servers:                │
   │                                  │  - STUN: stun:host:3478      │
   │                                  │  - TURN: turn:user:pass@host │
   │                                  │  (ephemeral HMAC-SHA1 creds, │
   │                                  │   1-hour validity)           │
   │                                  │                              │
   │                                  │◀─── { type: "sdp_answer",    │
   │◀─── sdp_answer ──────────────────│      sdp: remoteDesc } ──────│
   │                                  │                              │
   │──── { type: "candidate",         │                              │
   │       candidate: {...} } ───────▶│──── candidate ──────────────▶│
   │                                  │                              │
   │                                  │◀─── { type: "candidate",     │
   │◀─── candidate ───────────────────│      candidate: {...} } ─────│
   │                                  │                              │
   │  ICE connectivity checks:        │                              │
   │  1. Try host candidates (direct) │                              │
   │  2. Try server-reflexive (STUN)  │                              │
   │  3. Fallback to relay (TURN)     │                              │
   │                                  │                              │
   ╞══════════ DTLS + SCTP ═══════════╪══════════════════════════════╡
   │     WebRTC DataChannel (P2P or TURN relay)                      │
```

*Source: [peer-handler.ts:200-301](bridges/punchd-bridge/gateway/src/webrtc/peer-handler.ts#L200-L301)*
*Source: [signal index.ts:413-441](signal-server/src/index.ts#L413-L441) (TURN credential generation)*

---

### Phase 4: DataChannel Setup & Capabilities

```
Browser ◄══════ WebRTC DataChannel ══════▶ Gateway
   │                                        │
   │  dc label: "http-tunnel" (control)     │
   │  dc label: "bulk-data" (binary fast)   │
   │                                        │
   │◀──── { type: "capabilities",           │
   │        version: 2,                     │
   │        features: ["bulk-channel",      │
   │                   "binary-ws",         │  Sent proactively
   │                   "tcp-tunnel"] } ─────│  on channel open
   │                                        │
   │──── { type: "capabilities",            │
   │       features: [...] } ──────────────▶│
```

*Source: [peer-handler.ts:285-311](bridges/punchd-bridge/gateway/src/webrtc/peer-handler.ts#L285-L311)*

---

### Phase 5: RDCleanPath — Browser Opens Virtual WebSocket

```
Browser (IronRDP WASM)              Gateway (peer-handler)
   │                                     │
   │──── { type: "ws_open",              │
   │       id: UUID,                     │
   │       url: "/ws/rdcleanpath" } ────▶│
   │                                     │  Detects RDCleanPath URL
   │◀──── { type: "ws_opened" } ─────────│  Creates RDCleanPath session
   │                                     │
   │──── ws_message (binary):            │
   │     RDCleanPath Request PDU         │
   │     (ASN.1 DER):                    │
   │       [0] version = 3390            │
   │       [2] destination = "My PC"     │
   │       [3] proxyAuth = JWT           │
   │       [6] x224ConnectionPdu ───────▶│
   │                                     │
```

*Source: [peer-handler.ts:860-975](bridges/punchd-bridge/gateway/src/webrtc/peer-handler.ts#L860-L975)*

---

### Phase 6: RDCleanPath — Gateway Connects to RDP Server

```
Gateway                                          RDP Server
   │                                                  │
   │  1. Validate JWT (verifyToken)                   │
   │     - Local JWKS first, remote fallback          │
   │     - Check AZP matches TideCloak client         │
   │                                                  │
   │  2. Enforce dest: role                           │
   │     "dest:<gatewayId>:<backendName>"             │
   │     from realm_access.roles +                    │
   │     resource_access[clientId].roles              │
   │                                                  │
   │  3. Resolve backend → rdp://host:port            │
   │                                                  │
   │──── TCP connect ────────────────────────────────▶│ :3389
   │                                                  │
   │  4. For eddsa backends: patch X.224 to set       │
   │     RESTRICTED_ADMIN_MODE_REQUIRED flag (0x01)   │
   │                                                  │
   │──── X.224 Connection Request ───────────────────▶│
   │◀─── X.224 Connection Confirm ────────────────────│
   │                                                  │
   │──── TLS ClientHello ────────────────────────────▶│
   │◀─── TLS ServerHello + Certificate ───────────────│
   │  ... TLS handshake completes ...                 │
   │                                                  │
   │  5. Extract server cert chain (DER, leaf first)  │
```

*Source: [rdcleanpath-handler.ts:104-256](bridges/punchd-bridge/gateway/src/rdcleanpath/rdcleanpath-handler.ts#L104-L256)*

---

### Phase 7: CredSSP/NLA with EdDSA Verification (NEGOEX)

```
Gateway (CredSSP client)              TLS              RDP Server (TideSSP)
   │                                   │                      │
   │  STEP 1: NEGOEX INITIATOR_NEGO + AP_REQUEST(JWT)        │
   │                                   │                      │
   │  TSRequest v6 {                   │                      │
   │    negoToken: SPNEGO NegTokenInit │                      │
   │      mechTypes: [NEGOEX OID]      │                      │
   │      mechToken:                   │                      │
   │        NEGOEX msg 1: INITIATOR_NEGO                      │
   │          authSchemes: [{7A4E8B2C-...}]                   │
   │        NEGOEX msg 2: AP_REQUEST   │                      │
   │          authScheme: {7A4E8B2C-...}                      │
   │          token: [0x04][JWT ASCII] │                      │
   │    clientNonce: 32 random bytes   │                      │
   │  } ──────────────────────────────▶│─────────────────────▶│
   │                                   │                      │
   │                                   │  TideSSP receives    │
   │                                   │  TOKEN_JWT (0x04):   │
   │                                   │                      │
   │                                   │  a) Parse JWT:       │
   │                                   │     header.payload.sig
   │                                   │                      │
   │                                   │  b) base64url decode │
   │                                   │     signature → 64B  │
   │                                   │                      │
   │                                   │  c) Ed25519 verify:  │
   │                                   │     ed25519_verify(  │
   │                                   │       sig,           │
   │                                   │       "header.payload",
   │                                   │       JWK_PUBLIC_KEY)│
   │                                   │     (hardcoded 32B   │
   │                                   │      Ed25519 pubkey) │
   │                                   │                      │
   │                                   │  d) Check JWT expiry │
   │                                   │     (exp claim)      │
   │                                   │                      │
   │                                   │  e) Extract username │
   │                                   │     (preferred_username
   │                                   │      or sub claim)   │
   │                                   │                      │
   │                                   │  f) Derive session   │
   │                                   │     key:             │
   │                                   │     SHA-256(sig_bytes)│
   │                                   │     truncated to 16B │
   │                                   │                      │
   │                                   │  g) S4U logon →      │
   │                                   │     Windows token    │
   │                                   │     + add S-1-5-14   │
   │                                   │     (RemoteInteractive)
   │                                   │     via NtCreateToken│
   │                                   │                      │
   │                                   │  h) Store NLA session:│
   │                                   │     {sessionKey,     │
   │                                   │      ntHash=MD4(     │
   │                                   │       UTF16(hex(key))),
   │                                   │      username}       │
   │                                   │                      │
   │  STEP 2: Server responds          │                      │
   │                                   │                      │
   │  TSRequest {                      │                      │
   │    negoToken: SPNEGO NegTokenResp │                      │
   │      NEGOEX: ACCEPTOR_NEGO       │                      │
   │             + VERIFY (checksum)   │                      │
   │  } ◀─────────────────────────────│◀──────────────────────│
   │                                   │                      │
   │  Gateway verifies server VERIFY:  │                      │
   │  - sessionKey = SHA-256(jwt_sig)  │                      │
   │    truncated to 16 bytes          │                      │
   │  - HMAC-SHA1-96-AES128 checksum  │                      │
   │    over transcript (ku=23)        │                      │
   │                                   │                      │
   │  STEP 3: Client VERIFY            │                      │
   │                                   │                      │
   │  TSRequest {                      │                      │
   │    negoToken: SPNEGO NegTokenResp │                      │
   │      NEGOEX: VERIFY               │                      │
   │        checksum (ku=25,           │                      │
   │         4-msg transcript)         │                      │
   │  } ──────────────────────────────▶│─────────────────────▶│
   │                                   │                      │
   │  STEP 4: SPNEGO complete          │                      │
   │  ◀───────────────────────────────│◀──────────────────────│
   │                                   │                      │
   │  STEP 5: pubKeyAuth (TLS binding) │                      │
   │                                   │                      │
   │  clientHash = SHA-256(            │                      │
   │    "CredSSP Client-To-Server      │                      │
   │     Binding Hash\0"               │                      │
   │    + clientNonce                   │                      │
   │    + SubjectPublicKey)            │                      │
   │                                   │                      │
   │  TSRequest {                      │                      │
   │    pubKeyAuth: AES-128-GCM(       │                      │
   │      sessionKey, clientHash)      │                      │
   │  } ──────────────────────────────▶│─────────────────────▶│
   │                                   │                      │
   │  STEP 6: Server pubKeyAuth        │                      │
   │                                   │                      │
   │  serverHash = SHA-256(            │                      │
   │    "CredSSP Server-To-Client      │                      │
   │     Binding Hash\0"               │                      │
   │    + clientNonce                   │                      │
   │    + SubjectPublicKey)            │                      │
   │                                   │                      │
   │  TSRequest {                      │                      │
   │    pubKeyAuth: AES-128-GCM(...)   │                      │
   │  } ◀─────────────────────────────│◀──────────────────────│
   │                                   │                      │
   │  Gateway verifies server hash     │                      │
   │                                   │                      │
   │  STEP 7: authInfo (credentials)   │                      │
   │                                   │                      │
   │  TSRequest {                      │                      │
   │    authInfo: AES-128-GCM(         │                      │
   │      TSCredentials {              │                      │
   │        credType: 1 (password)     │                      │
   │        domain: "."                │                      │
   │        user: <from JWT>           │                      │
   │        password: ""               │                      │
   │      })                           │                      │
   │  } ──────────────────────────────▶│─────────────────────▶│
   │                                   │                      │
   │  NLA COMPLETE                     │                      │
```

*Source: [credssp-client.ts:77-394](bridges/punchd-bridge/gateway/src/rdcleanpath/credssp-client.ts#L77-L394)*
*Source: [ssp.c:653-789](tide-ssp/src/ssp.c#L653-L789) (TideSSP AcceptLsaModeContext)*
*Source: [ssp.c:590-610](tide-ssp/src/ssp.c#L590-L610) (session key derivation)*
*Source: [ssp.c:172-209](tide-ssp/src/ssp.c#L172-L209) (NLA session store)*

---

### Phase 8: Desktop Session via Restricted Admin

```
Gateway                                    RDP Server
   │                                            │
   │  Read Early User Authorization Result      │
   │  (4 bytes LE, must be 0x00000000)          │
   │◀───────────────────────────────────────────│
   │                                            │
   │  Patch X.224 selectedProtocol back         │
   │  to original (e.g. PROTOCOL_HYBRID_EX=8)  │
   │  but tell IronRDP it's PROTOCOL_SSL        │
   │  so it skips NLA (already done)            │
   │                                            │
   │  Send RDCleanPath Response PDU to browser: │
   │    x224ConnectionPdu (patched)             │
   │    serverCertChain (DER certs)             │
   │    serverAddr                              │
   │                                            │

Browser (IronRDP)              Gateway                  RDP Server
   │                              │                          │
   │◀── RDCleanPath Response ─────│                          │
   │                              │                          │
   │  IronRDP completes           │                          │
   │  MCS/RDP handshake           │                          │
   │                              │                          │
   │──── MCS Connect Initial ────▶│                          │
   │                              │  Patch MCS               │
   │                              │  serverSelectedProtocol  │
   │                              │  back to real value      │
   │                              │──── (patched) ──────────▶│
   │                              │                          │
   │  ◄══════ Bidirectional relay: TLS socket ↔ DataChannel ══════▶
   │                              │                          │
   │  RESTRICTED ADMIN mode:      │                          │
   │  termsrv uses NLA token      │                          │
   │  (SECPKG_ATTR_ACCESS_TOKEN)  │                          │
   │  directly for desktop logon  │                          │
   │  — no password re-auth       │                          │
   │                              │                          │
   │  ╔══════════════════════╗    │                          │
   │  ║  RDP Session Active  ║    │                          │
   │  ╚══════════════════════╝    │                          │
```

*Source: [rdcleanpath-handler.ts:258-361](bridges/punchd-bridge/gateway/src/rdcleanpath/rdcleanpath-handler.ts#L258-L361)*
*Source: [rdcleanpath-handler.ts:557-595](bridges/punchd-bridge/gateway/src/rdcleanpath/rdcleanpath-handler.ts#L557-L595) (MCS patching)*

---

## Data Channel Transport

```
Binary fast-path for RDP data:

  Browser ──── DataChannel "bulk-data" ────▶ Gateway
  [0x02][36-byte WS UUID][RDP payload]       │
                                             │  Forwards to
                                             │  RDCleanPath session
                                             ▼
  Gateway ──── TLS socket ─────────────────▶ RDP Server
  [raw RDP payload]

  RDP Server ──── TLS socket ──────────────▶ Gateway
  [raw RDP payload]                          │
                                             │  BINARY_WS_MAGIC (0x02)
                                             ▼
  Gateway ──── DataChannel "bulk-data" ────▶ Browser
  [0x02][36-byte WS UUID][RDP payload]
```

*Source: [peer-handler.ts:394-451](bridges/punchd-bridge/gateway/src/webrtc/peer-handler.ts#L394-L451) (bulk channel)*
*Source: [peer-handler.ts:946-960](bridges/punchd-bridge/gateway/src/webrtc/peer-handler.ts#L946-L960) (RDCleanPath binary send)*

---

## EdDSA Verification Detail (TideSSP ssp.c)

```
                    JWT Token
                        │
                        ▼
            ┌───────────────────────┐
            │ Parse: header.payload │
            │         .signature    │
            └───────┬───────────────┘
                    │
                    ▼
            ┌───────────────────────┐
            │ base64url_decode(sig) │
            │ → 64 bytes            │
            └───────┬───────────────┘
                    │
                    ▼
    ┌───────────────────────────────────┐
    │      ed25519_verify(              │
    │        sig_bytes,                 │
    │        "header.payload" (ASCII),  │
    │        JWK_PUBLIC_KEY             │  ← hardcoded 32-byte
    │      )                            │     Ed25519 public key
    └───────────────┬───────────────────┘
                    │
               ┌────┴────┐
               │ OK?     │
               └────┬────┘
                    │ yes
                    ▼
    ┌───────────────────────────────────┐
    │ Check exp claim > current time    │
    └───────────────┬───────────────────┘
                    │
                    ▼
    ┌───────────────────────────────────┐
    │ Extract preferred_username        │
    │ (fallback: sub)                   │
    └───────────────┬───────────────────┘
                    │
                    ▼
    ┌───────────────────────────────────┐
    │ Session Key = SHA-256(sig_bytes)  │
    │               [0..15]  (16 bytes) │
    └───────────────┬───────────────────┘
                    │
                    ▼
    ┌───────────────────────────────────┐
    │ S4U Logon → Windows Token         │
    │ + NtCreateToken with S-1-5-14     │
    │   (Remote Interactive SID)        │
    └───────────────┬───────────────────┘
                    │
                    ▼
    ┌───────────────────────────────────┐
    │ Store NLA Session:                │
    │   ntHash = MD4(UTF16LE(hex(key))) │
    │   TTL = 60 seconds                │
    │   One-time use                    │
    └───────────────────────────────────┘
```

*Source: [ssp.c:95-103](tide-ssp/src/ssp.c#L95-L103) (JWK public key)*
*Source: [ssp.c:703-789](tide-ssp/src/ssp.c#L703-L789) (JWT verification flow)*
*Source: [ssp.c:321-474](tide-ssp/src/ssp.c#L321-L474) (NtCreateToken with logon SIDs)*

---

## Session Key Agreement

Both gateway and TideSSP derive the **same session key** independently:

```
Gateway (negoex.ts):                    TideSSP (ssp.c):
  deriveSessionKeyFromJwt(jwt)            deriveSessionKeyFromSig(sigBytes, 64, outKey)
  → SHA-256(base64url_decode(             → SHA-256(sigBytes)
      jwt.split(".")[2]))                    [0..15]
    [0..15]

  Same 16-byte key ◄──────────────────▶ Same 16-byte key

Used for:
  • NEGOEX VERIFY checksums (HMAC-SHA1-96-AES128)
  • pubKeyAuth encryption (AES-128-GCM)
  • authInfo encryption (AES-128-GCM)
```

*Source: [negoex.ts deriveSessionKeyFromJwt](bridges/punchd-bridge/gateway/src/rdcleanpath/negoex.ts)*
*Source: [ssp.c:590-610](tide-ssp/src/ssp.c#L590-L610)*
