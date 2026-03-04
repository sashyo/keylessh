# TideSSP — Ed25519 Security Support Provider for Windows

A Windows Security Support Provider (SSP) that enables Ed25519-based authentication for RDP sessions, replacing traditional NTLM password-based auth.

## How it works

1. Gateway sends a NEGOTIATE token with the username
2. TideSSP generates a random 32-byte challenge
3. Gateway relays the challenge to the browser
4. Browser signs the challenge using TideCloak's Ed25519 key (via Tide enclave)
5. Gateway sends the AUTHENTICATE token with signature + public key
6. TideSSP verifies the Ed25519 signature and creates a Windows logon session

## Build

Requires Windows with MSVC (Visual Studio Build Tools).

```powershell
cmake -B build
cmake --build build --config Release
```

## Install

Run as Administrator:

```powershell
.\install.ps1
```

Then reboot.

## Uninstall

```powershell
.\install.ps1 -Uninstall
```

Then reboot.

## Wire Protocol

```
NEGOTIATE (client → server):
  [0x01][version:u8][username_len:u16LE][username:UTF-8]

CHALLENGE (server → client):
  [0x02][challenge:32 bytes]

AUTHENTICATE (client → server):
  [0x03][signature:64 bytes][pubkey:32 bytes]
```

## Security

- Ed25519 verification uses TweetNaCl (public domain, no external dependencies)
- Challenge is 32 bytes of cryptographic random (BCryptGenRandom)
- Private key never exists in full — TideCloak threshold cryptography splits it across ORK nodes
- SSP runs in LSA context within standard Windows security boundaries
