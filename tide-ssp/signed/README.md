# Microsoft-signed LSA binaries

`TideSSP.dll` and `TideSubAuth.dll` load into LSASS. With LSA Protection on —
the default on clean Windows 11 22H2+ installs — LSASS loads only modules
carrying a **Microsoft** signature. An EV code-signing certificate cannot
produce one: it authenticates your Partner Center account and signs the
submission; Microsoft signs the binaries.

So a working `TideSSP.msi` cannot be built in a single CI run. The DLLs make a
round trip through Microsoft first, and the MSI is built around what comes back.

## Getting the signed DLLs

```powershell
# 1. Build the DLLs
cmake -B build -S . -A x64
cmake --build build --config Release

# 2. Package them into a signed CAB
.\signing\build-lsa-cab.ps1 -Thumbprint <your EV cert thumbprint>

# 3. Submit out\signing\TideSSP-LSA.cab via Partner Center:
#    Hardware -> Submit new hardware
#    https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/file-signing-manage

# 4. When Microsoft returns the signed DLLs, drop them in this directory
#    and record what they came from in MANIFEST.md.
```

Do **not** re-sign the returned DLLs. Adding your own signature replaces
Microsoft's and LSA rejects them again.

## What goes here

    TideSSP.dll        Microsoft-signed
    TideSubAuth.dll    Microsoft-signed
    MANIFEST.md        which source commit they were built from, and when

`TideCA.dll` does not belong here. It is an MSI custom action that runs in
msiexec, never in LSA, so it is built from source at release time and covered by
your own EV signature.

## Why the source commit matters

A signature covers exact bytes. Change a line in `src/ssp.c`, rebuild, and the
signature no longer applies — that needs a fresh submission. `MANIFEST.md`
records which commit the signed binaries came from so it is obvious when they
have drifted from the source tree.

## What the release build does

`build-tidessp` in `.github/workflows/release.yml` prefers these files when
present and falls back to freshly compiled DLLs when they are absent, so day-to-day
builds keep working. The fallback MSI is published under a different artifact
name and **will not load under LSA Protection** — it is for development on
machines with `RunAsPPL` disabled.
