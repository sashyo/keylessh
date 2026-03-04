/*
 * TideSSP — Windows Security Support Provider for Ed25519 authentication.
 * DLL entry point and SpLsaModeInitialize export.
 */

#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

#include <sspi.h>
#include <ntsecapi.h>
#include <ntsecpkg.h>

/* Implemented in ssp.c */
extern SECPKG_FUNCTION_TABLE TideSSP_FunctionTable;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL;
    (void)lpvReserved;
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

/*
 * SpLsaModeInitialize — called by LSA when loading this Security Package.
 * Returns the function table with our SSP callbacks.
 */
NTSTATUS NTAPI SpLsaModeInitialize(
    ULONG LsaVersion,
    PULONG PackageVersion,
    PSECPKG_FUNCTION_TABLE *ppTables,
    PULONG pcTables)
{
    (void)LsaVersion;
    *PackageVersion = SECPKG_INTERFACE_VERSION;
    *ppTables = &TideSSP_FunctionTable;
    *pcTables = 1;
    return STATUS_SUCCESS;
}
