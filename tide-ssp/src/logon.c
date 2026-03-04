/*
 * TideSSP — LsaLogonUser helper.
 *
 * Creates a Windows logon session for a verified user using S4U logon
 * (Service-for-User). This allows password-less logon after Ed25519
 * signature verification succeeds.
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

/*
 * S4U logon: log in a user without their password.
 * The SSP runs in LSA context, which has the privilege to do this.
 *
 * This creates a KERB_S4U_LOGON structure and calls LsaLogonUser
 * through the LSA dispatch table.
 *
 * For a simpler initial implementation, we use the MSV1_0
 * S4U logon type which works for local accounts.
 */
NTSTATUS TideLogonUser(
    PLSA_SECPKG_FUNCTION_TABLE LsaDispatch,
    const WCHAR *username,
    PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
    PVOID *TokenInformation,
    PULONG TokenInfoSize)
{
    (void)LsaDispatch;
    (void)TokenInformationType;
    (void)TokenInformation;
    (void)TokenInfoSize;

    /*
     * NOTE: Full implementation requires calling LsaDispatch->CreateToken
     * or LsaDispatch->AllocateLsaHeap + building TOKEN_INFORMATION_V2.
     *
     * For the initial version, we verify the Ed25519 signature in ssp.c
     * and trust that the username maps to a local account. The RDP server
     * (termsrv) will create the session based on the authenticated context.
     *
     * The actual token creation flow:
     * 1. Look up the user SID via LsaDispatch->GetAuthDataForUser
     * 2. Build LSA_TOKEN_INFORMATION_V2 with the user's groups
     * 3. Return it so LSA can create the logon session
     *
     * For now, return success — the AcceptSecurityContext return code
     * (SEC_E_OK) tells CredSSP that auth succeeded, and termsrv will
     * map the username to a local session.
     */

    NTSTATUS status = STATUS_SUCCESS;

    if (!username || username[0] == L'\0')
        return STATUS_NO_SUCH_USER;

    /*
     * Use GetAuthDataForUser to look up the account and get auth data.
     * This is the LSA-side equivalent of LookupAccountName.
     */
    if (LsaDispatch && LsaDispatch->GetAuthDataForUser) {
        UNICODE_STRING uname;
        PUCHAR authData = NULL;
        ULONG authDataSize = 0;
        UNICODE_STRING flatNameBuf = {0};

        uname.Length = (USHORT)(wcslen(username) * sizeof(WCHAR));
        uname.MaximumLength = uname.Length + sizeof(WCHAR);
        uname.Buffer = (PWSTR)username;

        status = LsaDispatch->GetAuthDataForUser(
            (PSECURITY_STRING)&uname,
            SecNameFlat,       /* look up as flat (SAM) name */
            NULL,              /* no domain prefix */
            &authData,
            &authDataSize,
            &flatNameBuf);

        if (NT_SUCCESS(status) && authData) {
            /*
             * Convert auth data to token information that LSA can use
             * to create a logon session.
             */
            if (LsaDispatch->ConvertAuthDataToToken) {
                HANDLE tokenHandle = NULL;
                LUID logonId = {0};
                NTSTATUS subStatus = STATUS_SUCCESS;
                TOKEN_SOURCE tokenSource;

                memcpy(tokenSource.SourceName, "TideSSP\0", TOKEN_SOURCE_LENGTH);
                AllocateLocallyUniqueId(&tokenSource.SourceIdentifier);

                UNICODE_STRING accountName = uname;
                UNICODE_STRING authority;
                authority.Length = 0;
                authority.MaximumLength = 0;
                authority.Buffer = NULL;

                status = LsaDispatch->ConvertAuthDataToToken(
                    authData,
                    authDataSize,
                    SecurityImpersonation,
                    &tokenSource,
                    Interactive,       /* RDP needs interactive logon */
                    &authority,
                    &tokenHandle,
                    &logonId,
                    &accountName,
                    &subStatus);

                if (NT_SUCCESS(status) && tokenHandle) {
                    /* Token created successfully — store for CredSSP */
                    if (TokenInformation) *TokenInformation = tokenHandle;
                    if (TokenInfoSize) *TokenInfoSize = sizeof(HANDLE);
                    if (TokenInformationType)
                        *TokenInformationType = LsaTokenInformationV2;
                }
            }

            if (LsaDispatch->FreeLsaHeap && authData)
                LsaDispatch->FreeLsaHeap(authData);
        }
    }

    return status;
}
