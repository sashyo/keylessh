# SSH host certificates

The browser SSH client verifies the server's identity against a certificate
signed by the VVK, rather than against a key an operator once approved. The
client already trusts the VVK, so there is no `known_hosts` to distribute and no
first-use prompt.

Falls back to trust-on-first-use for hosts without a certificate; see
`hostCertificateAuthority` in `SSHClientOptions`.

## Issuing a certificate

1. **Take the host's existing public key** — `/etc/ssh/ssh_host_ed25519_key.pub`.
   The certificate vouches for this key, so the host keeps the private key it
   already has and nothing secret moves.

2. **Certify it in KeyleSSH.** The certificate body is assembled and signed by
   the VVK under quorum approval. Principals must name how KeyleSSH addresses
   the host — for gateway backends that is the address in the backend URL, e.g.
   `20.70.144.160` for `ssh://20.70.144.160`. A certificate naming no principals
   is refused by the client, since it would otherwise authenticate every host.

3. **Install it** as `/etc/ssh/ssh_host_ed25519_key-cert.pub`.

4. **Point sshd at it.** Placing the file is not enough — sshd does not load
   host certificates unless told to:

   ```
   HostKey /etc/ssh/ssh_host_ed25519_key
   HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
   ```

   If `HostKeyAlgorithms` is set explicitly, include the certificate algorithm:

   ```
   HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,ssh-ed25519
   ```

   Keeping plain `ssh-ed25519` lets clients that predate certificates still
   connect. Drop it to require certificates.

5. **Reload and confirm:**

   ```bash
   sudo sshd -t && sudo systemctl reload sshd
   sudo sshd -T | grep -Ei 'hostkey|hostcertificate'
   ssh -vvv user@host        # should negotiate ssh-ed25519-cert-v01@openssh.com
   ```

## What the client checks

Two signatures, and both are required:

| Check | Proves | Done by |
|---|---|---|
| Key exchange signature | The server holds the private key the certificate vouches for | The SSH library, via the certificate algorithm's verifier |
| CA signature | The VVK vouched for that key and identity | `verifyCertificate` |

The first alone is satisfied by any self-signed certificate, so the second is
what makes this mean anything.

Beyond the signatures: the certificate must be a **host** certificate, name the
host among its principals, be within its validity window (`validBefore` is
exclusive), carry no critical options the client does not implement, and not
have a revoked serial.

## Downgrade protection

When a certificate authority is configured, the client advertises **only**
`ssh-ed25519-cert-v01@openssh.com` during key exchange. Merely preferring it
would let a server — or something impersonating one — offer a plain host key and
pull the connection back to first-use trust.

So for a host configured to require certificates: no valid certificate, no
session.

## Rotation

A certificate's validity window means it expires. Re-issuing repeats steps 2-5;
the host key itself does not change, so nothing on the client needs updating.
Revoking early is done by serial, without waiting for expiry.
