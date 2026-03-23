#ifndef TIDE_ED25519_H
#define TIDE_ED25519_H

#include <stdint.h>
#include <stddef.h>

/*
 * Ed25519 signature verification.
 * Based on TweetNaCl (public domain) — verify-only, no signing needed.
 *
 * Returns 0 on success, -1 on failure.
 */
int ed25519_verify(
    const uint8_t signature[64],
    const uint8_t *message,
    size_t message_len,
    const uint8_t public_key[32]
);

#endif /* TIDE_ED25519_H */
