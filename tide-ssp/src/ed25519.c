/*
 * Ed25519 signature verification.
 * Derived from TweetNaCl by Daniel J. Bernstein et al. (public domain).
 * Only the verification path is included — no key generation or signing.
 */

#include "ed25519.h"
#include <string.h>
#include <stdlib.h>

typedef int64_t gf[16];

static const gf gf0 = {0};
static const gf gf1 = {1};
static const gf D = {
    0x78a3, 0x1359, 0x4dca, 0x75eb,
    0xd8ab, 0x4141, 0x0a4d, 0x0070,
    0xe898, 0x7779, 0x4079, 0x8cc7,
    0xfe73, 0x2b6f, 0x6cee, 0x5203
};
static const gf D2 = {
    0xf159, 0x26b2, 0x9b94, 0xebd6,
    0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e,
    0xfce7, 0x56df, 0xd9dc, 0x2406
};
static const gf X = {
    0xd51a, 0x8f25, 0x2d60, 0xc956,
    0xa7b2, 0x9525, 0xc760, 0x692c,
    0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
    0x53fe, 0xcd6e, 0x36d3, 0x2169
};
static const gf Y = {
    0x6658, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666
};
static const gf I_c = {
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee,
    0xe478, 0xad2f, 0x1806, 0x2f43,
    0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
    0xdf0b, 0x4fc1, 0x2480, 0x2b83
};

static void set25519(gf r, const gf a) {
    int i;
    for (i = 0; i < 16; i++) r[i] = a[i];
}

static void car25519(gf o) {
    int64_t c;
    int i;
    for (i = 0; i < 16; i++) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void sel25519(gf p, gf q, int b) {
    int64_t t, c = ~(int64_t)(b - 1);
    int i;
    for (i = 0; i < 16; i++) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(uint8_t *o, const gf n) {
    int i, j, b;
    gf m, t;
    set25519(t, n);
    car25519(t);
    car25519(t);
    car25519(t);
    for (j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (i = 0; i < 16; i++) {
        o[2 * i] = (uint8_t)(t[i] & 0xff);
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static void unpack25519(gf o, const uint8_t *n) {
    int i;
    for (i = 0; i < 16; i++)
        o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void A_gf(gf o, const gf a, const gf b) {
    int i;
    for (i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

static void Z_gf(gf o, const gf a, const gf b) {
    int i;
    for (i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

static void M_gf(gf o, const gf a, const gf b) {
    int64_t t[31];
    int i, j;
    for (i = 0; i < 31; i++) t[i] = 0;
    for (i = 0; i < 16; i++)
        for (j = 0; j < 16; j++)
            t[i + j] += a[i] * b[j];
    for (i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
    for (i = 0; i < 16; i++) o[i] = t[i];
    car25519(o);
    car25519(o);
}

static void S_gf(gf o, const gf a) {
    M_gf(o, a, a);
}

static void inv25519(gf o, const gf a) {
    gf c;
    int i;
    set25519(c, a);
    for (i = 253; i >= 0; i--) {
        S_gf(c, c);
        if (i != 2 && i != 4) M_gf(c, c, a);
    }
    set25519(o, c);
}

static void pow2523(gf o, const gf i_val) {
    gf c;
    int a;
    set25519(c, i_val);
    for (a = 250; a >= 0; a--) {
        S_gf(c, c);
        if (a != 1) M_gf(c, c, i_val);
    }
    set25519(o, c);
}

static int neq25519(const gf a, const gf b) {
    uint8_t c[32], d[32];
    pack25519(c, a);
    pack25519(d, b);
    return memcmp(c, d, 32);
}

static uint8_t par25519(const gf a) {
    uint8_t d[32];
    pack25519(d, a);
    return d[0] & 1;
}

/* Extended point: (X, Y, Z, T) where x=X/Z, y=Y/Z, x*y=T/Z */
static void add_point(gf p[4], gf q[4]) {
    gf a, b, c, dd, e, f, g, h;
    Z_gf(a, p[1], p[0]);
    Z_gf(h, q[1], q[0]);
    M_gf(a, a, h);
    A_gf(b, p[0], p[1]);
    A_gf(h, q[0], q[1]);
    M_gf(b, b, h);
    M_gf(c, p[3], q[3]);
    M_gf(c, c, D2);
    M_gf(dd, p[2], q[2]);
    A_gf(dd, dd, dd);
    Z_gf(e, b, a);
    Z_gf(f, dd, c);
    A_gf(g, dd, c);
    A_gf(h, b, a);
    M_gf(p[0], e, f);
    M_gf(p[1], h, g);
    M_gf(p[2], g, f);
    M_gf(p[3], e, h);
}

static void cswap_point(gf p[4], gf q[4], uint8_t b) {
    int i;
    for (i = 0; i < 4; i++) sel25519(p[i], q[i], b);
}

static void scalarmult(gf p[4], gf q[4], const uint8_t *s) {
    int i;
    set25519(p[0], gf0);
    set25519(p[1], gf1);
    set25519(p[2], gf1);
    set25519(p[3], gf0);
    for (i = 255; i >= 0; --i) {
        uint8_t b = (s[i / 8] >> (i & 7)) & 1;
        cswap_point(p, q, b);
        add_point(q, p);
        add_point(p, p);
        cswap_point(p, q, b);
    }
}

static void scalarbase(gf p[4], const uint8_t *s) {
    gf q[4];
    set25519(q[0], X);
    set25519(q[1], Y);
    set25519(q[2], gf1);
    M_gf(q[3], X, Y);
    scalarmult(p, q, s);
}

static int unpackneg(gf r[4], const uint8_t p[32]) {
    gf t, chk, num, den, den2, den4, den6;
    set25519(r[2], gf1);
    unpack25519(r[1], p);
    S_gf(num, r[1]);           /* num = y^2 */
    M_gf(den, num, D);        /* den = d*y^2 */
    Z_gf(num, num, r[2]);     /* num = y^2 - 1 */
    A_gf(den, r[2], den);     /* den = 1 + d*y^2 */

    S_gf(den2, den);
    S_gf(den4, den2);
    M_gf(den6, den4, den2);
    M_gf(t, den6, num);
    M_gf(t, t, den);

    pow2523(t, t);
    M_gf(t, t, num);
    M_gf(t, t, den);
    M_gf(t, t, den);
    M_gf(r[0], t, den);

    S_gf(chk, r[0]);
    M_gf(chk, chk, den);
    if (neq25519(chk, num)) {
        M_gf(r[0], r[0], I_c);
        S_gf(chk, r[0]);
        M_gf(chk, chk, den);
        if (neq25519(chk, num)) return -1;
    }

    if (par25519(r[0]) == (p[31] >> 7)) {
        Z_gf(r[0], gf0, r[0]); /* negate x */
    }

    M_gf(r[3], r[0], r[1]);
    return 0;
}

static void reduce(uint8_t *r) {
    int64_t x[64];
    static const int64_t L[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10
    };
    int i, j;
    for (i = 0; i < 64; i++) x[i] = (uint64_t)r[i];
    for (i = 0; i < 64; i++) r[i] = 0;
    for (i = 63; i >= 32; i--) {
        int64_t carry = 0;
        for (j = i - 32; j < i - 12; j++) {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[j] += carry;
        x[i] = 0;
    }
    {
        int64_t carry = 0;
        for (j = 0; j < 32; j++) {
            x[j] += carry - (x[31] >> 4) * L[j];
            carry = x[j] >> 8;
            x[j] &= 255;
        }
        for (j = 0; j < 32; j++) x[j] -= carry * L[j];
        for (i = 0; i < 32; i++) {
            x[i + 1] += x[i] >> 8;
            r[i] = (uint8_t)(x[i] & 255);
        }
    }
}

/* SHA-512 — minimal implementation for Ed25519 */

static uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

static uint64_t load64be(const uint8_t *p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  | (uint64_t)p[7];
}

static void store64be(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56); p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40); p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24); p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);  p[7] = (uint8_t)v;
}

static void sha512_block(uint64_t h[8], const uint8_t block[128]) {
    uint64_t w[80], a, b, c, dd, e, f, g, hh, t1, t2;
    int j;
    for (j = 0; j < 16; j++) w[j] = load64be(block + j * 8);
    for (j = 16; j < 80; j++) {
        uint64_t s0 = rotr64(w[j - 15], 1) ^ rotr64(w[j - 15], 8) ^ (w[j - 15] >> 7);
        uint64_t s1 = rotr64(w[j - 2], 19) ^ rotr64(w[j - 2], 61) ^ (w[j - 2] >> 6);
        w[j] = w[j - 16] + s0 + w[j - 7] + s1;
    }
    a = h[0]; b = h[1]; c = h[2]; dd = h[3];
    e = h[4]; f = h[5]; g = h[6]; hh = h[7];
    for (j = 0; j < 80; j++) {
        uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        t1 = hh + S1 + ch + K512[j] + w[j];
        uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;
        hh = g; g = f; f = e; e = dd + t1;
        dd = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += dd;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static void sha512(uint8_t hash[64], const uint8_t *m, size_t n) {
    uint64_t h[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };
    uint8_t block[128];
    size_t i;

    for (i = 0; i + 128 <= n; i += 128)
        sha512_block(h, m + i);

    size_t rem = n - i;
    memset(block, 0, 128);
    memcpy(block, m + i, rem);
    block[rem] = 0x80;

    if (rem >= 112) {
        sha512_block(h, block);
        memset(block, 0, 128);
    }

    store64be(block + 120, (uint64_t)n * 8);
    /* block[112..119] stays 0 (high 64 bits of bit count) */
    sha512_block(h, block);

    for (i = 0; i < 8; i++) store64be(hash + i * 8, h[i]);
}

/*
 * Ed25519 verify: check that signature (R, S) is valid for (message, public_key).
 *
 * 1. Decode A = -public_key (negate for subtraction)
 * 2. h = SHA-512(R || public_key || message) mod l
 * 3. Compute P = [S]B + [h](-A)  (should equal R)
 * 4. Encode P and compare to R
 */
int ed25519_verify(
    const uint8_t signature[64],
    const uint8_t *message,
    size_t message_len,
    const uint8_t public_key[32])
{
    uint8_t h[64], t[32];
    gf p[4], q[4];
    uint8_t *buf;

    /* S must be < L (the group order) */
    if (signature[63] & 0xE0) return -1;

    /* Decode -A from public key */
    if (unpackneg(q, public_key) != 0) return -1;

    /* h = SHA-512(R || A || M) mod l */
    buf = (uint8_t *)malloc(64 + message_len);
    if (!buf) return -1;
    memcpy(buf, signature, 32);         /* R */
    memcpy(buf + 32, public_key, 32);   /* A */
    memcpy(buf + 64, message, message_len);
    sha512(h, buf, 64 + message_len);
    free(buf);
    reduce(h);

    /* P = [S]B + [h](-A) */
    scalarmult(p, q, h);                /* p = [h](-A) */
    scalarbase(q, signature + 32);      /* q = [S]B */
    add_point(p, q);                    /* p = [S]B + [h](-A) */

    /* Encode P in compressed form and compare to R */
    {
        gf zinv, ax, ay;
        inv25519(zinv, p[2]);
        M_gf(ax, p[0], zinv);
        M_gf(ay, p[1], zinv);
        pack25519(t, ay);
        t[31] ^= par25519(ax) << 7;
    }

    return memcmp(t, signature, 32) == 0 ? 0 : -1;
}
