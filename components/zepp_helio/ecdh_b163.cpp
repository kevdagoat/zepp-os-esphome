// ECDH sect163k1 — C++ port of huami_ecdh.py / Gadgetbridge ECDH_B163.java.
// Fixed 6-word (192-bit) GF(2^163) storage, LSB-first word ordering.
//
// WARNING: not constant-time. Untested on-device. Cross-check against
// huami_ecdh.py test vectors before trusting in production.

#include "ecdh_b163.h"
#include "esp_system.h"
#include <cstring>

namespace esphome {
namespace zepp_helio {

static constexpr int CURVE_DEGREE = 163;
static constexpr int WORDS = BITVEC_WORDS;  // 6

// Reduction poly for sect163k1: x^163 + x^7 + x^6 + x^3 + 1
// POLY low = 0xC9 = 11001001b (bits 7,6,3,0)
// POLY bit 163 sits in word 5 bit 3 (163 = 5*32+3) = 0x08
static const uint32_t POLY_LOW = 0xC9u;
static const uint32_t POLY_W5 = 0x08u;

// Base point X,Y and base order, words LSW-first (matches Java int[]).
static const uint32_t BASE_X[WORDS] = {
    0xE8343E36u, 0xD4994637u, 0xA0991168u,
    0x86A2D57Eu, 0xF0EBA162u, 0x00000003u,
};
static const uint32_t BASE_Y[WORDS] = {
    0x797324F1u, 0xB11C5C0Cu, 0xA2CDD545u,
    0x71A0094Fu, 0xD51FBC6Cu, 0x00000000u,
};
static const uint32_t BASE_ORDER[WORDS] = {
    0xA4234C33u, 0x77E70C12u, 0x000292FEu,
    0x00000000u, 0x00000000u, 0x00000004u,
};

// ---- bitvec helpers ------------------------------------------------------

static inline void bv_zero(uint32_t *v) { std::memset(v, 0, WORDS * 4); }
static inline void bv_copy(uint32_t *d, const uint32_t *s) { std::memcpy(d, s, WORDS * 4); }
static inline void bv_swap(uint32_t *a, uint32_t *b) {
    uint32_t t;
    for (int i = 0; i < WORDS; i++) { t = a[i]; a[i] = b[i]; b[i] = t; }
}
static inline bool bv_is_zero(const uint32_t *v) {
    for (int i = 0; i < WORDS; i++) if (v[i]) return false;
    return true;
}
static inline bool bv_is_one(const uint32_t *v) {
    if (v[0] != 1) return false;
    for (int i = 1; i < WORDS; i++) if (v[i]) return false;
    return true;
}
static inline bool bv_equal(const uint32_t *a, const uint32_t *b) {
    for (int i = 0; i < WORDS; i++) if (a[i] != b[i]) return false;
    return true;
}
static inline int bv_degree(const uint32_t *v) {
    for (int i = WORDS - 1; i >= 0; i--) {
        if (v[i]) {
            uint32_t w = v[i];
            int d = 0;
            while (w) { w >>= 1; d++; }
            return i * 32 + d;
        }
    }
    return 0;
}
static inline int bv_get_bit(const uint32_t *v, int pos) {
    return (v[pos >> 5] >> (pos & 31)) & 1u;
}
static inline void bv_xor(uint32_t *d, const uint32_t *s) {
    for (int i = 0; i < WORDS; i++) d[i] ^= s[i];
}
static inline void bv_lshift1(uint32_t *v) {
    for (int i = WORDS - 1; i > 0; i--)
        v[i] = (v[i] << 1) | (v[i - 1] >> 31);
    v[0] <<= 1;
}
static void bv_lshift(uint32_t *v, int n) {
    while (n >= 32) {
        for (int i = WORDS - 1; i > 0; i--) v[i] = v[i - 1];
        v[0] = 0;
        n -= 32;
    }
    while (n-- > 0) bv_lshift1(v);
}

// ---- GF(2^163) arithmetic ------------------------------------------------

static void gf_reduce_once(uint32_t *tmp) {
    // If bit 163 set, xor POLY (bit163 + 0xC9 low).
    if ((tmp[5] >> 3) & 1u) {
        tmp[5] ^= POLY_W5;    // clears bit 163
        tmp[0] ^= POLY_LOW;
    }
}

static void gf_mul(const uint32_t *x, const uint32_t *y, uint32_t *out) {
    uint32_t tmp[WORDS];
    uint32_t z[WORDS];
    bv_copy(tmp, x);
    if (y[0] & 1u) bv_copy(z, x); else bv_zero(z);
    for (int i = 1; i < CURVE_DEGREE; i++) {
        bv_lshift1(tmp);
        gf_reduce_once(tmp);
        if (bv_get_bit(y, i)) bv_xor(z, tmp);
    }
    bv_copy(out, z);
}

static void gf_inv(const uint32_t *x, uint32_t *out) {
    uint32_t u[WORDS], v[WORDS], g[WORDS], z[WORDS];
    bv_copy(u, x);
    // v = POLY
    bv_zero(v);
    v[0] = POLY_LOW;
    v[5] = POLY_W5;  // bit 163
    bv_zero(g);
    bv_zero(z); z[0] = 1;

    while (!bv_is_one(u)) {
        int i = bv_degree(u) - bv_degree(v);
        if (i < 0) {
            bv_swap(u, v);
            bv_swap(g, z);
            i = -i;
        }
        uint32_t vs[WORDS], gs[WORDS];
        bv_copy(vs, v); bv_lshift(vs, i);
        bv_copy(gs, g); bv_lshift(gs, i);
        bv_xor(u, vs);
        bv_xor(z, gs);
    }
    bv_copy(out, z);
}

// ---- Point operations ----------------------------------------------------

static bool pt_is_zero(const uint32_t *x, const uint32_t *y) {
    return bv_is_zero(x) && bv_is_zero(y);
}

static void pt_double(uint32_t *x, uint32_t *y) {
    if (bv_is_zero(x)) { bv_zero(y); return; }
    uint32_t l[WORDS], inv[WORDS], t[WORDS], nx[WORDS], ny[WORDS];
    gf_inv(x, inv);
    gf_mul(inv, y, l);
    bv_xor(l, x);                 // l = x + y/x
    gf_mul(x, x, ny);              // new_y = x^2
    gf_mul(l, l, nx);              // new_x = l^2
    l[0] ^= 1u;                    // l += 1
    bv_xor(nx, l);                 // new_x += (l+1)
    gf_mul(l, nx, t);
    bv_xor(ny, t);                 // new_y += (l+1) * new_x
    bv_copy(x, nx);
    bv_copy(y, ny);
}

static void pt_add(uint32_t *x1, uint32_t *y1,
                   const uint32_t *x2, const uint32_t *y2) {
    if (pt_is_zero(x2, y2)) return;
    if (pt_is_zero(x1, y1)) { bv_copy(x1, x2); bv_copy(y1, y2); return; }
    if (bv_equal(x1, x2)) {
        if (bv_equal(y1, y2)) { pt_double(x1, y1); return; }
        bv_zero(x1); bv_zero(y1); return;
    }
    uint32_t a[WORDS], b[WORDS], c[WORDS], d[WORDS], inv[WORDS], t[WORDS];
    bv_copy(a, y1); bv_xor(a, y2);  // a = y1+y2
    bv_copy(b, x1); bv_xor(b, x2);  // b = x1+x2
    gf_inv(b, inv);
    gf_mul(inv, a, c);               // c = a/b
    gf_mul(c, c, d);                 // d = c^2
    bv_xor(d, c);
    bv_xor(d, b);
    d[0] ^= 1u;                      // d = c^2 + c + b + 1
    uint32_t nx[WORDS];
    bv_copy(nx, x1); bv_xor(nx, d);  // nx = x1 + d
    gf_mul(nx, c, t);
    bv_xor(t, d);
    bv_xor(y1, t);                   // y1 += nx*c + d
    bv_copy(x1, d);                  // x1 = d
}

static void pt_mul(uint32_t *x, uint32_t *y, const uint32_t *exp) {
    uint32_t tx[WORDS], ty[WORDS], bx[WORDS], by[WORDS];
    bv_zero(tx); bv_zero(ty);
    bv_copy(bx, x); bv_copy(by, y);
    int nbits = bv_degree(exp);
    for (int i = nbits - 1; i >= 0; i--) {
        pt_double(tx, ty);
        if (bv_get_bit(exp, i)) pt_add(tx, ty, bx, by);
    }
    bv_copy(x, tx);
    bv_copy(y, ty);
}

static bool pt_on_curve(const uint32_t *x, const uint32_t *y) {
    if (pt_is_zero(x, y)) return false;
    uint32_t a[WORDS], b[WORDS], t[WORDS];
    gf_mul(x, x, a);
    gf_mul(a, x, b);
    bv_xor(a, b);
    // COEFF_B = 0x00000002_0A601907_B8C953CA_1481EB10_512F7874_4A3205FD
    uint32_t coeff_b[WORDS] = {
        0x4A3205FDu, 0x512F7874u, 0x1481EB10u,
        0xB8C953CAu, 0x0A601907u, 0x00000002u,
    };
    bv_xor(a, coeff_b);
    gf_mul(y, y, b);
    bv_xor(a, b);
    gf_mul(x, y, t);
    return bv_equal(a, t);
}

// ---- Public API ----------------------------------------------------------

static void bytes_to_bv(const uint8_t *b, int nbytes, uint32_t *v) {
    bv_zero(v);
    for (int i = 0; i < nbytes; i++)
        v[i / 4] |= ((uint32_t) b[i]) << ((i % 4) * 8);
}

static void bv_to_bytes(const uint32_t *v, uint8_t *b, int nbytes) {
    for (int i = 0; i < nbytes; i++)
        b[i] = (v[i / 4] >> ((i % 4) * 8)) & 0xFF;
}

static void sanitize_private(uint32_t *priv) {
    // Clear bits >= 162 (bit_length(BASE_ORDER)-1 = 162).
    // 162 = word 5 bit 2. Mask word 5 to low 2 bits, clear higher words.
    priv[5] &= 0x03u;
    // (upper 5-word already <163, no higher words exist in 6-word storage)
}

bool ecdh_generate_keypair(uint8_t priv_out[PRV_KEY_SIZE],
                           uint8_t pub_out[PUB_KEY_SIZE]) {
    for (int attempt = 0; attempt < 16; attempt++) {
        esp_fill_random(priv_out, PRV_KEY_SIZE);
        uint32_t priv[WORDS];
        bytes_to_bv(priv_out, PRV_KEY_SIZE, priv);
        if (bv_degree(priv) < CURVE_DEGREE / 2) continue;
        sanitize_private(priv);
        uint32_t px[WORDS], py[WORDS];
        bv_copy(px, BASE_X);
        bv_copy(py, BASE_Y);
        pt_mul(px, py, priv);
        bv_to_bytes(px, pub_out, FIELD_BYTES);
        bv_to_bytes(py, pub_out + FIELD_BYTES, FIELD_BYTES);
        // write back sanitized priv
        bv_to_bytes(priv, priv_out, PRV_KEY_SIZE);
        return true;
    }
    return false;
}

bool ecdh_generate_shared(const uint8_t priv_in[PRV_KEY_SIZE],
                          const uint8_t remote_pub[PUB_KEY_SIZE],
                          uint8_t shared_out[PUB_KEY_SIZE]) {
    uint32_t priv[WORDS], rx[WORDS], ry[WORDS];
    bytes_to_bv(priv_in, PRV_KEY_SIZE, priv);
    sanitize_private(priv);
    bytes_to_bv(remote_pub, FIELD_BYTES, rx);
    bytes_to_bv(remote_pub + FIELD_BYTES, FIELD_BYTES, ry);
    if (pt_is_zero(rx, ry) || !pt_on_curve(rx, ry)) return false;
    pt_mul(rx, ry, priv);
    bv_to_bytes(rx, shared_out, FIELD_BYTES);
    bv_to_bytes(ry, shared_out + FIELD_BYTES, FIELD_BYTES);
    return true;
}

}  // namespace zepp_helio
}  // namespace esphome
