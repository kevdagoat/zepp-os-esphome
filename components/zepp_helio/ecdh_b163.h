#pragma once
#include <cstdint>

namespace esphome {
namespace zepp_helio {

// 6 * uint32_t = 192 bits, enough for GF(2^163).
// Word 0 = LSW (little-endian matching Gadgetbridge ECDH_B163.java).
constexpr int BITVEC_WORDS = 6;
using bitvec_t = uint32_t[BITVEC_WORDS];

constexpr int PRV_KEY_SIZE = 24;
constexpr int PUB_KEY_SIZE = 48;
constexpr int FIELD_BYTES = 24;

// Generate random 24-byte priv + derive 48-byte (x||y) pub. Returns false
// on repeated sanitize failure.
bool ecdh_generate_keypair(uint8_t priv[PRV_KEY_SIZE], uint8_t pub[PUB_KEY_SIZE]);

// Derive 48-byte shared secret from priv (24) + remote_pub (48).
bool ecdh_generate_shared(const uint8_t priv[PRV_KEY_SIZE],
                          const uint8_t remote_pub[PUB_KEY_SIZE],
                          uint8_t shared[PUB_KEY_SIZE]);

}  // namespace zepp_helio
}  // namespace esphome
