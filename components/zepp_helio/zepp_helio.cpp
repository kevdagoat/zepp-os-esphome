// Zepp OS 2021+ auth + legacy temperature fetch for ESPHome.
// Port of amazfit/zepp_proto.py + zepp_temp_legacy.py.
//
// WARNING: this is a scaffold. Service/characteristic handle discovery
// uses short 16-bit UUIDs but Huami chars are 128-bit — you must match
// by the full UUID string in the gattc SEARCH_CMPL handler. On first
// boot, watch the logs to see which handles correspond to which chars
// and adjust the UUID matching below if needed.

#include "zepp_helio.h"
#include "ecdh_b163.h"
#include "esphome/core/log.h"
#include "esphome/core/application.h"
#include "esphome/core/hal.h"
#include "esphome/core/preferences.h"
#include "esphome/components/esp32_ble_tracker/esp32_ble_tracker.h"

#include <esp_bt_main.h>
#include <esp_gap_ble_api.h>
#include <esp_gatt_common_api.h>
#include <esp_gattc_api.h>
#include <cstdio>
#include <cstring>
#include <ctime>

namespace esphome {
namespace zepp_helio {

static const char *const TAG = "zepp_helio";

StatisticReadyTrigger::StatisticReadyTrigger(ZeppHelio *parent) {
  parent->add_statistic_ready_trigger(this);
}

// Full Huami UUIDs (byte order as printed; reversed to little-endian 128)
// 0000XXXX-0000-3512-2118-0009af100700
static const uint8_t HUAMI_BASE_SUFFIX[] = {
    0x00, 0x07, 0x10, 0xAF, 0x09, 0x00, 0x18, 0x21,
    0x12, 0x35, 0x00, 0x00,
};

static bool is_huami_uuid(const esp_bt_uuid_t &uuid, uint16_t short_id) {
  if (uuid.len != ESP_UUID_LEN_128) return false;
  const uint8_t *u = uuid.uuid.uuid128;
  if (std::memcmp(u, HUAMI_BASE_SUFFIX, 12) != 0) return false;
  uint16_t sid = (uint16_t) u[12] | ((uint16_t) u[13] << 8);
  return sid == short_id;
}

// ---- AES-128-ECB (tiny-AES-c, public domain, ECB-only) -------------------
// Replaces the mbedtls/hwcrypto dependency so this component stays fully
// self-contained under esp-idf where mbedtls_aes_* symbols aren't reliably
// pulled out of the mbedtls archive for external components.
// Source: https://github.com/kokke/tiny-AES-c (The Unlicense).

namespace {

constexpr int AES_Nb = 4;
constexpr int AES_Nk = 4;
constexpr int AES_Nr = 10;
constexpr int AES_KEYEXPSIZE = 176;

using state_t = uint8_t[4][4];

static const uint8_t AES_SBOX[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t AES_RSBOX[256] = {
  0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
  0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
  0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
  0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
  0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
  0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
  0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
  0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
  0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
  0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
  0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
  0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
  0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
  0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
  0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
  0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint8_t AES_RCON[11] = {
  0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

static void aes_key_expansion(uint8_t rk[AES_KEYEXPSIZE], const uint8_t key[16]) {
  uint8_t t[4];
  for (int i = 0; i < AES_Nk; ++i) {
    rk[i*4+0] = key[i*4+0];
    rk[i*4+1] = key[i*4+1];
    rk[i*4+2] = key[i*4+2];
    rk[i*4+3] = key[i*4+3];
  }
  for (int i = AES_Nk; i < AES_Nb * (AES_Nr + 1); ++i) {
    int k = (i - 1) * 4;
    t[0] = rk[k+0]; t[1] = rk[k+1]; t[2] = rk[k+2]; t[3] = rk[k+3];
    if (i % AES_Nk == 0) {
      uint8_t u = t[0];
      t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = u;
      t[0] = AES_SBOX[t[0]];
      t[1] = AES_SBOX[t[1]];
      t[2] = AES_SBOX[t[2]];
      t[3] = AES_SBOX[t[3]];
      t[0] ^= AES_RCON[i/AES_Nk];
    }
    int j = i * 4;
    int l = (i - AES_Nk) * 4;
    rk[j+0] = rk[l+0] ^ t[0];
    rk[j+1] = rk[l+1] ^ t[1];
    rk[j+2] = rk[l+2] ^ t[2];
    rk[j+3] = rk[l+3] ^ t[3];
  }
}

static inline uint8_t aes_xtime(uint8_t x) {
  return (uint8_t) ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static uint8_t aes_mul(uint8_t x, uint8_t y) {
  return (uint8_t) (
      ((y      & 1) *  x) ^
      ((y >> 1 & 1) *  aes_xtime(x)) ^
      ((y >> 2 & 1) *  aes_xtime(aes_xtime(x))) ^
      ((y >> 3 & 1) *  aes_xtime(aes_xtime(aes_xtime(x)))) ^
      ((y >> 4 & 1) *  aes_xtime(aes_xtime(aes_xtime(aes_xtime(x))))));
}

static void aes_add_round_key(uint8_t round, state_t *s, const uint8_t *rk) {
  for (int i = 0; i < 4; ++i)
    for (int j = 0; j < 4; ++j)
      (*s)[i][j] ^= rk[round * AES_Nb * 4 + i * AES_Nb + j];
}

static void aes_sub_bytes(state_t *s) {
  for (int i = 0; i < 4; ++i)
    for (int j = 0; j < 4; ++j)
      (*s)[j][i] = AES_SBOX[(*s)[j][i]];
}

static void aes_shift_rows(state_t *s) {
  uint8_t t;
  t = (*s)[0][1]; (*s)[0][1] = (*s)[1][1]; (*s)[1][1] = (*s)[2][1];
  (*s)[2][1] = (*s)[3][1]; (*s)[3][1] = t;
  t = (*s)[0][2]; (*s)[0][2] = (*s)[2][2]; (*s)[2][2] = t;
  t = (*s)[1][2]; (*s)[1][2] = (*s)[3][2]; (*s)[3][2] = t;
  t = (*s)[0][3]; (*s)[0][3] = (*s)[3][3]; (*s)[3][3] = (*s)[2][3];
  (*s)[2][3] = (*s)[1][3]; (*s)[1][3] = t;
}

static void aes_mix_columns(state_t *s) {
  uint8_t Tmp, Tm, t;
  for (int i = 0; i < 4; ++i) {
    t   = (*s)[i][0];
    Tmp = (*s)[i][0] ^ (*s)[i][1] ^ (*s)[i][2] ^ (*s)[i][3];
    Tm = (*s)[i][0] ^ (*s)[i][1]; Tm = aes_xtime(Tm); (*s)[i][0] ^= Tm ^ Tmp;
    Tm = (*s)[i][1] ^ (*s)[i][2]; Tm = aes_xtime(Tm); (*s)[i][1] ^= Tm ^ Tmp;
    Tm = (*s)[i][2] ^ (*s)[i][3]; Tm = aes_xtime(Tm); (*s)[i][2] ^= Tm ^ Tmp;
    Tm = (*s)[i][3] ^ t;          Tm = aes_xtime(Tm); (*s)[i][3] ^= Tm ^ Tmp;
  }
}

static void aes_inv_sub_bytes(state_t *s) {
  for (int i = 0; i < 4; ++i)
    for (int j = 0; j < 4; ++j)
      (*s)[j][i] = AES_RSBOX[(*s)[j][i]];
}

static void aes_inv_shift_rows(state_t *s) {
  uint8_t t;
  t = (*s)[3][1]; (*s)[3][1] = (*s)[2][1]; (*s)[2][1] = (*s)[1][1];
  (*s)[1][1] = (*s)[0][1]; (*s)[0][1] = t;
  t = (*s)[0][2]; (*s)[0][2] = (*s)[2][2]; (*s)[2][2] = t;
  t = (*s)[1][2]; (*s)[1][2] = (*s)[3][2]; (*s)[3][2] = t;
  t = (*s)[0][3]; (*s)[0][3] = (*s)[1][3]; (*s)[1][3] = (*s)[2][3];
  (*s)[2][3] = (*s)[3][3]; (*s)[3][3] = t;
}

static void aes_inv_mix_columns(state_t *s) {
  for (int i = 0; i < 4; ++i) {
    uint8_t a = (*s)[i][0];
    uint8_t b = (*s)[i][1];
    uint8_t c = (*s)[i][2];
    uint8_t d = (*s)[i][3];
    (*s)[i][0] = aes_mul(a,0x0e) ^ aes_mul(b,0x0b) ^ aes_mul(c,0x0d) ^ aes_mul(d,0x09);
    (*s)[i][1] = aes_mul(a,0x09) ^ aes_mul(b,0x0e) ^ aes_mul(c,0x0b) ^ aes_mul(d,0x0d);
    (*s)[i][2] = aes_mul(a,0x0d) ^ aes_mul(b,0x09) ^ aes_mul(c,0x0e) ^ aes_mul(d,0x0b);
    (*s)[i][3] = aes_mul(a,0x0b) ^ aes_mul(b,0x0d) ^ aes_mul(c,0x09) ^ aes_mul(d,0x0e);
  }
}

static void aes_cipher(state_t *s, const uint8_t *rk) {
  aes_add_round_key(0, s, rk);
  for (uint8_t r = 1; r < AES_Nr; ++r) {
    aes_sub_bytes(s);
    aes_shift_rows(s);
    aes_mix_columns(s);
    aes_add_round_key(r, s, rk);
  }
  aes_sub_bytes(s);
  aes_shift_rows(s);
  aes_add_round_key(AES_Nr, s, rk);
}

static void aes_inv_cipher(state_t *s, const uint8_t *rk) {
  aes_add_round_key(AES_Nr, s, rk);
  for (uint8_t r = AES_Nr - 1; r > 0; --r) {
    aes_inv_shift_rows(s);
    aes_inv_sub_bytes(s);
    aes_add_round_key(r, s, rk);
    aes_inv_mix_columns(s);
  }
  aes_inv_shift_rows(s);
  aes_inv_sub_bytes(s);
  aes_add_round_key(0, s, rk);
}

}  // anonymous namespace

static void aes_ecb_encrypt_block(const uint8_t key[16],
                                  const uint8_t *in, size_t nblocks,
                                  uint8_t *out) {
  uint8_t rk[AES_KEYEXPSIZE];
  aes_key_expansion(rk, key);
  for (size_t i = 0; i < nblocks; ++i) {
    std::memcpy(out + i * 16, in + i * 16, 16);
    aes_cipher(reinterpret_cast<state_t *>(out + i * 16), rk);
  }
}

static void aes_ecb_decrypt_block(const uint8_t key[16],
                                  const uint8_t *in, size_t nblocks,
                                  uint8_t *out) {
  uint8_t rk[AES_KEYEXPSIZE];
  aes_key_expansion(rk, key);
  for (size_t i = 0; i < nblocks; ++i) {
    std::memcpy(out + i * 16, in + i * 16, 16);
    aes_inv_cipher(reinterpret_cast<state_t *>(out + i * 16), rk);
  }
}

static void derive_message_key(const uint8_t session_key[16],
                               uint8_t handle, uint8_t out[16]) {
  for (int i = 0; i < 16; i++) out[i] = session_key[i] ^ handle;
}

// CRC32 IEEE (matches Python zlib.crc32)
static uint32_t crc32_ieee(const uint8_t *data, size_t len) {
  uint32_t crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (int k = 0; k < 8; k++) {
      uint32_t mask = -(int32_t)(crc & 1);
      crc = (crc >> 1) ^ (0xEDB88320u & mask);
    }
  }
  return ~crc;
}

// ---- Setup / config ------------------------------------------------------

void ZeppHelio::setup() {
  ESP_LOGI(TAG, "zepp_helio setup");
  load_last_import_ts_();
  // Request MTU 247 at link layer so chunked writes get fat chunks.
  esp_err_t st = esp_ble_gatt_set_local_mtu(247);
  if (st != ESP_OK) {
    ESP_LOGW(TAG, "esp_ble_gatt_set_local_mtu failed: %d", st);
  }
  // ECDH self-test (gap #2).
  ecdh_ok_ = run_ecdh_self_test();
  if (!ecdh_ok_) {
    ESP_LOGE(TAG, "ECDH self-test FAILED — fetches will be disabled");
  } else {
    ESP_LOGI(TAG, "ECDH self-test OK");
  }
}

bool ZeppHelio::run_ecdh_self_test() {
  uint8_t priv_a[24], pub_a[48];
  uint8_t priv_b[24], pub_b[48];
  uint8_t shared_ab[48], shared_ba[48];
  if (!ecdh_generate_keypair(priv_a, pub_a)) return false;
  if (!ecdh_generate_keypair(priv_b, pub_b)) return false;
  if (!ecdh_generate_shared(priv_a, pub_b, shared_ab)) return false;
  if (!ecdh_generate_shared(priv_b, pub_a, shared_ba)) return false;
  return std::memcmp(shared_ab, shared_ba, 48) == 0;
}

void ZeppHelio::dump_config() {
  ESP_LOGCONFIG(TAG, "Zepp Helio client");
  ESP_LOGCONFIG(TAG, "  Auth key set: %d", auth_key_[0] != 0);
}

void ZeppHelio::loop() {
  // Periodic state pump. BLE flow is event-driven via gattc cb; the
  // statistic pump runs independently so it drains even while a fetch
  // is in progress or between cycles.
  pump_pending_stats_();

  // Inactivity watchdog. Any BLE event or outbound write bumps
  // last_activity_ms_; if we're non-IDLE and nothing's moved in 30 s,
  // force a disconnect + reset so the next trigger can retry.
  if (state_ != State::IDLE) {
    uint32_t now_ms = millis();
    if (last_activity_ms_ == 0) last_activity_ms_ = now_ms;
    if (now_ms - last_activity_ms_ > INACTIVITY_TIMEOUT_MS) {
      ESP_LOGW(TAG, "watchdog: state=%d idle for %u ms, forcing reset",
               (int) state_, (unsigned) (now_ms - last_activity_ms_));
      last_activity_ms_ = 0;
      finish_and_disconnect_(false);
    }
  }

  if (want_fetch_ && state_ == State::IDLE) {
    want_fetch_ = false;
    start_connect_();
  }
}

void ZeppHelio::trigger_fetch() {
  if (state_ != State::IDLE) {
    ESP_LOGW(TAG, "fetch requested but state=%d", (int) state_);
    return;
  }
  if (!ecdh_ok_) {
    ESP_LOGW(TAG, "fetch skipped: ECDH self-test failed at boot");
    return;
  }
  // Gap #3: don't run a fetch before SNTP has synced — fetch_since_
  // would be garbage and the device would either reject or return
  // unbounded history.
  if (time_ == nullptr || !time_->now().is_valid()) {
    ESP_LOGW(TAG, "fetch skipped: clock not yet synced");
    return;
  }
  ESP_LOGI(TAG, "fetch triggered");
  want_fetch_ = true;
}

void ZeppHelio::start_connect_() {
  ESP_LOGI(TAG, "connecting to BLE client");
  state_ = State::CONNECTING;
  last_activity_ms_ = millis();
  this->parent()->set_enabled(true);
  this->parent()->connect();
}

// ---- GATT event handler --------------------------------------------------

void ZeppHelio::gattc_event_handler(esp_gattc_cb_event_t event,
                                    esp_gatt_if_t gattc_if,
                                    esp_ble_gattc_cb_param_t *param) {
  last_activity_ms_ = millis();
  switch (event) {
    case ESP_GATTC_OPEN_EVT:
      if (param->open.status == ESP_GATT_OK) {
        ESP_LOGI(TAG, "BLE open ok");
        // Request a bigger MTU post-connect. Device will reply with
        // ESP_GATTC_CFG_MTU_EVT carrying the negotiated value.
        esp_ble_gattc_send_mtu_req(gattc_if, param->open.conn_id);
      }
      break;

    case ESP_GATTC_CFG_MTU_EVT:
      if (param->cfg_mtu.status == ESP_GATT_OK) {
        mtu_ = param->cfg_mtu.mtu > 23 ? param->cfg_mtu.mtu : 23;
        ESP_LOGI(TAG, "MTU negotiated: %u", (unsigned) mtu_);
      } else {
        ESP_LOGW(TAG, "MTU negotiation failed, using 23");
        mtu_ = 23;
      }
      break;

    case ESP_GATTC_SEARCH_CMPL_EVT: {
      ESP_LOGI(TAG, "service discovery complete, resolving chars");
      notify_registered_count_ = 0;

      // Iterate ESPHome's own service cache rather than the raw esp-idf
      // GATT DB — recent ESPHome builds don't call esp_ble_gattc_search_
      // service, so esp_ble_gattc_get_service returns 0 entries.
      auto chunked_write_uuid = esp32_ble_tracker::ESPBTUUID::from_raw(
          "00000016-0000-3512-2118-0009af100700");
      auto chunked_read_uuid = esp32_ble_tracker::ESPBTUUID::from_raw(
          "00000017-0000-3512-2118-0009af100700");
      auto act_ctrl_uuid = esp32_ble_tracker::ESPBTUUID::from_raw(
          "00000004-0000-3512-2118-0009af100700");
      auto act_data_uuid = esp32_ble_tracker::ESPBTUUID::from_raw(
          "00000005-0000-3512-2118-0009af100700");

      h_chunked_write_ = 0;
      h_chunked_read_  = 0;
      h_act_control_   = 0;
      h_act_data_      = 0;

      auto &svc_list = this->parent()->services_;
      ESP_LOGI(TAG, "cached services: %u", (unsigned) svc_list.size());
      for (auto *svc : svc_list) {
        ESP_LOGI(TAG, "  svc %s  h=%u..%u",
                 svc->uuid.to_string().c_str(),
                 svc->start_handle, svc->end_handle);
        for (auto *chr : svc->characteristics) {
          ESP_LOGD(TAG, "    chr %s  h=%u props=0x%02X",
                   chr->uuid.to_string().c_str(),
                   chr->handle, chr->properties);
          if (chr->uuid == chunked_write_uuid) h_chunked_write_ = chr->handle;
          else if (chr->uuid == chunked_read_uuid) h_chunked_read_ = chr->handle;
          else if (chr->uuid == act_ctrl_uuid)  h_act_control_   = chr->handle;
          else if (chr->uuid == act_data_uuid)  h_act_data_      = chr->handle;
        }
      }

      bool missing = (h_chunked_write_ == 0 || h_chunked_read_ == 0 ||
                      h_act_data_ == 0 ||
                      (!use_zeppos_control_ && h_act_control_ == 0));
      if (missing) {
        ESP_LOGE(TAG, "missing char handle: cw=0x%04X cr=0x%04X ac=0x%04X ad=0x%04X",
                 h_chunked_write_, h_chunked_read_,
                 h_act_control_, h_act_data_);
        finish_and_disconnect_(false);
        return;
      }
      ESP_LOGI(TAG, "handles cw=0x%04X cr=0x%04X ac=0x%04X ad=0x%04X "
                    "(control_path=%s)",
               h_chunked_write_, h_chunked_read_, h_act_control_, h_act_data_,
               use_zeppos_control_ ? "zeppos" : "legacy");

      // Notify subs depend on control_path:
      //   zeppos: chunked_read + act_data           (target=2)
      //   legacy: chunked_read + act_data + act_ctl (target=3)
      auto remote = this->parent()->get_remote_bda();
      esp_ble_gattc_register_for_notify(gattc_if, remote, h_chunked_read_);
      esp_ble_gattc_register_for_notify(gattc_if, remote, h_act_data_);
      if (!use_zeppos_control_) {
        esp_ble_gattc_register_for_notify(gattc_if, remote, h_act_control_);
        notify_target_count_ = 3;
      } else {
        notify_target_count_ = 2;
      }
      break;
    }

    case ESP_GATTC_REG_FOR_NOTIFY_EVT: {
      if (param->reg_for_notify.status != ESP_GATT_OK) {
        ESP_LOGE(TAG, "register_for_notify failed on handle 0x%04X: %d",
                 param->reg_for_notify.handle,
                 param->reg_for_notify.status);
        finish_and_disconnect_(false);
        break;
      }
      notify_registered_count_++;
      ESP_LOGD(TAG, "notify registered %u/%u (handle 0x%04X)",
               notify_registered_count_, notify_target_count_,
               param->reg_for_notify.handle);
      if (notify_registered_count_ >= notify_target_count_) {
        on_connected_();
      }
      break;
    }

    case ESP_GATTC_NOTIFY_EVT: {
      uint16_t h = param->notify.handle;
      const uint8_t *v = param->notify.value;
      uint16_t len = param->notify.value_len;
      if (h == h_chunked_read_) {
        handle_chunked_read_(v, len);
      } else if (h == h_act_data_) {
        on_data_notify_(v, len);
      } else if (h == h_act_control_ && !use_zeppos_control_) {
        // Legacy path: control replies come directly on char 0x04.
        on_control_notify_(v, len);
      }
      break;
    }

    case ESP_GATTC_DISCONNECT_EVT:
      ESP_LOGI(TAG, "BLE disconnected");
      state_ = State::IDLE;
      have_session_ = false;
      notify_registered_count_ = 0;
      chunked_buf_.clear();
      chunked_handle_ = 0;
      break;

    default:
      break;
  }
}

void ZeppHelio::on_connected_() {
  ESP_LOGI(TAG, "starting auth handshake");
  if (!ecdh_generate_keypair(priv_key_, pub_key_)) {
    ESP_LOGE(TAG, "ECDH keygen failed");
    finish_and_disconnect_(false);
    return;
  }
  state_ = State::AUTH_PUBKEY_SENT;
  send_pubkey_();
}

// ---- Chunked framing -----------------------------------------------------

void ZeppHelio::encode_and_write_(uint16_t endpoint, const uint8_t *data,
                                  size_t len, bool encrypt) {
  uint8_t handle = ++write_handle_counter_;
  std::vector<uint8_t> payload;
  size_t length;

  if (encrypt) {
    if (!have_session_) {
      ESP_LOGE(TAG, "encrypt without session key");
      return;
    }
    length = len;
    size_t enc_len = length + 8;
    size_t overflow = enc_len % 16;
    if (overflow) enc_len += 16 - overflow;

    std::vector<uint8_t> pt(enc_len, 0);
    std::memcpy(pt.data(), data, length);
    uint32_t seq = encrypted_seq_++;
    std::memcpy(pt.data() + length, &seq, 4);
    uint32_t crc = crc32_ieee(pt.data(), length + 4);
    std::memcpy(pt.data() + length + 4, &crc, 4);

    uint8_t msg_key[16];
    derive_message_key(session_key_, handle, msg_key);
    payload.resize(enc_len);
    aes_ecb_encrypt_block(msg_key, pt.data(), enc_len / 16, payload.data());
  } else {
    length = len;
    payload.assign(data, data + len);
  }

  const int HEADER_FIRST = 11;
  const int HEADER_CONT = 5;

  size_t remaining = payload.size();
  size_t offset = 0;
  uint8_t count = 0;
  while (remaining > 0) {
    bool first = (count == 0);
    int hdr = first ? HEADER_FIRST : HEADER_CONT;
    int max_chunk = (mtu_ - 3) - hdr;
    if (max_chunk <= 0) max_chunk = 1;
    size_t take = remaining < (size_t) max_chunk ? remaining : (size_t) max_chunk;

    uint8_t flags = 0;
    if (first) flags |= 0x01;
    if (remaining <= (size_t) max_chunk) { flags |= 0x02; flags |= 0x04; }
    if (encrypt) flags |= 0x08;

    std::vector<uint8_t> buf(hdr + take);
    buf[0] = 0x03;
    buf[1] = flags;
    buf[2] = 0x00;
    buf[3] = handle;
    buf[4] = count;
    if (first) {
      uint32_t l32 = (uint32_t) length;
      std::memcpy(&buf[5], &l32, 4);
      uint16_t ep = endpoint;
      std::memcpy(&buf[9], &ep, 2);
    }
    std::memcpy(&buf[hdr], &payload[offset], take);

    // Write without response
    esp_ble_gattc_write_char(this->parent()->get_gattc_if(),
                             this->parent()->get_conn_id(),
                             h_chunked_write_,
                             buf.size(), buf.data(),
                             ESP_GATT_WRITE_TYPE_NO_RSP,
                             ESP_GATT_AUTH_REQ_NONE);

    offset += take;
    remaining -= take;
    count++;
  }
}

void ZeppHelio::handle_chunked_read_(const uint8_t *data, uint16_t len) {
  if (len < 5 || data[0] != 0x03) return;
  int i = 1;
  uint8_t flags = data[i++];
  bool encrypted = flags & 0x08;
  bool first = flags & 0x01;
  bool last = flags & 0x02;
  i++;  // ext flags zero
  uint8_t handle = data[i++];
  uint8_t count = data[i++];
  (void) count;

  if (chunked_handle_ != 0 && chunked_handle_ != handle) {
    chunked_buf_.clear();
  }

  if (first) {
    if (len < 11) {
      ESP_LOGW(TAG, "chunked first frame too short: len=%u", (unsigned) len);
      chunked_buf_.clear();
      chunked_handle_ = 0;
      return;
    }
    uint32_t full_len;
    std::memcpy(&full_len, &data[i], 4); i += 4;
    chunked_len_ = full_len;
    std::memcpy(&chunked_type_, &data[i], 2); i += 2;
    chunked_buf_.clear();
    chunked_handle_ = handle;
    chunked_encrypted_ = encrypted;
  }

  if (i > len) {
    ESP_LOGW(TAG, "chunked header past end of frame");
    chunked_buf_.clear();
    chunked_handle_ = 0;
    return;
  }
  chunked_buf_.insert(chunked_buf_.end(), &data[i], &data[len]);
  if (!last) return;

  std::vector<uint8_t> payload;
  if (chunked_encrypted_) {
    if (!have_session_) { chunked_buf_.clear(); chunked_handle_ = 0; return; }
    if (chunked_buf_.size() % 16 != 0 ||
        chunked_len_ > chunked_buf_.size()) {
      ESP_LOGW(TAG, "chunked enc frame malformed: buf=%u len=%u",
               (unsigned) chunked_buf_.size(), (unsigned) chunked_len_);
      chunked_buf_.clear();
      chunked_handle_ = 0;
      return;
    }
    uint8_t msg_key[16];
    derive_message_key(session_key_, chunked_handle_, msg_key);
    std::vector<uint8_t> pt(chunked_buf_.size());
    aes_ecb_decrypt_block(msg_key, chunked_buf_.data(),
                          chunked_buf_.size() / 16, pt.data());
    payload.assign(pt.begin(), pt.begin() + chunked_len_);
  } else {
    if (chunked_len_ > chunked_buf_.size()) {
      ESP_LOGW(TAG, "chunked plain frame short: buf=%u len=%u",
               (unsigned) chunked_buf_.size(), (unsigned) chunked_len_);
      chunked_buf_.clear();
      chunked_handle_ = 0;
      return;
    }
    payload.assign(chunked_buf_.begin(),
                   chunked_buf_.begin() + chunked_len_);
  }
  chunked_buf_.clear();
  chunked_handle_ = 0;

  // AUTH endpoint = 0x0082
  if (chunked_type_ == 0x0082) {
    handle_auth_reply_(payload.data(), payload.size());
  } else if (chunked_type_ == 0x004B) {
    // Zepp OS activity fetch control replies
    on_control_notify_(payload.data(), payload.size());
  } else if (chunked_type_ == 0x0029) {
    // Battery service reply
    handle_battery_reply_(payload.data(), payload.size());
  }
}

// ---- Auth ----------------------------------------------------------------

void ZeppHelio::send_pubkey_() {
  uint8_t cmd[1 + 3 + 48];
  cmd[0] = 0x04;  // CMD_PUB_KEY
  cmd[1] = 0x02;
  cmd[2] = 0x00;
  cmd[3] = 0x02;
  std::memcpy(&cmd[4], pub_key_, 48);
  encode_and_write_(0x0082, cmd, sizeof(cmd), false);
}

void ZeppHelio::handle_auth_reply_(const uint8_t *p, int len) {
  if (len < 3 || p[0] != 0x10) return;
  if (p[1] == 0x04) {
    // pub key reply: [0x10 0x04 0x01 rand(16) remote_pub(48)]
    if (p[2] != 0x01) { finish_and_disconnect_(false); return; }
    if (len < 67) {
      ESP_LOGE(TAG, "auth pub reply short: len=%d", len);
      finish_and_disconnect_(false);
      return;
    }
    std::memcpy(remote_random_, &p[3], 16);
    uint8_t remote_pub[48];
    std::memcpy(remote_pub, &p[19], 48);
    uint8_t shared[48];
    if (!ecdh_generate_shared(priv_key_, remote_pub, shared)) {
      finish_and_disconnect_(false); return;
    }
    std::memcpy(&encrypted_seq_, shared, 4);
    for (int i = 0; i < 16; i++)
      session_key_[i] = shared[i + 8] ^ auth_key_[i];
    have_session_ = true;
    send_session_key_();
  } else if (p[1] == 0x05) {
    if (p[2] == 0x25) { ESP_LOGE(TAG, "wrong auth key"); finish_and_disconnect_(false); return; }
    if (p[2] != 0x01) { finish_and_disconnect_(false); return; }
    ESP_LOGI(TAG, "auth success");
    // Fire-and-forget battery request on the chunked-2021 pipe; reply
    // lands in handle_battery_reply_ whenever it arrives. Does not
    // gate the legacy fetch state machine.
    request_battery_();
    begin_legacy_fetch_();
  }
}

void ZeppHelio::request_battery_() {
  // ZeppOsBatteryService: endpoint 0x0029, CMD_BATTERY_REQUEST = 0x03
  uint8_t cmd[1] = {0x03};
  encode_and_write_(0x0029, cmd, 1, true);
}

void ZeppHelio::handle_battery_reply_(const uint8_t *p, int len) {
  // HuamiBatteryInfo layout:
  //   p[0] = CMD_BATTERY_REPLY (0x04)
  //   p[1] = unknown first field
  //   p[2] = level percent
  //   p[3] = state (0 normal, 1 charging)
  //   p[4..10]  = current/last-known time
  //   p[11..18] = last charge time (year LE, mon, day, h, m, s, ...)
  //   p[20]     = last charge target percent
  if (len < 4 || p[0] != 0x04) {
    ESP_LOGW(TAG, "battery reply malformed (len=%d byte0=0x%02X)", len, len ? p[0] : 0);
    return;
  }
  latest_.battery_pct = p[2];
  latest_.has_battery = true;
  latest_.charging = (p[3] == 1);
  latest_.has_charging = true;
  ESP_LOGI(TAG, "battery %d%% %s", latest_.battery_pct,
           latest_.charging ? "charging" : "normal");
  // Publish immediately — fetch cycle may still be running, but the
  // battery reply is self-contained so no reason to wait.
  if (battery_sensor_) battery_sensor_->publish_state(latest_.battery_pct);
  if (charging_sensor_) charging_sensor_->publish_state(latest_.charging);
}

void ZeppHelio::send_session_key_() {
  uint8_t enc_r1[16], enc_r2[16];
  aes_ecb_encrypt_block(auth_key_, remote_random_, 1, enc_r1);
  aes_ecb_encrypt_block(session_key_, remote_random_, 1, enc_r2);
  uint8_t cmd[1 + 32];
  cmd[0] = 0x05;
  std::memcpy(&cmd[1], enc_r1, 16);
  std::memcpy(&cmd[17], enc_r2, 16);
  encode_and_write_(0x0082, cmd, sizeof(cmd), false);
  state_ = State::AUTH_SESSION_SENT;
}

// ---- Legacy temperature fetch --------------------------------------------

void ZeppHelio::begin_legacy_fetch_() {
  // Do NOT clear latest_ — stale cached values from prior cycles stay
  // published; only fields we actually see new data for this cycle get
  // overwritten. This is what keeps HR/temp/etc. sticky when the
  // device returns zero records for a type.
  latest_.total_samples = 0;
  current_type_idx_ = 0;
  start_next_type_();
}

void ZeppHelio::start_next_type_() {
  if (current_type_idx_ >= fetch_types_.size()) {
    publish_latest_();
    finish_and_disconnect_(true);
    return;
  }
  current_type_ = fetch_types_[current_type_idx_];
  time_t now = time_ ? time_->now().timestamp : ::time(nullptr);

  // Prefer NVS-persisted last_import_ts_ (survives reboots). Fall
  // back to in-RAM last_seen_ if nothing has been persisted yet.
  time_t prior = (time_t) last_import_ts_[current_type_idx_];
  if (prior == 0) prior = last_seen_[current_type_idx_];

  time_t floor_ts;
  if (prior == 0) {
    // First-ever run for this type → pull first_run_lookback window.
    floor_ts = now - (time_t) first_run_lookback_s_;
    ESP_LOGI(TAG, "type 0x%02X: first-run backfill window %u s",
             current_type_, (unsigned) first_run_lookback_s_);
  } else {
    // Steady state — capped at max_lookback as a safety net.
    floor_ts = now - (time_t) max_lookback_s_;
  }
  fetch_since_ = (prior > 0 && prior + 1 > floor_ts) ? (prior + 1) : floor_ts;

  round_num_ = 0;
  active_buckets_.clear();
  ESP_LOGI(TAG, "fetching type 0x%02X since %ld (prior=%ld)",
           current_type_, (long) fetch_since_, (long) prior);
  send_start_date_();
}

static void pack_time_bytes(time_t ts, uint8_t out[8]) {
  struct tm tmv;
  localtime_r(&ts, &tmv);
  uint16_t year = tmv.tm_year + 1900;
  out[0] = year & 0xFF;
  out[1] = year >> 8;
  out[2] = tmv.tm_mon + 1;
  out[3] = tmv.tm_mday;
  out[4] = tmv.tm_hour;
  out[5] = tmv.tm_min;
  out[6] = 0;
  // tz units of 15 min. newlib lacks tm_gmtoff; derive from ts - mktime(gmtime(ts)).
  struct tm gmv;
  gmtime_r(&ts, &gmv);
  gmv.tm_isdst = tmv.tm_isdst;
  long offset_sec = (long) (ts - mktime(&gmv));
  out[7] = (int8_t) (offset_sec / 60 / 15);
}

void ZeppHelio::send_start_date_() {
  fetch_round_start_ = fetch_since_;
  last_data_counter_ = -1;
  round_buf_.clear();
  round_num_++;

  uint8_t cmd[10];
  cmd[0] = 0x01;           // CMD_START_DATE
  cmd[1] = current_type_;  // active fetch type
  pack_time_bytes(fetch_since_, &cmd[2]);
  write_activity_control_(cmd, sizeof(cmd));
  state_ = State::FETCH_WAIT_START_REPLY;
}

void ZeppHelio::send_fetch_data_() {
  uint8_t cmd[1] = {0x02};
  write_activity_control_(cmd, 1);
  state_ = State::FETCH_WAIT_DATA;
}

void ZeppHelio::send_ack_() {
  uint8_t cmd[2] = {0x03, current_type_};
  write_activity_control_(cmd, 2);
}

void ZeppHelio::write_activity_control_(const uint8_t *cmd, size_t len) {
  if (use_zeppos_control_) {
    // Zepp OS: encrypted chunked-2021 endpoint 0x004B
    encode_and_write_(0x004B, cmd, len, true);
  } else {
    // Legacy: unencrypted raw write to char 0x0004
    esp_ble_gattc_write_char(this->parent()->get_gattc_if(),
                             this->parent()->get_conn_id(),
                             h_act_control_, len,
                             const_cast<uint8_t *>(cmd),
                             ESP_GATT_WRITE_TYPE_NO_RSP,
                             ESP_GATT_AUTH_REQ_NONE);
  }
}

void ZeppHelio::on_control_notify_(const uint8_t *d, uint16_t len) {
  if (len < 3) return;
  if (d[0] == 0x10 && d[1] == 0x01) {
    // START_DATE reply
    if (d[2] != 0x01) { finish_and_disconnect_(false); return; }
    if (len < 7) {
      ESP_LOGE(TAG, "start_date reply short: len=%u", (unsigned) len);
      finish_and_disconnect_(false);
      return;
    }
    uint32_t exp;
    std::memcpy(&exp, &d[3], 4);
    expected_pkts_ = exp;
    if (exp == 0) {
      ESP_LOGI(TAG, "type 0x%02X: no data for window", current_type_);
      send_ack_();
      current_type_idx_++;
      start_next_type_();
      return;
    }
    if (len < 13) {
      ESP_LOGE(TAG, "start_date reply missing date fields: len=%u",
               (unsigned) len);
      finish_and_disconnect_(false);
      return;
    }
    // Reparse actual_start for round timestamp
    uint16_t year;
    std::memcpy(&year, &d[7], 2);
    struct tm tmv{};
    tmv.tm_year = year - 1900;
    tmv.tm_mon = d[9] - 1;
    tmv.tm_mday = d[10];
    tmv.tm_hour = d[11];
    tmv.tm_min = d[12];
    tmv.tm_sec = len > 13 ? d[13] : 0;
    tmv.tm_isdst = -1;
    fetch_round_start_ = mktime(&tmv);
    send_fetch_data_();
  } else if (d[0] == 0x10 && d[1] == 0x02) {
    // FETCH_DATA reply — round complete
    if (d[2] != 0x01) { finish_and_disconnect_(false); return; }
    parse_buffer_for_type_(current_type_, round_buf_, fetch_round_start_);
    send_ack_();
    // Single round covers the 15-min window for all types we use.
    // Advance to next type.
    current_type_idx_++;
    start_next_type_();
  }
}

void ZeppHelio::on_data_notify_(const uint8_t *d, uint16_t len) {
  if (len == 0) return;
  uint8_t counter = d[0];
  if ((int) counter != ((last_data_counter_ + 1) & 0xFF)) {
    ESP_LOGW(TAG, "data counter gap got=%d exp=%d",
             counter, (last_data_counter_ + 1) & 0xFF);
  }
  last_data_counter_ = counter;
  round_buf_.insert(round_buf_.end(), d + 1, d + len);
}

static int16_t rd_i16(const uint8_t *p) { int16_t v; std::memcpy(&v, p, 2); return v; }
static uint32_t rd_u32(const uint8_t *p) { uint32_t v; std::memcpy(&v, p, 4); return v; }

void ZeppHelio::parse_buffer_for_type_(uint8_t type,
                                       const std::vector<uint8_t> &buf,
                                       time_t round_start) {
  const uint8_t *b = buf.data();
  size_t n = buf.size();
  size_t count = 0;
  time_t newest_ts = last_seen_[current_type_idx_];

  auto track_ts = [&](time_t t) {
    if (t > newest_ts) newest_ts = t;
  };

  // Bucket a single numeric sample into the active 5-min window map.
  // Only called for the "primary" value of each type (the one we
  // expose as an HA statistic). Activity gets bucketed on hr.
  auto bucket = [&](time_t ts, double v) {
    if (!stat_triggers_.empty()) bucket_add_(ts, v);
  };

  switch (type) {
    // Sentinel policy matches Gadgetbridge: only STRESS filters 0xFF.
    // All other types persist raw per upstream FetchXxxOperation.java.
    case 0x2E: {  // TEMPERATURE — 8 bytes: unk16, temp16, unk32
      for (size_t i = 0; i + 8 <= n; i += 8) {
        int16_t raw = rd_i16(&b[i + 2]);
        float temp_c = raw / 100.0f;
        latest_.temp = temp_c;
        latest_.has_temp = true;
        time_t ts = round_start + (time_t) count * 60;
        track_ts(ts);
        bucket(ts, temp_c);
        count++;
      }
      break;
    }
    case 0x01: {  // ACTIVITY — 4B basic or 8B extended sample.
      size_t record_idx = 0;
      // Helio streams 8B records (FetchActivityOperation.createExtendedSample).
      // Layout: kind, intensity, steps, hr, unk, sleep, deep_sleep, rem_sleep.
      // We handle both; detection: length % 8 == 0 → extended.
      const size_t rec = (n % 8 == 0) ? 8 : 4;
      for (size_t i = 0; i + rec <= n; i += rec) {
        uint8_t kind = b[i];
        uint8_t hr   = b[i + 3];
        uint8_t steps = b[i + 2];

        latest_.kind = kind;
        latest_.has_kind = true;
        latest_.worn = huami_kind_is_worn(kind);
        latest_.has_worn = true;

        // HR is only trustworthy when the band is on wrist. Gate cache
        // updates so an off-wrist 0xFF doesn't overwrite the last real HR.
        if (latest_.worn && hr != 0 && hr != 0xFF) {
          latest_.hr = hr;
          latest_.has_hr = true;
        }
        if (latest_.worn) {
          latest_.steps = steps;
          latest_.has_steps = true;
        }
        time_t ts = round_start + (time_t) record_idx * 60;
        track_ts(ts);
        // Bucket HR as the activity-type statistic (most chart-worthy).
        if (latest_.worn && hr != 0 && hr != 0xFF) {
          bucket(ts, (double) hr);
        }
        record_idx++;
        count++;
      }
      break;
    }
    case 0x13: {  // STRESS_AUTO — 1B, 0xFF = skip
      for (size_t i = 0; i < n; i++) {
        time_t ts = round_start + (time_t) i * 60;
        // Timestamp walks forward on every byte so last_seen advances
        // even if the whole window is skip sentinels.
        track_ts(ts);
        if (b[i] == 0xFF) continue;
        latest_.stress = b[i];
        latest_.has_stress = true;
        bucket(ts, (double) b[i]);
        count++;
      }
      break;
    }
    case 0x25: {  // SPO2_NORMAL — 1B hdr (v=2) + 65B recs (ts32 @ off 0)
      if (n < 1 || b[0] != 2) { ESP_LOGW(TAG, "spo2 ver mismatch"); break; }
      for (size_t i = 1; i + 65 <= n; i += 65) {
        time_t ts = (time_t) rd_u32(&b[i]);
        track_ts(ts);
        int v = (int) b[i + 4];
        latest_.spo2 = v;
        latest_.has_spo2 = true;
        bucket(ts, (double) v);
        count++;
      }
      break;
    }
    case 0x3A: {  // RESTING_HR — 6B: ts32, tz8, hr8
      for (size_t i = 0; i + 6 <= n; i += 6) {
        time_t ts = (time_t) rd_u32(&b[i]);
        track_ts(ts);
        latest_.resting_hr = b[i + 5];
        latest_.has_resting_hr = true;
        bucket(ts, (double) b[i + 5]);
        count++;
      }
      break;
    }
    case 0x3D: {  // MAX_HR — 6B: ts32, tz8, hr8
      for (size_t i = 0; i + 6 <= n; i += 6) {
        time_t ts = (time_t) rd_u32(&b[i]);
        track_ts(ts);
        latest_.max_hr = b[i + 5];
        latest_.has_max_hr = true;
        bucket(ts, (double) b[i + 5]);
        count++;
      }
      break;
    }
    case 0x38: {  // SLEEP_RESPIRATORY_RATE — 8B
      for (size_t i = 0; i + 8 <= n; i += 8) {
        time_t ts = (time_t) rd_u32(&b[i]);
        track_ts(ts);
        latest_.resp = b[i + 5];
        latest_.has_resp = true;
        bucket(ts, (double) b[i + 5]);
        count++;
      }
      break;
    }
    case 0x49: {  // HRV — 6B: ts32, unk8, hrv8
      for (size_t i = 0; i + 6 <= n; i += 6) {
        time_t ts = (time_t) rd_u32(&b[i]);
        track_ts(ts);
        latest_.hrv = b[i + 5];
        latest_.has_hrv = true;
        bucket(ts, (double) b[i + 5]);
        count++;
      }
      break;
    }
    default:
      ESP_LOGW(TAG, "no parser for type 0x%02X (%u bytes)",
               type, (unsigned) n);
      break;
  }
  (void) round_start;
  latest_.total_samples += count;
  last_seen_[current_type_idx_] = newest_ts;
  flush_buckets_for_type_(type, current_type_idx_);
  ESP_LOGI(TAG, "type 0x%02X: parsed %u samples, last_seen=%ld, pending=%u",
           type, (unsigned) count, (long) newest_ts,
           (unsigned) pending_stats_.size());
}

void ZeppHelio::publish_latest_() {
  if (temp_sensor_       && latest_.has_temp)       temp_sensor_->publish_state(latest_.temp);
  if (hr_sensor_         && latest_.has_hr)         hr_sensor_->publish_state(latest_.hr);
  if (resting_hr_sensor_ && latest_.has_resting_hr) resting_hr_sensor_->publish_state(latest_.resting_hr);
  if (max_hr_sensor_     && latest_.has_max_hr)     max_hr_sensor_->publish_state(latest_.max_hr);
  if (steps_sensor_      && latest_.has_steps)      steps_sensor_->publish_state(latest_.steps);
  if (stress_sensor_     && latest_.has_stress)     stress_sensor_->publish_state(latest_.stress);
  if (spo2_sensor_       && latest_.has_spo2)       spo2_sensor_->publish_state(latest_.spo2);
  if (resp_rate_sensor_  && latest_.has_resp)       resp_rate_sensor_->publish_state(latest_.resp);
  if (hrv_sensor_        && latest_.has_hrv)        hrv_sensor_->publish_state(latest_.hrv);
  if (count_sensor_)                                count_sensor_->publish_state(latest_.total_samples);
  if (battery_sensor_    && latest_.has_battery)    battery_sensor_->publish_state(latest_.battery_pct);
  if (charging_sensor_   && latest_.has_charging)   charging_sensor_->publish_state(latest_.charging);
  if (worn_sensor_       && latest_.has_worn)       worn_sensor_->publish_state(latest_.worn);
  if (sleep_stage_sensor_ && latest_.has_kind)
    sleep_stage_sensor_->publish_state(huami_kind_to_sleep_stage(latest_.kind));
  if (activity_kind_sensor_ && latest_.has_kind)
    activity_kind_sensor_->publish_state(huami_kind_to_string(latest_.kind));
}

void ZeppHelio::finish_and_disconnect_(bool ok) {
  ESP_LOGI(TAG, "fetch %s, total %u samples across types",
           ok ? "ok" : "FAIL", (unsigned) latest_.total_samples);
  state_ = State::IDLE;
  have_session_ = false;
  this->parent()->disconnect();
}

// ---- NVS persistence ----------------------------------------------------

void ZeppHelio::load_last_import_ts_() {
  for (size_t i = 0; i < last_import_ts_.size(); i++) {
    uint32_t hash = 0x7E990000u | (uint32_t) i;
    last_import_pref_[i] = global_preferences->make_preference<uint32_t>(hash);
    uint32_t v = 0;
    if (last_import_pref_[i].load(&v)) {
      last_import_ts_[i] = v;
      ESP_LOGI(TAG, "nvs load: type_idx=%u last_import_ts=%u",
               (unsigned) i, (unsigned) v);
    }
  }
}

void ZeppHelio::save_last_import_ts_(size_t idx) {
  if (idx >= last_import_ts_.size()) return;
  uint32_t v = last_import_ts_[idx];
  last_import_pref_[idx].save(&v);
  global_preferences->sync();
  ESP_LOGI(TAG, "nvs save: type_idx=%u last_import_ts=%u",
           (unsigned) idx, (unsigned) v);
}

// ---- Bucket helpers -----------------------------------------------------

void ZeppHelio::bucket_add_(time_t ts, double v) {
  time_t bucket_start = (ts / BUCKET_SECONDS) * BUCKET_SECONDS;
  auto it = active_buckets_.find(bucket_start);
  if (it == active_buckets_.end()) {
    active_buckets_[bucket_start] = Bucket{bucket_start, 1, v, v, v};
  } else {
    it->second.count++;
    it->second.sum += v;
    if (v < it->second.min_v) it->second.min_v = v;
    if (v > it->second.max_v) it->second.max_v = v;
  }
}

const char *ZeppHelio::huami_type_short_name_(uint8_t huami_code) {
  switch (huami_code) {
    case 0x01: return "heart_rate";
    case 0x13: return "stress";
    case 0x25: return "spo2";
    case 0x2E: return "temperature";
    case 0x38: return "respiratory_rate";
    case 0x3A: return "resting_heart_rate";
    case 0x3D: return "max_heart_rate";
    case 0x49: return "hrv";
    default:   return "unknown";
  }
}

void ZeppHelio::format_iso8601_utc_(time_t ts, std::string &out) {
  struct tm tmv;
  gmtime_r(&ts, &tmv);
  char buf[32];
  // HA recorder.import_statistics stats.start must be a 5-min-aligned
  // RFC3339 timestamp in UTC. "+00:00" tail is mandatory.
  snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:00+00:00",
           tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
           tmv.tm_hour, tmv.tm_min);
  out.assign(buf);
}

void ZeppHelio::flush_buckets_for_type_(uint8_t huami_code, size_t type_idx) {
  if (active_buckets_.empty() || stat_triggers_.empty()) {
    active_buckets_.clear();
    return;
  }
  const char *name = huami_type_short_name_(huami_code);
  for (auto &kv : active_buckets_) {
    const Bucket &b = kv.second;
    PendingStat s;
    s.type = name;
    format_iso8601_utc_(b.start_ts, s.start_iso);
    s.mean = (float) (b.sum / (double) b.count);
    s.min_v = (float) b.min_v;
    s.max_v = (float) b.max_v;
    s.count = b.count;
    s.type_idx = type_idx;
    pending_stats_.push_back(std::move(s));
  }
  active_buckets_.clear();
}

// ---- Statistic pump -----------------------------------------------------

void ZeppHelio::pump_pending_stats_() {
  if (stat_triggers_.empty()) {
    pending_stats_.clear();
    pending_stats_cursor_ = 0;
    return;
  }
  if (pending_stats_cursor_ >= pending_stats_.size()) {
    if (!pending_stats_.empty()) {
      // Queue just drained → commit every type_idx we touched to NVS.
      // We keep a simple set via an on-stack array.
      std::array<bool, 8> touched{};
      for (auto &p : pending_stats_) {
        if (p.type_idx < touched.size()) touched[p.type_idx] = true;
      }
      for (size_t i = 0; i < touched.size(); i++) {
        if (touched[i]) {
          last_import_ts_[i] = (uint32_t) last_seen_[i];
          save_last_import_ts_(i);
        }
      }
      pending_stats_.clear();
      pending_stats_cursor_ = 0;
    }
    return;
  }

  // Throttle: fire at most one bucket per 100 ms across all triggers.
  // Keeps HA's API queue from backing up during a 24 h first-run dump.
  uint32_t now_ms = millis();
  if (now_ms - last_pending_fire_ms_ < 100) return;
  last_pending_fire_ms_ = now_ms;

  PendingStat &s = pending_stats_[pending_stats_cursor_++];
  for (auto *t : stat_triggers_) {
    t->trigger(s.type, s.start_iso, s.mean, s.min_v, s.max_v, s.count);
  }
}

}  // namespace zepp_helio
}  // namespace esphome
