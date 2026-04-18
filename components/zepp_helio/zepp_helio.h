#pragma once

#include "esphome/core/component.h"
#include "esphome/components/ble_client/ble_client.h"
#include "esphome/components/sensor/sensor.h"
#include "esphome/components/binary_sensor/binary_sensor.h"
#include "esphome/components/text_sensor/text_sensor.h"
#include "esphome/components/time/real_time_clock.h"
#include "esphome/core/preferences.h"
#include "esphome/core/automation.h"
#include <string>
#include <vector>
#include <array>
#include <map>

namespace esphome {
namespace zepp_helio {

// Huami/Zepp chunked-2021 chars
static const uint16_t CHAR_CHUNKED_WRITE_HANDLE_UUID = 0x0016;
static const uint16_t CHAR_CHUNKED_READ_HANDLE_UUID  = 0x0017;
// Legacy activity fetch chars
static const uint16_t CHAR_ACT_CONTROL_UUID = 0x0004;
static const uint16_t CHAR_ACT_DATA_UUID    = 0x0005;

// Raw `kind` byte in 8-byte Huami extended activity records.
// Source: HuamiExtendedSampleProvider.java.
enum HuamiExtKind : uint8_t {
  HEK_UNSET            = 0xFF,  // int8 -1 / nothing recorded
  HEK_OUTDOOR_RUNNING  = 64,    // 0x40
  HEK_NOT_WORN         = 115,   // 0x73
  HEK_CHARGING         = 118,   // 0x76
  HEK_SLEEP_LIGHT      = 120,   // 0x78
  HEK_SLEEP_DEEP       = 121,   // TYPE_SLEEP + 1
  HEK_SLEEP_REM        = 122,   // TYPE_SLEEP + 2
  HEK_SLEEP_AWAKE      = 123,   // TYPE_SLEEP + 3
};

inline bool huami_kind_is_worn(uint8_t k) {
  return k != HEK_NOT_WORN && k != HEK_CHARGING && k != HEK_UNSET;
}

inline bool huami_kind_is_sleep(uint8_t k) {
  return k == HEK_SLEEP_LIGHT || k == HEK_SLEEP_DEEP ||
         k == HEK_SLEEP_REM   || k == HEK_SLEEP_AWAKE;
}

inline const char *huami_kind_to_string(uint8_t k) {
  switch (k) {
    case HEK_UNSET:           return "unset";
    case HEK_OUTDOOR_RUNNING: return "running";
    case HEK_NOT_WORN:        return "not_worn";
    case HEK_CHARGING:        return "charging";
    case HEK_SLEEP_LIGHT:     return "sleep_light";
    case HEK_SLEEP_DEEP:      return "sleep_deep";
    case HEK_SLEEP_REM:       return "sleep_rem";
    case HEK_SLEEP_AWAKE:     return "sleep_awake";
    default:                  return "awake";  // worn + no sleep flag
  }
}

inline const char *huami_kind_to_sleep_stage(uint8_t k) {
  switch (k) {
    case HEK_SLEEP_LIGHT: return "light";
    case HEK_SLEEP_DEEP:  return "deep";
    case HEK_SLEEP_REM:   return "rem";
    case HEK_SLEEP_AWAKE: return "awake";
    default:              return "none";  // awake-worn or off-wrist
  }
}

class ZeppHelio;

class StatisticReadyTrigger
    : public Trigger<std::string, std::string, float, float, float, uint32_t> {
  friend class ZeppHelio;
 public:
  explicit StatisticReadyTrigger(ZeppHelio *parent);
};

enum class State : uint8_t {
  IDLE,
  CONNECTING,
  AUTH_PUBKEY_SENT,
  AUTH_SESSION_SENT,
  FETCH_WAIT_START_REPLY,
  FETCH_WAIT_DATA,
};

class ZeppHelio : public Component, public ble_client::BLEClientNode {
 public:
  void setup() override;
  void loop() override;
  void dump_config() override;
  float get_setup_priority() const override { return setup_priority::AFTER_BLUETOOTH; }

  void gattc_event_handler(esp_gattc_cb_event_t event,
                           esp_gatt_if_t gattc_if,
                           esp_ble_gattc_cb_param_t *param) override;

  // Runs a self-consistency ECDH test; logs result. Called from setup().
  bool run_ecdh_self_test();

  void set_auth_key(const std::vector<uint8_t> &k) {
    for (size_t i = 0; i < 16 && i < k.size(); i++) auth_key_[i] = k[i];
  }
  void set_time(time::RealTimeClock *t) { time_ = t; }
  void set_use_zeppos_control(bool v) { use_zeppos_control_ = v; }
  void set_max_lookback(uint32_t seconds) { max_lookback_s_ = seconds; }
  void set_first_run_lookback(uint32_t seconds) { first_run_lookback_s_ = seconds; }

  // Register an on_statistic_ready trigger (called once per declared handler).
  void add_statistic_ready_trigger(
      Trigger<std::string, std::string, float, float, float, uint32_t> *t) {
    stat_triggers_.push_back(t);
  }
  void set_temperature_sensor(sensor::Sensor *s) { temp_sensor_ = s; }
  void set_heart_rate_sensor(sensor::Sensor *s) { hr_sensor_ = s; }
  void set_resting_hr_sensor(sensor::Sensor *s) { resting_hr_sensor_ = s; }
  void set_max_hr_sensor(sensor::Sensor *s) { max_hr_sensor_ = s; }
  void set_steps_sensor(sensor::Sensor *s) { steps_sensor_ = s; }
  void set_stress_sensor(sensor::Sensor *s) { stress_sensor_ = s; }
  void set_spo2_sensor(sensor::Sensor *s) { spo2_sensor_ = s; }
  void set_resp_rate_sensor(sensor::Sensor *s) { resp_rate_sensor_ = s; }
  void set_hrv_sensor(sensor::Sensor *s) { hrv_sensor_ = s; }
  void set_count_sensor(sensor::Sensor *s) { count_sensor_ = s; }
  void set_battery_level_sensor(sensor::Sensor *s) { battery_sensor_ = s; }
  void set_worn_sensor(binary_sensor::BinarySensor *s) { worn_sensor_ = s; }
  void set_charging_sensor(binary_sensor::BinarySensor *s) { charging_sensor_ = s; }
  void set_sleep_stage_sensor(text_sensor::TextSensor *s) { sleep_stage_sensor_ = s; }
  void set_activity_kind_sensor(text_sensor::TextSensor *s) { activity_kind_sensor_ = s; }

  // Called from YAML interval to kick a fetch cycle.
  void trigger_fetch();

 protected:
  void start_connect_();
  void on_connected_();
  void send_pubkey_();
  void handle_chunked_read_(const uint8_t *data, uint16_t len);
  void handle_auth_reply_(const uint8_t *payload, int len);
  void request_battery_();
  void handle_battery_reply_(const uint8_t *payload, int len);

  // Historical backfill (option 2): bucket raw records into 5-min
  // windows, emit one trigger per bucket.
  static constexpr uint32_t BUCKET_SECONDS = 300;  // 5 min

  struct Bucket {
    time_t start_ts;
    uint32_t count;
    double sum;
    double min_v;
    double max_v;
  };

  // Per-type bucket accumulator used during parse_buffer_for_type_.
  // Key: bucket start ts (seconds since epoch, aligned to BUCKET_SECONDS).
  std::map<time_t, Bucket> active_buckets_;

  void bucket_add_(time_t ts, double v);
  void flush_buckets_for_type_(uint8_t huami_code, size_t type_idx);
  void format_iso8601_utc_(time_t ts, std::string &out);
  const char *huami_type_short_name_(uint8_t huami_code);
  void load_last_import_ts_();
  void save_last_import_ts_(size_t idx);
  void send_session_key_();
  void begin_legacy_fetch_();
  void on_control_notify_(const uint8_t *data, uint16_t len);
  void on_data_notify_(const uint8_t *data, uint16_t len);
  void send_start_date_();
  void send_fetch_data_();
  void send_ack_();
  void write_activity_control_(const uint8_t *cmd, size_t len);
  void start_next_type_();
  void parse_buffer_for_type_(uint8_t type, const std::vector<uint8_t> &buf,
                              time_t round_start);
  void publish_latest_();
  void finish_and_disconnect_(bool ok);

  // Chunked framing
  void encode_and_write_(uint16_t endpoint, const uint8_t *data,
                         size_t len, bool encrypt);

  // State
  State state_{State::IDLE};
  time::RealTimeClock *time_{nullptr};
  sensor::Sensor *temp_sensor_{nullptr};
  sensor::Sensor *hr_sensor_{nullptr};
  sensor::Sensor *resting_hr_sensor_{nullptr};
  sensor::Sensor *max_hr_sensor_{nullptr};
  sensor::Sensor *steps_sensor_{nullptr};
  sensor::Sensor *stress_sensor_{nullptr};
  sensor::Sensor *spo2_sensor_{nullptr};
  sensor::Sensor *resp_rate_sensor_{nullptr};
  sensor::Sensor *hrv_sensor_{nullptr};
  sensor::Sensor *count_sensor_{nullptr};
  sensor::Sensor *battery_sensor_{nullptr};
  binary_sensor::BinarySensor *worn_sensor_{nullptr};
  binary_sensor::BinarySensor *charging_sensor_{nullptr};
  text_sensor::TextSensor *sleep_stage_sensor_{nullptr};
  text_sensor::TextSensor *activity_kind_sensor_{nullptr};

  // Latest-value cache (published after fetch cycle completes)
  struct LatestValues {
    bool has_temp{false};        float temp{0};
    bool has_hr{false};          int hr{0};
    bool has_resting_hr{false};  int resting_hr{0};
    bool has_max_hr{false};      int max_hr{0};
    bool has_steps{false};       int steps{0};
    bool has_stress{false};      int stress{0};
    bool has_spo2{false};        int spo2{0};
    bool has_resp{false};        int resp{0};
    bool has_hrv{false};         int hrv{0};
    bool has_worn{false};        bool worn{false};
    bool has_kind{false};        uint8_t kind{HEK_UNSET};
    bool has_battery{false};     int battery_pct{0};
    bool has_charging{false};    bool charging{false};
    size_t total_samples{0};
  } latest_;

  uint8_t auth_key_[16]{};

  // Session
  uint8_t session_key_[16]{};
  bool have_session_{false};
  uint32_t encrypted_seq_{0};
  uint8_t write_handle_counter_{0};
  uint16_t mtu_{23};

  // Auth handshake
  uint8_t priv_key_[24]{};
  uint8_t pub_key_[48]{};
  uint8_t remote_random_[16]{};

  // Handles (looked up after service discovery)
  uint16_t h_chunked_write_{0};
  uint16_t h_chunked_read_{0};
  uint16_t h_act_control_{0};
  uint16_t h_act_data_{0};

  // Notify subscription tracking. Target count is set at SEARCH_CMPL
  // based on control_path: zeppos = 2 (chunked_read + act_data),
  // legacy = 3 (+ act_control).
  uint8_t notify_registered_count_{0};
  uint8_t notify_target_count_{2};

  // Control transport toggle (YAML `control_path`). true = Zepp OS
  // chunked-2021 endpoint 0x004B (encrypted). false = legacy char 0x04
  // (unencrypted). Data always comes on char 0x05.
  bool use_zeppos_control_{true};

  // ECDH self-test result (set in setup(), gates fetch_trigger)
  bool ecdh_ok_{false};

  // Chunked reassembly
  std::vector<uint8_t> chunked_buf_;
  uint16_t chunked_type_{0};
  uint32_t chunked_len_{0};
  uint8_t chunked_handle_{0};
  bool chunked_encrypted_{false};

  // Fetch
  time_t fetch_since_{0};
  time_t fetch_round_start_{0};
  uint32_t expected_pkts_{0};
  int last_data_counter_{-1};
  std::vector<uint8_t> round_buf_;
  int round_num_{0};

  // Multi-type fetch queue (Huami data type codes).
  // Order matters only for determinism; any that the device refuses are
  // skipped (start_date status != 0x01) and we move on.
  //
  // All eight types verified on Helio Strap via the legacy backdoor
  // (control_path=legacy) using amazfit/zepp_all_legacy.py. Layouts
  // match Gadgetbridge's Fetch*Operation.java byte-for-byte:
  //   0x01 activity       8-byte extended sample on Helio
  //   0x13 stress_auto    1B/min, 0xFF = skip
  //   0x25 spo2_normal    1B header (v=2) + 65B records
  //   0x2E temperature    8B/min (unk16, temp16, unk32)
  //   0x38 sleep_resp     8B/record, embedded timestamp
  //   0x3A resting_hr     6B/record, sparse cadence
  //   0x3D max_hr         6B/record, usually empty window
  //   0x49 hrv            6B/record, ~30 min cadence
  std::vector<uint8_t> fetch_types_{
      0x2E,  // TEMPERATURE
      0x01,  // ACTIVITY
      0x13,  // STRESS_AUTO
      0x25,  // SPO2_NORMAL
      0x3A,  // RESTING_HR
      0x3D,  // MAX_HR
      0x38,  // SLEEP_RESPIRATORY_RATE
      0x49,  // HRV
  };
  size_t current_type_idx_{0};
  uint8_t current_type_{0};

  // Per-type "last seen" timestamps (seconds since epoch). Next fetch
  // uses max(last_seen+1, now - max_lookback) as since. Zero means
  // "first run — fall back to max_lookback". Kept in RAM only, so a
  // reboot re-fetches one max_lookback window.
  std::array<time_t, 8> last_seen_{};

  // Hard ceiling on how far back we go when last_seen is zero or stale.
  // Default 24 h — catches sparse types after boot; steady-state fetch
  // windows are driven by last_seen and land in seconds, not hours.
  time_t max_lookback_s_{24 * 3600};

  // Persisted per-type "last successfully emitted statistic" ts.
  // Loaded from NVS in setup(), saved after a type's bucket queue
  // fully drains through the triggers. Zero means "nothing ever
  // emitted" → first-run backfill uses first_run_lookback_s_.
  std::array<uint32_t, 8> last_import_ts_{};
  std::array<ESPPreferenceObject, 8> last_import_pref_{};

  // First-run backfill window, used when last_import_ts_[i] == 0.
  uint32_t first_run_lookback_s_{24 * 3600};

  // Statistic trigger state
  std::vector<Trigger<std::string, std::string, float, float, float, uint32_t> *> stat_triggers_;
  uint8_t pending_type_idx_mask_{0};  // bitmask of type indices flushed inline

  bool want_fetch_{false};

  // Activity watchdog. Every BLE event or outbound write bumps
  // last_activity_ms_; if nothing has happened for this long while we
  // aren't IDLE, force a disconnect + reset.
  uint32_t last_activity_ms_{0};
  static constexpr uint32_t INACTIVITY_TIMEOUT_MS = 30000;
};

}  // namespace zepp_helio
}  // namespace esphome
