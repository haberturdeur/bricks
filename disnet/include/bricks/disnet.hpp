#pragma once

#include "bricks/disnet/utils.hpp"
#include "bricks/exceptions.hpp"

#include <chrono>
#include <cstring>
#include <esp_random.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include <esp_netif.h>
#include <esp_mac.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <set>
#include <future>
#include <span>
#include <compare>
#include <optional>
#include <vector>

namespace bricks::disnet {

struct MacAddress {
    std::uint8_t _data[6];

    std::uint8_t* data() { return _data; }
    const std::uint8_t* data() const { return _data; }

    std::uint8_t* begin() { return _data; }
    std::uint8_t* end()   { return _data + 6; }

    const std::uint8_t* begin() const { return _data; }
    const std::uint8_t* end()   const { return _data + 6; }

    const std::uint8_t* cbegin() const { return _data; }
    const std::uint8_t* cend()   const { return _data + 6; }

    static MacAddress broadcast() {
        MacAddress addr;
        for (auto& c : addr) c = 0xFF;
        return addr;
    }

    static MacAddress my_address_sta() {
        MacAddress addr;
        esp_read_mac(addr.data(), ESP_MAC_WIFI_STA);
        return addr;
    }

    bool operator==(const MacAddress& o) const {
        return std::memcmp(_data, o._data, 6) == 0;
    }

    std::strong_ordering operator<=>(const MacAddress& o) const {
        int cmp = std::memcmp(_data, o._data, 6);
        if (cmp < 0) return std::strong_ordering::less;
        if (cmp > 0) return std::strong_ordering::greater;
        return std::strong_ordering::equal;
    }

    uint8_t& operator[](std::size_t idx) { return _data[idx]; }
    const uint8_t& operator[](std::size_t idx) const { return _data[idx]; }
};

namespace message {

enum class Type : std::uint8_t {
    Raw = 0,

    Reliable,
    ReliableAck,

    Segmented,
    SegmentedAnnounce,
    SegmentedAck,
    SegmentedNack,

    Heartbeat,
};

struct [[gnu::packed]] Id {
    MacAddress source;
    uint32_t seq;

    bool operator==(const Id& o) const {
        return o.seq == seq && o.source == source;
    }
    bool operator!=(const Id& o) const { return !(*this == o); }
    bool operator<(const Id& o) const {
        if (seq != o.seq) return seq < o.seq;
        if (source != o.source) return source < o.source;
        return false;
    }
};

struct [[gnu::packed]] Header {
    Id id;
    Type type;
    std::uint8_t ttl;
    std::uint8_t channel;
    std::uint8_t target_count = 0;
    MacAddress targets[];

    bool operator==(const Header& o) const = default;

    std::size_t size() const {
        return sizeof(Header) + target_count * 6;
    }

    bool is_valid() const {
        return size() <= ESP_NOW_MAX_DATA_LEN_V2;
    }

    std::size_t max_payload_size() const {
        const auto s = size();
        return s <= ESP_NOW_MAX_DATA_LEN_V2 ? (ESP_NOW_MAX_DATA_LEN_V2 - s) : 0;
    }
};

} // namespace message

using Callback  = std::function<void(const MacAddress&, std::span<const std::uint8_t>)>;
using Predicate = std::function<bool(const message::Header&)>;
using AckFuture = std::future<std::tuple<>>; // Empty future
using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

bool default_input_filter(const message::Header& header);
bool default_processing_filter(const message::Header& header);
bool default_forwarding_filter(const message::Header& header);

void init();

bool is_initialized();

void shutdown();

void activate_channel(std::uint8_t channel);

bool is_channel_active(std::uint8_t channel);

void register_handler(std::uint8_t channel, Callback cb);

void set_input_filter(Predicate predicate);
void set_processing_filter(Predicate predicate);
void set_forwarding_filter(Predicate predicate);

bool process_one(std::chrono::milliseconds time_to_wait = {});

void send_raw(std::uint8_t channel,
              std::uint8_t ttl,
              const std::set<MacAddress>& targets,
              std::span<const std::uint8_t> payload);

static inline void broadcast_raw(std::uint8_t channel,
                                 std::uint8_t ttl,
                                 std::span<const std::uint8_t> payload) {
    send_raw(channel, ttl, {}, payload);
}

AckFuture send_reliable(std::uint8_t channel,
                        std::uint8_t ttl,
                        const std::set<MacAddress>& targets,
                        std::span<const std::uint8_t> payload);

AckFuture send_segmented(std::uint8_t channel,
                         std::uint8_t ttl,
                         const std::set<MacAddress>& targets,
                         std::span<const std::uint8_t> payload);

void send_heartbeat(std::uint8_t channel, std::uint8_t ttl);

void ensure_heartbeat(std::uint8_t channel, std::uint8_t ttl, TimePoint cutoff);

static inline void ensure_heartbeat(std::uint8_t channel, std::uint8_t ttl, std::chrono::milliseconds cutoff) {
    ensure_heartbeat(channel, ttl, Clock::now() - cutoff);
}

TimePoint last_heartbeat(std::uint8_t channel, const MacAddress& address);

std::vector<std::pair<MacAddress, TimePoint>> neighbours(std::uint8_t channel, std::optional<TimePoint> cutoff = std::nullopt);

inline std::uint8_t g_default_ttl = 15;

class Channel {
private:
    const std::uint8_t _channel;
    std::uint8_t _default_ttl;

public:
    Channel(std::uint8_t channel)
        : _channel(channel), _default_ttl(g_default_ttl) {
    }

    Channel(std::uint8_t channel, std::uint8_t default_ttl)
        : _channel(channel), _default_ttl(default_ttl) {
        g_default_ttl = default_ttl;
    }

    void on(Callback&& cb) {
        register_handler(_channel, std::forward<Callback>(cb));
    }

    void send_raw(const std::set<MacAddress>& targets, std::span<const std::uint8_t> payload, std::uint8_t ttl = g_default_ttl) {
        bricks::disnet::send_raw(_channel, ttl, targets, payload);
    }

    void broadcast_raw(std::span<const std::uint8_t> payload, std::uint8_t ttl = g_default_ttl) {
        bricks::disnet::send_raw(_channel, ttl, {}, payload);
    }

    AckFuture send_reliable(const std::set<MacAddress>& targets, std::span<const std::uint8_t> payload, std::uint8_t ttl = g_default_ttl) {
        return bricks::disnet::send_reliable(_channel, ttl, targets, payload);
    }

    AckFuture send_segmented(const std::set<MacAddress>& targets, std::span<const std::uint8_t> payload, std::uint8_t ttl = g_default_ttl) {
        return bricks::disnet::send_segmented(_channel, ttl, targets, payload);
    }

    void send_heartbeat(std::uint8_t ttl = g_default_ttl) {
        bricks::disnet::send_heartbeat(_channel, ttl);
    }

    void ensure_heartbeat(TimePoint cutoff, std::uint8_t ttl = g_default_ttl) {
        bricks::disnet::ensure_heartbeat(_channel, ttl, cutoff);
    }

    void ensure_heartbeat(std::chrono::milliseconds cutoff, std::uint8_t ttl = g_default_ttl) {
        bricks::disnet::ensure_heartbeat(_channel, ttl, cutoff);
    }

    TimePoint last_heartbeat(const MacAddress& address) {
        return bricks::disnet::last_heartbeat(_channel, address);
    }

    std::vector<std::pair<MacAddress, TimePoint>> neighbours(std::optional<TimePoint> cutoff = std::nullopt) {
        return bricks::disnet::neighbours(_channel, cutoff); 
    }
};

} // namespace bricks::disnet
