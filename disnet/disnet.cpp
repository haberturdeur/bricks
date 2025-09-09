#include "include/bricks/disnet.hpp"
#include <cstdlib>
#include <memory>
;
#include "bricks/disnet.hpp"

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

#include "bricks/exceptions.hpp"

#include <any>
#include <atomic>
#include <cassert>
#include <chrono>
#include <compare>
#include <cstdint>
#include <cstring>
#include <future>>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>
#include <mutex>

static const char* g_tag = "bricks/disnet";

namespace bricks::disnet {

using message::Header;
using message::Id;
using message::Type;

enum class InitState { NotInitialized, Initializing, Initialized };

using AckPromise = std::promise<std::tuple<>>;

struct AckCookie {
    TimePoint timeout;
    AckPromise promise;
};

struct State {
    const MacAddress my_address = MacAddress::my_address_sta();

    std::atomic<InitState> init_state = InitState::NotInitialized;

    std::mutex active_channels_mutex;
    std::vector<bool> active_channels = std::vector<bool>(static_cast<std::vector<bool>::size_type>(256));
    std::uint8_t active_kiddy_count = 0;

    std::atomic<bool> custom_filters_enabled = false;
    std::mutex filter_mutex;
    Predicate input_filter;      // true -> keep
    Predicate processing_filter; // true -> process
    Predicate forwarding_filter; // true -> forward

    std::mutex channel_handlers_mutex;
    std::map<std::uint8_t, Callback> channel_handlers;

    std::atomic<std::uint8_t> initial_ttl = 15;

    utils::DeduplicationTable<Id> dedupe;
    std::atomic<std::uint32_t> msg_seq = esp_random();

    QueueHandle_t packet_queue = nullptr;

    std::mutex heartbeats_mutex;
    std::map<std::pair<std::uint8_t, MacAddress>, TimePoint> heartbeats;
    TimePoint last_message;

    std::mutex ack_promises_mutex;
    std::map<Id, AckCookie> ack_promises;
};

struct QueueItem {
    std::size_t size;
    MacAddress source;
    std::uint16_t channel;
    uint8_t payload[];
};

namespace {

inline std::size_t header_size_bytes(const Header& h) {
    return sizeof(Header) + static_cast<std::size_t>(h.target_count) * 6u;
}

inline bool targets_contains(const Header& h, const MacAddress& addr) {
    const auto* t = reinterpret_cast<const MacAddress*>(h.targets);
    for (std::uint8_t i = 0; i < h.target_count; ++i) {
        if (t[i] == addr) return true;
    }
    return false;
}

inline std::vector<MacAddress> targets_vector(const std::set<MacAddress>& targets) {
    return std::vector<MacAddress>(targets.begin(), targets.end());
}

static State g_state{};

inline bool is_kiddy_device_locked() {
    return g_state.active_kiddy_count > 0;
}

void send_buffer(std::span<const std::uint8_t> data) {
    static MacAddress bcast = MacAddress::broadcast();
    CHECK_IDF_ERROR(esp_now_send(bcast.data(), data.data(), static_cast<int>(data.size())));
}

Id build_and_send(std::uint8_t channel,
                    std::uint8_t ttl,
                    Type type,
                    std::span<const MacAddress> targets,
                    std::span<const std::uint8_t> payload) {

    Header header;
    header.id.source    = g_state.my_address;
    header.id.seq       = g_state.msg_seq++;
    header.type         = type;
    header.ttl          = ttl;
    header.channel      = channel;
    header.target_count = static_cast<std::uint8_t>(std::min<std::size_t>(targets.size(), UINT8_MAX));

    const std::size_t hdr_bytes = sizeof(Header) + static_cast<std::size_t>(header.target_count) * 6u;
    const std::size_t total     = hdr_bytes + payload.size();
    if (total > ESP_NOW_MAX_DATA_LEN_V2) {
        throw exceptions::Exception(std::runtime_error("disnet: packet too large for ESP-NOW"));
    }

    std::vector<std::uint8_t> buf(total);
    std::memcpy(buf.data(), &header, sizeof(Header));
    if (header.target_count) {
        std::memcpy(buf.data() + sizeof(Header), targets.data(), header.target_count * 6u);
    }

    if (!payload.empty()) {
        std::memcpy(buf.data() + hdr_bytes, payload.data(), payload.size());
    }

    std::scoped_lock l(g_state.heartbeats_mutex);
    g_state.last_message = Clock::now();

    send_buffer(buf);

    return header.id;
}

void forward_packet(std::span<std::uint8_t> packet) {
    if (packet.size() < sizeof(Header))
        return;

    auto* hdr = reinterpret_cast<Header*>(packet.data());
    if (hdr->ttl == 0)
        return;

    hdr->ttl--;
    send_buffer(packet);
    hdr->ttl++;
}

void dispatch(const MacAddress& source, std::uint8_t channel, std::span<const std::uint8_t> payload) {
    std::scoped_lock l(g_state.channel_handlers_mutex);
    auto it = g_state.channel_handlers.find(channel);
    if (it != g_state.channel_handlers.end() && it->second) {
        it->second(source, payload);
    }
}

void enqueue_packet(MacAddress source, std::uint8_t channel, std::span<const std::uint8_t> payload) {
    QueueItem* item = static_cast<QueueItem*>(std::malloc(sizeof(QueueItem) + payload.size()));
    item->source = source;
    item->channel = channel;
    item->size = payload.size();
    std::memcpy(&item->payload, payload.data(), payload.size());

    if (xQueueSend(g_state.packet_queue, &item, 0) != pdPASS) {
        free(item);
    }
}

void handle_ack(std::span<const std::uint8_t> payload_span) {
    const Id* acked = reinterpret_cast<const Id*>(payload_span.data());

    std::scoped_lock l(g_state.ack_promises_mutex);

    auto it = g_state.ack_promises.find(*acked);
    if (it != g_state.ack_promises.end()) {
        try {
            it->second.promise.set_value({});
        } catch (...) {
        }
        g_state.ack_promises.erase(it);
    } else {
        ESP_LOGD(g_tag, "ACK for unknown Id (maybe timed out or already handled)");
    }
}

static void send_reliable_ack(const Header& hdr) {
    const uint8_t* id_bytes = reinterpret_cast<const uint8_t*>(&hdr.id);
    std::span<const uint8_t> ack_payload(id_bytes, sizeof(Id));

    MacAddress target = hdr.id.source;
    std::span<const MacAddress> targets(&target, 1);

    build_and_send(hdr.channel, g_state.initial_ttl, Type::ReliableAck, targets, ack_payload);
}

void handle_incoming(const esp_now_recv_info_t* info, const std::uint8_t* data, int len) {
    if (!info || !data || len <= 0) {
        ESP_LOGW(g_tag, "Incorrect message received. info: %p, data: %p, len: %d", info, data, len);
        return;
    }

    MacAddress source;
    std::memcpy(source._data, info->src_addr, 6);

    ESP_LOGD(g_tag, "Packet from: %x:%x:%x:%x:%x:%x", source[0], source[1], source[2], source[3], source[4], source[5]);
    
    std::span<const std::uint8_t> packet_ro(data, static_cast<std::size_t>(len));
    if (packet_ro.size() < sizeof(Header)) {
        ESP_LOGW(g_tag, "Incorrect message");
        
        return;
    }

    const auto* hdr = reinterpret_cast<const Header*>(packet_ro.data());
    const std::size_t hdr_bytes = sizeof(Header) + static_cast<std::size_t>(hdr->target_count) * 6u;
    if (hdr_bytes > packet_ro.size()) {
        ESP_LOGW(g_tag, "Incorrect message");
        return;
    }

    if (g_state.custom_filters_enabled) {
        std::scoped_lock l(g_state.filter_mutex);

        const bool keep_input =
            g_state.input_filter
                ? g_state.input_filter(*hdr)
                : default_input_filter(*hdr);
        if (!keep_input)
            return;
    } else {
        if (!default_input_filter(*hdr)) {
            ESP_LOGD(g_tag, "input filter rejects");
            return;
        }
    }

    if (g_state.dedupe.check_seen_and_mark(hdr->id)) {
        ESP_LOGD(g_tag, "Message is duplicate");
        return;
    }

    if (g_state.custom_filters_enabled) {
        std::scoped_lock l(g_state.filter_mutex);

        bool allow_by_device_policy = false;
        {
            std::scoped_lock l(g_state.active_channels_mutex);
            const bool kiddy = is_kiddy_device_locked();
            allow_by_device_policy = kiddy ? true : g_state.active_channels[hdr->channel];
        }

        const bool allow_by_filter =
            g_state.forwarding_filter
                ? g_state.forwarding_filter(*hdr)
                : default_forwarding_filter(*hdr);

        if (hdr->ttl > 0 && allow_by_device_policy && allow_by_filter) {
            auto* mut = const_cast<std::uint8_t*>(packet_ro.data());
            std::span<std::uint8_t> packet_rw(mut, packet_ro.size());
            forward_packet(packet_rw);
        }

        const bool allow_processing =
            g_state.processing_filter
                ? g_state.processing_filter(*hdr)
                : default_processing_filter(*hdr);

        if (!allow_processing)
            return;

    } else {
        bool allow_by_device_policy = false;
        {
            std::scoped_lock l(g_state.active_channels_mutex);
            const bool kiddy = (g_state.active_kiddy_count > 0);
            allow_by_device_policy = kiddy ? true : g_state.active_channels[hdr->channel];
        }

        const bool allow_by_filter = default_forwarding_filter(*hdr);

        if (hdr->ttl > 0 && allow_by_device_policy && allow_by_filter) {
            auto* mut = const_cast<std::uint8_t*>(packet_ro.data());
            std::span<std::uint8_t> packet_rw(mut, packet_ro.size());
            forward_packet(packet_rw);
        }

        if (!default_processing_filter(*hdr)) {
            ESP_LOGD(g_tag, "processing filter rejects");
            return;
        }

    }

    {
        std::scoped_lock l(g_state.heartbeats_mutex);
        g_state.heartbeats.emplace(std::pair<std::uint8_t, MacAddress>{ hdr->channel, hdr->id.source }, Clock::now());
    }

    switch (hdr->type) {
        case Type::Raw:
            enqueue_packet(hdr->id.source, hdr->channel, packet_ro.subspan(header_size_bytes(*hdr)));
            break;

        case Type::Reliable:
            send_reliable_ack(*hdr);
            enqueue_packet(hdr->id.source, hdr->channel, packet_ro.subspan(header_size_bytes(*hdr)));
            break;

        case Type::ReliableAck:
            handle_ack(packet_ro.subspan(header_size_bytes(*hdr)));
            break;

        case Type::Segmented:
            break;

        case Type::SegmentedNack:
            break;

        case Type::Heartbeat:
            break;
    }

}

} // namespace

bool default_input_filter(const message::Header& header) {
    return header.id.source != g_state.my_address;
}

bool default_processing_filter(const message::Header& header) {
    // Broadcast
    if (header.target_count == 0)
        return true;

    return targets_contains(header, g_state.my_address);
}

bool default_forwarding_filter(const message::Header& header) {
    const bool for_me = (header.target_count != 0) && targets_contains(header, g_state.my_address);
    return (!for_me) && (header.ttl > 0);
}

void init() {
    InitState expected = InitState::NotInitialized;
    if (!g_state.init_state.compare_exchange_strong(expected, InitState::Initializing)) {
        throw exceptions::Exception(std::runtime_error("disnet already initialized"));
    }

    g_state.msg_seq.store(esp_random(), std::memory_order_relaxed);

    g_state.packet_queue = xQueueCreate(32, sizeof(QueueItem*));
    if (!g_state.packet_queue) {
        g_state.init_state.store(InitState::NotInitialized, std::memory_order_release);
        throw exceptions::Exception(std::runtime_error("disnet: failed to create inbound packet queue"));
    }

    CHECK_IDF_ERROR(esp_now_init());
    CHECK_IDF_ERROR(esp_now_register_recv_cb(handle_incoming));

    esp_now_peer_info_t peer_info = {
        .peer_addr = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
        .lmk = {0},
        .channel = 0,
        .ifidx   = WIFI_IF_STA,
        .encrypt = false,
        .priv = nullptr
    };

    CHECK_IDF_ERROR(esp_now_add_peer(&peer_info));
    {
        std::scoped_lock l(g_state.active_channels_mutex);
        g_state.initial_ttl.store(15, std::memory_order_relaxed);
        g_state.active_channels.assign(256, false);
        g_state.active_kiddy_count = 0;
    }

    {
        std::scoped_lock l(g_state.heartbeats_mutex);
        g_state.heartbeats.clear();
    }

    g_state.init_state.store(InitState::Initialized, std::memory_order_release);

}

bool is_initialized() {
    return g_state.init_state.load(std::memory_order_acquire) == InitState::Initialized;
}

void shutdown() {
    InitState expected = InitState::Initialized;
    if (!g_state.init_state.compare_exchange_strong(expected, InitState::Initializing)) {
        return;

    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wterminate"

    CHECK_IDF_ERROR(esp_now_unregister_recv_cb());
    CHECK_IDF_ERROR(esp_now_deinit());

    if (g_state.packet_queue) {
        QueueItem* pkt = nullptr;
        while (xQueueReceive(g_state.packet_queue, &pkt, 0) == pdPASS) {
            std::free(pkt);
        }
        vQueueDelete(g_state.packet_queue);
        g_state.packet_queue = nullptr;
    }

#pragma GCC diagnostic pop

    {
        std::scoped_lock l(g_state.channel_handlers_mutex);
        g_state.channel_handlers.clear();
    }
    {
        std::scoped_lock l(g_state.heartbeats_mutex);
        g_state.heartbeats.clear();
    }
    {
        std::scoped_lock l(g_state.active_channels_mutex);
        g_state.active_channels.assign(256, false);
        g_state.active_kiddy_count = 0;
    }

    g_state.init_state.store(InitState::NotInitialized, std::memory_order_release);
}

void activate_channel(std::uint8_t channel) {
    std::scoped_lock l(g_state.active_channels_mutex);
    std::vector<bool>::reference slot = g_state.active_channels[channel];
    if (!slot) {
        slot = true;
        if (channel < 128) {
            ++g_state.active_kiddy_count;
        }
    }
}

bool is_channel_active(std::uint8_t channel) {
    std::scoped_lock l(g_state.active_channels_mutex);
    return g_state.active_channels[channel];
}

void register_handler(std::uint8_t channel, Callback cb) {
    std::scoped_lock l(g_state.channel_handlers_mutex);
    g_state.channel_handlers[channel] = std::move(cb);
}

static inline void recompute_custom_filters_flag_unlocked() {
    const bool enabled =
        static_cast<bool>(g_state.input_filter) ||
        static_cast<bool>(g_state.processing_filter) ||
        static_cast<bool>(g_state.forwarding_filter);
    g_state.custom_filters_enabled.store(enabled, std::memory_order_relaxed);
}

void set_input_filter(Predicate predicate) {
    std::scoped_lock l(g_state.filter_mutex);
    g_state.input_filter = std::move(predicate);
    recompute_custom_filters_flag_unlocked();
}

void set_processing_filter(Predicate predicate) {
    std::scoped_lock l(g_state.filter_mutex);
    g_state.processing_filter = std::move(predicate);
    recompute_custom_filters_flag_unlocked();
}

void set_forwarding_filter(Predicate predicate) {
    std::scoped_lock l(g_state.filter_mutex);
    g_state.forwarding_filter = std::move(predicate);
    recompute_custom_filters_flag_unlocked();
}

bool process_one(std::chrono::milliseconds time_to_wait) {
    if (!g_state.packet_queue) return false;

    QueueItem* item = nullptr;
    if (xQueueReceive(g_state.packet_queue, &item, pdMS_TO_TICKS(time_to_wait.count())) != pdPASS) {
        return false;
    }

    dispatch(item->source, item->channel, std::span<std::uint8_t>(item->payload, item->size));

    std::free(item);
    return true;
}

void send_raw(std::uint8_t channel,
              std::uint8_t ttl,
              const std::set<MacAddress>& targets,
              std::span<const std::uint8_t> payload) {
    if (!is_channel_active(channel)) {
        ESP_LOGW(g_tag, "send_raw: Channel not active: %x", channel);
        return;
    }

    const auto tvec = targets_vector(targets);
    build_and_send(channel, ttl, Type::Raw, tvec, payload);
}

AckFuture send_reliable(std::uint8_t channel,
                        std::uint8_t ttl,
                        const std::set<MacAddress>& targets,
                        std::span<const std::uint8_t> payload) {
    if (!is_channel_active(channel)) {
        ESP_LOGW(g_tag, "send_reliable: Channel not active: %x", channel);
        return {};
    }

    const auto tvec = targets_vector(targets);
    Id id = build_and_send(channel, ttl, Type::Reliable, tvec, payload);

    std::scoped_lock l(g_state.ack_promises_mutex);
    auto [it, inserted] = g_state.ack_promises.emplace(id, AckCookie{ Clock::now(), {} });

    return it->second.promise.get_future();
}

AckFuture send_segmented(std::uint8_t, std::uint8_t, const std::set<MacAddress>&, std::span<const std::uint8_t>) {
    std::promise<std::tuple<>> p;
    p.set_exception(std::make_exception_ptr(std::runtime_error("disnet: Segmented API not implemented")));
    return p.get_future();
}

void send_heartbeat(std::uint8_t channel, std::uint8_t ttl) {
    if (!is_channel_active(channel))
        return;

    build_and_send(channel, ttl, Type::Heartbeat, /*targets*/{}, /*payload*/{});
    std::scoped_lock l(g_state.heartbeats_mutex);
}

void ensure_heartbeat(std::uint8_t channel, std::uint8_t ttl, TimePoint cutoff) {
    const auto key = std::make_pair(channel, g_state.my_address);
    bool need = false;
    {
        std::scoped_lock l(g_state.heartbeats_mutex);
        need = g_state.last_message < cutoff;
    }
    if (need)
        send_heartbeat(channel, ttl);
}

TimePoint last_heartbeat(std::uint8_t channel, const MacAddress& address) {
    const auto key = std::make_pair(channel, address);
    std::scoped_lock l(g_state.heartbeats_mutex);
    auto it = g_state.heartbeats.find(key);
    if (it == g_state.heartbeats.end()) return TimePoint{};
    return it->second;
}

std::vector<std::pair<MacAddress, TimePoint>> neighbours(std::uint8_t channel, std::optional<TimePoint> cutoff) {
    std::vector<std::pair<MacAddress, TimePoint>> out;
    std::scoped_lock l(g_state.heartbeats_mutex);
    for (const auto& [key, ts] : g_state.heartbeats) {
        const auto& [ch, mac] = key;
        if (ch != channel) continue;
        if (cutoff.has_value() && ts < *cutoff) continue;
        out.emplace_back(mac, ts);
    }
    return out;
}

} // namespace bricks::disnet

