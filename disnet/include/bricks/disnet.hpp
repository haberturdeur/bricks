#pragma once

#include "bricks/disnet/utils.hpp"
#include "bricks/exceptions.hpp"

#include <chrono>
#include <cstring>
#include <esp_mac.h>
#include <esp_netif.h>
#include <esp_now.h>
#include <esp_random.h>
#include <esp_wifi.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include <atomic>
#include <array>
#include <compare>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <unordered_set>
#include <vector>

namespace bricks::disnet {

#ifndef BRICKS_DISNET_DIAGNOSTICS
#if defined(CONFIG_DISNET_ENABLE_DIAGNOSTICS)
#define BRICKS_DISNET_DIAGNOSTICS 1
#else
#define BRICKS_DISNET_DIAGNOSTICS 0
#endif
#endif

struct MacAddress {
    std::uint8_t _data[6];

    std::uint8_t* data() {
        return _data;
    }
    const std::uint8_t* data() const {
        return _data;
    }

    std::uint8_t* begin() {
        return _data;
    }
    std::uint8_t* end() {
        return _data + 6;
    }

    const std::uint8_t* begin() const {
        return _data;
    }
    const std::uint8_t* end() const {
        return _data + 6;
    }

    const std::uint8_t* cbegin() const {
        return _data;
    }
    const std::uint8_t* cend() const {
        return _data + 6;
    }

    static MacAddress broadcast() {
        MacAddress addr;
        for (auto& c : addr)
            c = 0xFF;
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
        if (cmp < 0)
            return std::strong_ordering::less;
        if (cmp > 0)
            return std::strong_ordering::greater;
        return std::strong_ordering::equal;
    }

    std::uint8_t& operator[](std::size_t idx) {
        return _data[idx];
    }
    const std::uint8_t& operator[](std::size_t idx) const {
        return _data[idx];
    }
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
    std::uint32_t seq;

    bool operator==(const Id& o) const {
        return o.seq == seq && o.source == source;
    }

    bool operator!=(const Id& o) const {
        return !(*this == o);
    }

    bool operator<(const Id& o) const {
        if (seq != o.seq)
            return seq < o.seq;
        if (source != o.source)
            return source < o.source;
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

using Callback = std::function<void(const MacAddress&, std::span<const std::uint8_t>)>;
using Predicate = std::function<bool(const message::Header&)>;
using AckFuture = std::future<std::tuple<>>;
using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

namespace detail {

struct Limits {
    // FIXME: Re-tune these defaults for constrained embedded RAM (session count and payload caps).
    static constexpr std::size_t max_segmented_rx_sessions = 4;
    static constexpr std::size_t max_segmented_tx_sessions = 4;
    static constexpr std::size_t max_segmented_equations_per_session = 128;
    static constexpr std::size_t max_segmented_seen_seeds_per_session = 512;
    static constexpr std::size_t max_segmented_payload_bytes = 16 * 1024;
    static constexpr std::uint16_t max_segmented_block_size = 512;
    static constexpr std::uint16_t max_segmented_block_count = 128;
};

enum class InitState { NotInitialized, Initializing, Initialized };
using AckPromise = std::promise<std::tuple<>>;

struct AckCookie {
    TimePoint timeout;
    AckPromise promise;
};

struct SessionId {
    std::uint8_t bytes[32];

    bool operator==(const SessionId& o) const {
        return std::memcmp(bytes, o.bytes, 32) == 0;
    }

    bool operator<(const SessionId& o) const {
        return std::memcmp(bytes, o.bytes, 32) < 0;
    }
};

struct ReceiverSessionKey {
    std::uint8_t channel;
    MacAddress sender;
    SessionId session;

    bool operator<(const ReceiverSessionKey& o) const {
        if (channel != o.channel)
            return channel < o.channel;
        if (!(sender == o.sender))
            return sender < o.sender;
        return session < o.session;
    }
};

struct ReceiverSession {
    mutable std::mutex mutex;
    SessionId session;
    std::uint8_t channel;
    MacAddress sender;
    std::uint32_t total_len = 0;
    std::uint16_t block_size = 0;
    std::uint16_t K = 0;

    std::vector<std::vector<std::uint8_t>> blocks;
    std::vector<bool> known;
    std::vector<bool> cached;
    std::vector<std::uint16_t> cache_order;

    struct Equation {
        std::vector<std::uint16_t> idx;
        std::vector<std::uint8_t> data;
    };
    std::vector<Equation> equations;

    std::set<std::uint32_t> seen_seeds;
    std::size_t innovative_count = 0;
    TimePoint last_progress = Clock::now();
};

struct SenderSessionKey {
    SessionId session;

    bool operator<(const SenderSessionKey& o) const {
        return session < o.session;
    }
};

struct SenderSession {
    SessionId session;
    std::uint8_t channel;
    std::uint8_t ttl;
    std::vector<MacAddress> targets;
    std::uint32_t total_len;
    std::uint16_t block_size;
    std::uint16_t K;
    std::vector<std::vector<std::uint8_t>> blocks;

    std::set<MacAddress> init_acked;
    std::set<MacAddress> finished;
    mutable std::mutex ack_mutex;
    std::atomic<bool> stop{false};
    TaskHandle_t task = nullptr;

    AckPromise promise;
};

struct InitSlice {
    std::atomic<InitState> state = InitState::NotInitialized;
};

struct ChannelSlice {
    mutable std::mutex active_mutex;
    std::vector<bool> active_channels = std::vector<bool>(256);
    std::uint8_t active_kiddy_count = 0;

    mutable std::mutex handlers_mutex;
    std::map<std::uint8_t, Callback> handlers;
};

struct FilterSlice {
    std::atomic<bool> custom_enabled = false;
    mutable std::mutex mutex;
    Predicate input;
    Predicate processing;
    Predicate forwarding;
};

struct RuntimeSlice {
    std::atomic<std::uint8_t> initial_ttl = 15;
    std::atomic<std::uint32_t> msg_seq = 0;
    utils::DeduplicationTable<message::Id> dedupe;
    QueueHandle_t packet_queue = nullptr;
    std::atomic<std::uint32_t> enqueue_inflight = 0;
};

struct QueueSlice {
    struct Item {
        std::size_t size = 0;
        MacAddress source{};
        std::uint16_t channel = 0;
        bool use_heap = false;
        std::array<std::uint8_t, ESP_NOW_MAX_DATA_LEN_V2> inline_payload{};
        std::vector<std::uint8_t> heap_payload;
    };

    mutable std::mutex mutex;
    std::vector<std::unique_ptr<Item>> storage;
    std::vector<Item*> free_items;
};

struct HeartbeatSlice {
    mutable std::mutex mutex;
    std::map<std::pair<std::uint8_t, MacAddress>, TimePoint> by_channel;
    TimePoint last_message;
};

struct AckSlice {
    mutable std::mutex mutex;
    std::map<message::Id, AckCookie> promises;
};

struct SegmentedSlice {
    mutable std::mutex rx_mutex;
    std::map<ReceiverSessionKey, std::shared_ptr<ReceiverSession>> rx_sessions;

    mutable std::mutex tx_mutex;
    std::map<SenderSessionKey, std::shared_ptr<SenderSession>> tx_sessions;
    std::atomic<std::uint32_t> active_tx_workers = 0;
};

struct DiagnosticsSlice {
#if BRICKS_DISNET_DIAGNOSTICS
    std::atomic<std::uint32_t> enqueue_drop_no_slot = 0;
    std::atomic<std::uint32_t> enqueue_drop_queue_full = 0;
    std::atomic<std::uint32_t> rx_session_rejected_limit = 0;
    std::atomic<std::uint32_t> tx_session_rejected_limit = 0;
    std::atomic<std::uint32_t> segment_store_store_failures = 0;
    std::atomic<std::uint32_t> segment_store_load_failures = 0;
    std::atomic<std::uint32_t> segment_cache_evictions = 0;
#endif
};

} // namespace detail

class Node {
  public:
    class Channel;

    struct Transport {
        esp_err_t (*init)() = nullptr;
        esp_err_t (*deinit)() = nullptr;
        esp_err_t (*add_broadcast_peer)() = nullptr;
        esp_err_t (*send_broadcast)(std::span<const std::uint8_t>) = nullptr;
        std::uint32_t (*random_u32)() = nullptr;
        TimePoint (*now)() = nullptr;
        void (*sleep_for)(std::chrono::milliseconds) = nullptr;
    };

    struct Config {
        struct SegmentedLimits {
            std::size_t max_rx_sessions = detail::Limits::max_segmented_rx_sessions;
            std::size_t max_tx_sessions = detail::Limits::max_segmented_tx_sessions;
            std::size_t max_equations_per_session = detail::Limits::max_segmented_equations_per_session;
            std::size_t max_seen_seeds_per_session = detail::Limits::max_segmented_seen_seeds_per_session;
            std::size_t max_payload_bytes = detail::Limits::max_segmented_payload_bytes;
            std::uint16_t max_block_size = detail::Limits::max_segmented_block_size;
            std::uint16_t max_block_count = detail::Limits::max_segmented_block_count;
        };

        struct SegmentStore {
            std::function<bool(const detail::SessionId&, std::uint16_t, std::span<const std::uint8_t>)> store_block;
            std::function<bool(const detail::SessionId&, std::uint16_t, std::span<std::uint8_t>)> load_block;
        };

        std::size_t inbound_slots = 32;
        std::size_t segmented_rx_cache_blocks = detail::Limits::max_segmented_block_count;
        SegmentedLimits segmented_limits{};
        Transport transport{};
        SegmentStore segment_store{};
    };

    struct Diagnostics {
#if BRICKS_DISNET_DIAGNOSTICS
        std::uint32_t enqueue_drop_no_slot = 0;
        std::uint32_t enqueue_drop_queue_full = 0;
        std::uint32_t rx_session_rejected_limit = 0;
        std::uint32_t tx_session_rejected_limit = 0;
        std::uint32_t segment_store_store_failures = 0;
        std::uint32_t segment_store_load_failures = 0;
        std::uint32_t segment_cache_evictions = 0;
#endif
    };

    static Transport default_transport();

    explicit Node(MacAddress my_address = MacAddress::my_address_sta());
    explicit Node(Config config, MacAddress my_address = MacAddress::my_address_sta());
    ~Node();

    Node(const Node&) = delete;
    Node& operator=(const Node&) = delete;

    void init();
    bool is_initialized() const;
    void shutdown();
#if BRICKS_DISNET_DIAGNOSTICS
    Diagnostics diagnostics() const;
#endif

    void activate_channel(std::uint8_t channel);
    bool is_channel_active(std::uint8_t channel) const;

    void register_handler(std::uint8_t channel, Callback cb);

    void set_input_filter(Predicate predicate);
    void set_processing_filter(Predicate predicate);
    void set_forwarding_filter(Predicate predicate);

    bool process_one(std::chrono::milliseconds time_to_wait = {});

    void send_raw(std::uint8_t channel, std::uint8_t ttl, const std::set<MacAddress>& targets,
                  std::span<const std::uint8_t> payload);

    AckFuture send_reliable(std::uint8_t channel, std::uint8_t ttl, const std::set<MacAddress>& targets,
                            std::span<const std::uint8_t> payload);

    AckFuture send_segmented(std::uint8_t channel, std::uint8_t ttl, const std::set<MacAddress>& targets,
                             std::span<const std::uint8_t> payload);

    void send_heartbeat(std::uint8_t channel, std::uint8_t ttl);
    void ensure_heartbeat(std::uint8_t channel, std::uint8_t ttl, TimePoint cutoff);

    TimePoint last_heartbeat(std::uint8_t channel, const MacAddress& address) const;
    std::vector<std::pair<MacAddress, TimePoint>> neighbours(std::uint8_t channel,
                                                             std::optional<TimePoint> cutoff = std::nullopt) const;

    bool default_input_filter(const message::Header& header) const {
        return _apply_default_input_filter(header);
    }
    bool default_processing_filter(const message::Header& header) const {
        return _apply_default_processing_filter(header);
    }
    bool default_forwarding_filter(const message::Header& header) const {
        return _apply_default_forwarding_filter(header);
    }

    // Host/simulation entrypoint: inject serialized frame directly.
    void inject_received(const MacAddress& source, std::span<const std::uint8_t> packet) {
        _handle_received_packet(source, packet);
    }

    Channel channel(std::uint8_t channel);

  private:
    bool _is_kiddy_device_locked() const {
        return m_channels.active_kiddy_count > 0;
    }
    static std::size_t _header_size_bytes(const message::Header& h) {
        return sizeof(message::Header) + static_cast<std::size_t>(h.target_count) * 6u;
    }
    bool _targets_contains(const message::Header& h, const MacAddress& addr) const;
    static std::vector<MacAddress> _targets_vector(const std::set<MacAddress>& targets) {
        return std::vector<MacAddress>(targets.begin(), targets.end());
    }

    void _send_buffer(std::span<const std::uint8_t> data);
    TimePoint _now() const {
        return m_config.transport.now ? m_config.transport.now() : Clock::now();
    }
    std::uint32_t _random_u32() const {
        return m_config.transport.random_u32 ? m_config.transport.random_u32() : 0;
    }
    void _sleep_for(std::chrono::milliseconds d) const {
        if (m_config.transport.sleep_for) {
            m_config.transport.sleep_for(d);
        }
    }
    message::Id _build_and_send(std::uint8_t channel, std::uint8_t ttl, message::Type type,
                                std::span<const MacAddress> targets, std::span<const std::uint8_t> payload);

    void _forward_packet(std::span<std::uint8_t> packet);
    void _dispatch(const MacAddress& source, std::uint8_t channel, std::span<const std::uint8_t> payload);
    void _enqueue_packet(MacAddress source, std::uint8_t channel, std::span<const std::uint8_t> payload);
    detail::QueueSlice::Item* _acquire_queue_item();
    void _release_queue_item(detail::QueueSlice::Item* item);

    bool _apply_default_input_filter(const message::Header& header) const;
    bool _apply_default_processing_filter(const message::Header& header) const;
    bool _apply_default_forwarding_filter(const message::Header& header) const;
    bool _should_keep_input_packet(const message::Header& header) const;
    bool _should_allow_by_device_policy(const message::Header& header) const;
    std::pair<bool, bool> _packet_filter_decisions(const message::Header& header) const;
    void _record_heartbeat_seen(const message::Header& header);
    void _handle_packet_by_type(const message::Header& header, std::span<const std::uint8_t> payload);

    void _handle_received_packet(const MacAddress& source, std::span<const std::uint8_t> packet_ro);
    void _recompute_custom_filters_flag_unlocked();

    void _reliable_cleanup_expired_acks(TimePoint now);
    void _reliable_sweep_timeouts();
    void _reliable_handle_ack(std::span<const std::uint8_t> payload_span);
    void _reliable_send_ack(const message::Header& hdr);

    void _segmented_handle_announce(const message::Header& hdr, std::span<const std::uint8_t> payload);
    void _segmented_handle_symbol(const message::Header& hdr, std::span<const std::uint8_t> payload);
    void _segmented_process_symbol_locked(detail::ReceiverSession& session, const detail::SessionId& session_id,
                                          std::uint32_t seed, std::span<const std::uint8_t> symbol_payload,
                                          TimePoint now, bool& send_repeat_nack, bool& send_need_more_nack,
                                          bool& send_finish_ack, bool& erase_session,
                                          std::vector<std::uint8_t>& full_payload);
    void _segmented_handle_ack(const message::Header& hdr, std::span<const std::uint8_t> payload);
    void _segmented_handle_nack(std::span<const std::uint8_t> payload);
    void _segmented_send_ack(std::uint8_t channel, const MacAddress& target, const detail::SessionId& session,
                             std::uint8_t flags);
    void _segmented_send_nack(std::uint8_t channel, const MacAddress& target, const detail::SessionId& session,
                              std::uint8_t reason);
    void _segmented_send_announce(const detail::SenderSession& ss);
    void _segmented_send_symbol(const detail::SenderSession& ss, std::uint32_t seed);
    static void _segmented_sender_task_entry(void* pv);
    void _segmented_sender_task(detail::SenderSession& ss);
    std::shared_ptr<detail::SenderSession> _segmented_create_sender_session(std::uint8_t channel, std::uint8_t ttl,
                                                                            const std::vector<MacAddress>& targets,
                                                                            std::span<const std::uint8_t> payload);

  private:
    detail::InitSlice m_lifecycle;
    detail::ChannelSlice m_channels;
    detail::FilterSlice m_filters;
    detail::RuntimeSlice m_runtime;
    detail::QueueSlice m_inbound;
    detail::HeartbeatSlice m_heartbeats;
    detail::AckSlice m_acks;
    detail::SegmentedSlice m_segmented;
    detail::DiagnosticsSlice m_diag;
    MacAddress m_my_address;
    Config m_config;
};

inline constexpr std::uint8_t g_default_ttl = 15;

class Node::Channel {
  private:
    Node& m_node;
    const std::uint8_t m_channel;

  public:
    Channel(Node& node, std::uint8_t channel) : m_node(node), m_channel(channel) {}

    void on(Callback&& cb) {
        m_node.register_handler(m_channel, std::forward<Callback>(cb));
    }

    void send_raw(const std::set<MacAddress>& targets, std::span<const std::uint8_t> payload,
                  std::uint8_t ttl = g_default_ttl) {
        m_node.send_raw(m_channel, ttl, targets, payload);
    }

    void broadcast_raw(std::span<const std::uint8_t> payload, std::uint8_t ttl = g_default_ttl) {
        m_node.send_raw(m_channel, ttl, {}, payload);
    }

    AckFuture send_reliable(const std::set<MacAddress>& targets, std::span<const std::uint8_t> payload,
                            std::uint8_t ttl = g_default_ttl) {
        return m_node.send_reliable(m_channel, ttl, targets, payload);
    }

    AckFuture send_segmented(const std::set<MacAddress>& targets, std::span<const std::uint8_t> payload,
                             std::uint8_t ttl = g_default_ttl) {
        return m_node.send_segmented(m_channel, ttl, targets, payload);
    }

    void send_heartbeat(std::uint8_t ttl = g_default_ttl) {
        m_node.send_heartbeat(m_channel, ttl);
    }

    void ensure_heartbeat(TimePoint cutoff, std::uint8_t ttl = g_default_ttl) {
        m_node.ensure_heartbeat(m_channel, ttl, cutoff);
    }

    void ensure_heartbeat(std::chrono::milliseconds cutoff, std::uint8_t ttl = g_default_ttl) {
        m_node.ensure_heartbeat(m_channel, ttl, Clock::now() - cutoff);
    }

    TimePoint last_heartbeat(const MacAddress& address) const {
        return m_node.last_heartbeat(m_channel, address);
    }

    std::vector<std::pair<MacAddress, TimePoint>> neighbours(std::optional<TimePoint> cutoff = std::nullopt) const {
        return m_node.neighbours(m_channel, cutoff);
    }
};

inline Node::Channel Node::channel(std::uint8_t channel_id) {
    return Channel(*this, channel_id);
}

} // namespace bricks::disnet
