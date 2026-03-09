#include "bricks/disnet.hpp"

#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <stdexcept>
#include <thread>

using namespace std::chrono_literals;

static const char* g_tag = "bricks/disnet";

namespace {

esp_err_t default_add_broadcast_peer() {
    esp_now_peer_info_t peer_info = {
        .peer_addr = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        .lmk = {0},
        .channel = 0,
        .ifidx = WIFI_IF_STA,
        .encrypt = false,
        .priv = nullptr,
    };
    return esp_now_add_peer(&peer_info);
}

esp_err_t default_send_broadcast(std::span<const std::uint8_t> data) {
    static bricks::disnet::MacAddress bcast = bricks::disnet::MacAddress::broadcast();
    return esp_now_send(bcast.data(), data.data(), static_cast<int>(data.size()));
}

bricks::disnet::TimePoint default_now() {
    return bricks::disnet::Clock::now();
}

void default_sleep_for(std::chrono::milliseconds d) {
    std::this_thread::sleep_for(d);
}

} // namespace

namespace bricks::disnet {

Node::Transport Node::default_transport() {
    return Transport{
        .init = esp_now_init,
        .deinit = esp_now_deinit,
        .add_broadcast_peer = default_add_broadcast_peer,
        .send_broadcast = default_send_broadcast,
        .random_u32 = esp_random,
        .now = default_now,
        .sleep_for = default_sleep_for,
    };
}

Node::Node(MacAddress my_addr)
    : Node(Config{.inbound_slots = 32, .transport = default_transport()}, my_addr) {
}

Node::Node(Config cfg, MacAddress my_addr)
    : m_my_address(my_addr)
    , m_config(std::move(cfg)) {
    if (!m_config.transport.init || !m_config.transport.deinit || !m_config.transport.add_broadcast_peer ||
        !m_config.transport.send_broadcast || !m_config.transport.random_u32 || !m_config.transport.now ||
        !m_config.transport.sleep_for) {
        m_config.transport = default_transport();
    }
    if (m_config.inbound_slots == 0) {
        m_config.inbound_slots = 32;
    }
}

Node::~Node() {
    shutdown();
}

bool Node::_targets_contains(const message::Header& h, const MacAddress& addr) const {
    const MacAddress* t = reinterpret_cast<const MacAddress*>(h.targets);
    for (std::uint8_t i = 0; i < h.target_count; ++i) {
        if (t[i] == addr) return true;
    }
    return false;
}

void Node::_send_buffer(std::span<const std::uint8_t> data) {
    esp_err_t err = ESP_OK;
    // Intentionally naive for now: keep retrying on temporary ESP-NOW NO_MEM and
    // revisit policy once we have real-world telemetry on frequency and impact.
    while ((err = m_config.transport.send_broadcast(data)) == ESP_ERR_ESPNOW_NO_MEM) {
        _sleep_for(100ms);
    }
    CHECK_IDF_ERROR(err);
}

message::Id Node::_build_and_send(std::uint8_t channel,
                                  std::uint8_t ttl,
                                  message::Type type,
                                  std::span<const MacAddress> targets,
                                  std::span<const std::uint8_t> payload) {
    message::Header header{
        .id = {.source = m_my_address, .seq = m_runtime.msg_seq++},
        .type = type,
        .ttl = ttl,
        .channel = channel,
        .target_count = static_cast<std::uint8_t>(std::min<std::size_t>(targets.size(), UINT8_MAX)),
    };

    const std::size_t hdr_bytes = sizeof(message::Header) + static_cast<std::size_t>(header.target_count) * 6u;
    const std::size_t total = hdr_bytes + payload.size();
    if (total > ESP_NOW_MAX_DATA_LEN_V2) {
        throw exceptions::Exception(std::runtime_error("disnet: packet too large for ESP-NOW"));
    }

    std::vector<std::uint8_t> buf(total);
    std::memcpy(buf.data(), &header, sizeof(message::Header));
    if (header.target_count) {
        std::memcpy(buf.data() + sizeof(message::Header), targets.data(), header.target_count * 6u);
    }
    if (!payload.empty()) {
        std::memcpy(buf.data() + hdr_bytes, payload.data(), payload.size());
    }

    {
        std::scoped_lock l(m_heartbeats.mutex);
        m_heartbeats.last_message = _now();
    }

    _send_buffer(buf);
    return header.id;
}

void Node::_forward_packet(std::span<std::uint8_t> packet) {
    if (packet.size() < sizeof(message::Header)) return;

    message::Header* hdr = reinterpret_cast<message::Header*>(packet.data());
    if (hdr->ttl == 0) return;

    hdr->ttl--;
    _send_buffer(packet);
    hdr->ttl++;
}

void Node::_dispatch(const MacAddress& source, std::uint8_t channel, std::span<const std::uint8_t> payload) {
    std::scoped_lock l(m_channels.handlers_mutex);
    std::map<std::uint8_t, Callback>::iterator it = m_channels.handlers.find(channel);
    if (it != m_channels.handlers.end() && it->second) {
        it->second(source, payload);
    }
}

detail::QueueSlice::Item* Node::_acquire_queue_item() {
    std::scoped_lock l(m_inbound.mutex);
    if (m_inbound.free_items.empty()) return nullptr;
    detail::QueueSlice::Item* item = m_inbound.free_items.back();
    m_inbound.free_items.pop_back();
    return item;
}

void Node::_release_queue_item(detail::QueueSlice::Item* item) {
    if (!item) return;
    item->size = 0;
    item->channel = 0;
    item->use_heap = false;
    item->heap_payload.clear();

    std::scoped_lock l(m_inbound.mutex);
    m_inbound.free_items.push_back(item);
}

void Node::_enqueue_packet(MacAddress source, std::uint8_t channel, std::span<const std::uint8_t> payload) {
    m_runtime.enqueue_inflight.fetch_add(1, std::memory_order_acq_rel);
    struct EnqueueGuard {
        std::atomic<std::uint32_t>& counter;
        ~EnqueueGuard() { counter.fetch_sub(1, std::memory_order_acq_rel); }
    } guard{m_runtime.enqueue_inflight};

    if (m_lifecycle.state.load(std::memory_order_acquire) != detail::InitState::Initialized) {
        return;
    }
    QueueHandle_t queue = m_runtime.packet_queue;
    if (!queue) {
        return;
    }

    detail::QueueSlice::Item* item = _acquire_queue_item();
    if (!item) {
#if BRICKS_DISNET_DIAGNOSTICS
        m_diag.enqueue_drop_no_slot.fetch_add(1, std::memory_order_relaxed);
#endif
        return;
    }

    item->source = source;
    item->channel = channel;
    item->size = payload.size();

    if (payload.size() <= item->inline_payload.size()) {
        item->use_heap = false;
        std::memcpy(item->inline_payload.data(), payload.data(), payload.size());
    } else {
        item->use_heap = true;
        item->heap_payload.assign(payload.begin(), payload.end());
    }

    if (xQueueSend(queue, &item, 0) != pdPASS) {
#if BRICKS_DISNET_DIAGNOSTICS
        m_diag.enqueue_drop_queue_full.fetch_add(1, std::memory_order_relaxed);
#endif
        _release_queue_item(item);
    }
}

bool Node::_apply_default_input_filter(const message::Header& header) const {
    return header.id.source != m_my_address;
}

bool Node::_apply_default_processing_filter(const message::Header& header) const {
    if (header.target_count == 0) return true;
    return _targets_contains(header, m_my_address);
}

bool Node::_apply_default_forwarding_filter(const message::Header& header) const {
    const bool for_me = (header.target_count != 0) && _targets_contains(header, m_my_address);
    return (!for_me) && (header.ttl > 0);
}

bool Node::_should_keep_input_packet(const message::Header& header) const {
    if (m_filters.custom_enabled) {
        std::scoped_lock l(m_filters.mutex);
        return m_filters.input ? m_filters.input(header) : _apply_default_input_filter(header);
    }
    return _apply_default_input_filter(header);
}

bool Node::_should_allow_by_device_policy(const message::Header& header) const {
    std::scoped_lock l(m_channels.active_mutex);
    const bool kiddy = _is_kiddy_device_locked();
    return kiddy ? true : m_channels.active_channels[header.channel];
}

std::pair<bool, bool> Node::_packet_filter_decisions(const message::Header& header) const {
    bool allow_by_filter = false;
    bool allow_processing = false;
    if (m_filters.custom_enabled) {
        std::scoped_lock l(m_filters.mutex);
        allow_by_filter = m_filters.forwarding ? m_filters.forwarding(header) : _apply_default_forwarding_filter(header);
        allow_processing = m_filters.processing ? m_filters.processing(header) : _apply_default_processing_filter(header);
    } else {
        allow_by_filter = _apply_default_forwarding_filter(header);
        allow_processing = _apply_default_processing_filter(header);
    }
    return std::make_pair(allow_by_filter, allow_processing);
}

void Node::_record_heartbeat_seen(const message::Header& header) {
    std::scoped_lock l(m_heartbeats.mutex);
    m_heartbeats.by_channel.emplace(std::pair<std::uint8_t, MacAddress>{header.channel, header.id.source}, _now());
}

void Node::_handle_packet_by_type(const message::Header& header, std::span<const std::uint8_t> payload) {
    switch (header.type) {
    case message::Type::Raw:
        _enqueue_packet(header.id.source, header.channel, payload);
        break;

    case message::Type::Reliable:
        _reliable_send_ack(header);
        _enqueue_packet(header.id.source, header.channel, payload);
        break;

    case message::Type::ReliableAck:
        _reliable_handle_ack(payload);
        break;

    case message::Type::Segmented:
        _segmented_handle_symbol(header, payload);
        break;

    case message::Type::SegmentedAnnounce:
        _segmented_handle_announce(header, payload);
        break;

    case message::Type::SegmentedAck:
        _segmented_handle_ack(header, payload);
        break;

    case message::Type::SegmentedNack:
        _segmented_handle_nack(payload);
        break;

    case message::Type::Heartbeat:
        break;
    }
}

void Node::_handle_received_packet(const MacAddress& source, std::span<const std::uint8_t> packet_ro) {
    if (m_lifecycle.state.load(std::memory_order_acquire) != detail::InitState::Initialized || m_runtime.packet_queue == nullptr) {
        return;
    }

    if (packet_ro.size() < sizeof(message::Header)) return;

    const message::Header* hdr = reinterpret_cast<const message::Header*>(packet_ro.data());
    const std::size_t hdr_bytes = sizeof(message::Header) + static_cast<std::size_t>(hdr->target_count) * 6u;
    if (hdr_bytes > packet_ro.size()) return;

    const bool keep_input = _should_keep_input_packet(*hdr);
    if (!keep_input) return;

    if (m_runtime.dedupe.check_seen_and_mark(hdr->id)) return;

    const bool allow_by_device_policy = _should_allow_by_device_policy(*hdr);
    const std::pair<bool, bool> filter_decisions = _packet_filter_decisions(*hdr);
    const bool allow_by_filter = filter_decisions.first;
    const bool allow_processing = filter_decisions.second;

    if (hdr->ttl > 0 && allow_by_device_policy && allow_by_filter) {
        std::uint8_t* mut = const_cast<std::uint8_t*>(packet_ro.data());
        std::span<std::uint8_t> packet_rw(mut, packet_ro.size());
        _forward_packet(packet_rw);
    }
    if (!allow_processing) return;

    _record_heartbeat_seen(*hdr);
    _handle_packet_by_type(*hdr, packet_ro.subspan(_header_size_bytes(*hdr)));

    (void)source;
}

void Node::_recompute_custom_filters_flag_unlocked() {
    const bool enabled = static_cast<bool>(m_filters.input) || static_cast<bool>(m_filters.processing) || static_cast<bool>(m_filters.forwarding);
    m_filters.custom_enabled.store(enabled, std::memory_order_relaxed);
}

void Node::init() {
    detail::InitState expected = detail::InitState::NotInitialized;
    if (!m_lifecycle.state.compare_exchange_strong(expected, detail::InitState::Initializing)) {
        throw exceptions::Exception(std::runtime_error("disnet already initialized"));
    }

    m_runtime.msg_seq.store(_random_u32(), std::memory_order_relaxed);

    m_runtime.packet_queue = xQueueCreate(static_cast<UBaseType_t>(m_config.inbound_slots), sizeof(detail::QueueSlice::Item*));
    if (!m_runtime.packet_queue) {
        m_lifecycle.state.store(detail::InitState::NotInitialized, std::memory_order_release);
        throw exceptions::Exception(std::runtime_error("disnet: failed to create inbound packet queue"));
    }

    {
        std::scoped_lock l(m_inbound.mutex);
        m_inbound.storage.clear();
        m_inbound.free_items.clear();
        m_inbound.storage.reserve(m_config.inbound_slots);
        m_inbound.free_items.reserve(m_config.inbound_slots);
        for (std::size_t i = 0; i < m_config.inbound_slots; ++i) {
            m_inbound.storage.emplace_back(std::make_unique<detail::QueueSlice::Item>());
            m_inbound.free_items.push_back(m_inbound.storage.back().get());
        }
    }

    CHECK_IDF_ERROR(m_config.transport.init());
    CHECK_IDF_ERROR(m_config.transport.add_broadcast_peer());

    {
        std::scoped_lock l(m_channels.active_mutex);
        m_runtime.initial_ttl.store(15, std::memory_order_relaxed);
        m_channels.active_channels.assign(256, false);
        m_channels.active_kiddy_count = 0;
    }

    {
        std::scoped_lock l(m_heartbeats.mutex);
        m_heartbeats.by_channel.clear();
    }

    m_lifecycle.state.store(detail::InitState::Initialized, std::memory_order_release);
}

bool Node::is_initialized() const {
    return m_lifecycle.state.load(std::memory_order_acquire) == detail::InitState::Initialized;
}

#if BRICKS_DISNET_DIAGNOSTICS
Node::Diagnostics Node::diagnostics() const {
    return Diagnostics{
        .enqueue_drop_no_slot = m_diag.enqueue_drop_no_slot.load(std::memory_order_relaxed),
        .enqueue_drop_queue_full = m_diag.enqueue_drop_queue_full.load(std::memory_order_relaxed),
        .rx_session_rejected_limit = m_diag.rx_session_rejected_limit.load(std::memory_order_relaxed),
        .tx_session_rejected_limit = m_diag.tx_session_rejected_limit.load(std::memory_order_relaxed),
        .segment_store_store_failures = m_diag.segment_store_store_failures.load(std::memory_order_relaxed),
        .segment_store_load_failures = m_diag.segment_store_load_failures.load(std::memory_order_relaxed),
        .segment_cache_evictions = m_diag.segment_cache_evictions.load(std::memory_order_relaxed),
    };
}
#endif

void Node::shutdown() {
    detail::InitState expected = detail::InitState::Initialized;
    if (!m_lifecycle.state.compare_exchange_strong(expected, detail::InitState::Initializing)) {
        return;
    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wterminate"

    m_lifecycle.state.store(detail::InitState::Initializing, std::memory_order_release);
    CHECK_IDF_ERROR(m_config.transport.deinit());

    for (int i = 0; i < 50; ++i) {
        if (m_runtime.enqueue_inflight.load(std::memory_order_acquire) == 0) break;
        _sleep_for(2ms);
    }

    if (m_runtime.packet_queue) {
        detail::QueueSlice::Item* item = nullptr;
        while (xQueueReceive(m_runtime.packet_queue, &item, 0) == pdPASS) {
            _release_queue_item(item);
        }
        vQueueDelete(m_runtime.packet_queue);
        m_runtime.packet_queue = nullptr;
    }

#pragma GCC diagnostic pop

    {
        std::scoped_lock l(m_channels.handlers_mutex);
        m_channels.handlers.clear();
    }
    {
        std::scoped_lock l(m_acks.mutex);
        for (std::pair<const message::Id, detail::AckCookie>& entry : m_acks.promises) {
            try {
                entry.second.promise.set_exception(std::make_exception_ptr(std::runtime_error("disnet shutdown")));
            } catch (...) {
            }
            (void)entry;
        }
        m_acks.promises.clear();
    }
    {
        std::scoped_lock l(m_segmented.tx_mutex);
        for (std::pair<const detail::SenderSessionKey, std::shared_ptr<detail::SenderSession>>& entry : m_segmented.tx_sessions) {
            entry.second->stop.store(true, std::memory_order_relaxed);
            try {
                entry.second->promise.set_exception(std::make_exception_ptr(std::runtime_error("disnet shutdown")));
            } catch (...) {
            }
            (void)entry;
        }
    }
    for (int i = 0; i < 50; ++i) {
        if (m_segmented.active_tx_workers.load(std::memory_order_relaxed) == 0) break;
        _sleep_for(10ms);
    }
    {
        std::scoped_lock l(m_segmented.tx_mutex);
        m_segmented.tx_sessions.clear();
    }
    {
        std::scoped_lock l(m_segmented.rx_mutex);
        m_segmented.rx_sessions.clear();
    }
    {
        std::scoped_lock l(m_heartbeats.mutex);
        m_heartbeats.by_channel.clear();
    }
    {
        std::scoped_lock l(m_channels.active_mutex);
        m_channels.active_channels.assign(256, false);
        m_channels.active_kiddy_count = 0;
    }
    {
        std::scoped_lock l(m_inbound.mutex);
        m_inbound.free_items.clear();
        m_inbound.storage.clear();
    }

    m_lifecycle.state.store(detail::InitState::NotInitialized, std::memory_order_release);
}

void Node::activate_channel(std::uint8_t channel_id) {
    std::scoped_lock l(m_channels.active_mutex);
    bool slot = m_channels.active_channels[channel_id];
    if (!slot) {
        m_channels.active_channels[channel_id] = true;
        if (channel_id < 128) {
            ++m_channels.active_kiddy_count;
        }
    }
}

bool Node::is_channel_active(std::uint8_t channel_id) const {
    std::scoped_lock l(m_channels.active_mutex);
    return m_channels.active_channels[channel_id];
}

void Node::register_handler(std::uint8_t channel_id, Callback cb) {
    std::scoped_lock l(m_channels.handlers_mutex);
    m_channels.handlers[channel_id] = std::move(cb);
}

void Node::set_input_filter(Predicate predicate) {
    std::scoped_lock l(m_filters.mutex);
    m_filters.input = std::move(predicate);
    _recompute_custom_filters_flag_unlocked();
}

void Node::set_processing_filter(Predicate predicate) {
    std::scoped_lock l(m_filters.mutex);
    m_filters.processing = std::move(predicate);
    _recompute_custom_filters_flag_unlocked();
}

void Node::set_forwarding_filter(Predicate predicate) {
    std::scoped_lock l(m_filters.mutex);
    m_filters.forwarding = std::move(predicate);
    _recompute_custom_filters_flag_unlocked();
}

bool Node::process_one(std::chrono::milliseconds time_to_wait) {
    _reliable_sweep_timeouts();

    if (!m_runtime.packet_queue) return false;

    detail::QueueSlice::Item* item = nullptr;
    if (xQueueReceive(m_runtime.packet_queue, &item, pdMS_TO_TICKS(time_to_wait.count())) != pdPASS) {
        _reliable_sweep_timeouts();
        return false;
    }

    const std::span<const std::uint8_t> payload =
        item->use_heap ? std::span<const std::uint8_t>(item->heap_payload) : std::span<const std::uint8_t>(item->inline_payload.data(), item->size);
    _dispatch(item->source, item->channel, payload);

    _release_queue_item(item);
    _reliable_sweep_timeouts();
    return true;
}

void Node::send_raw(std::uint8_t channel_id,
                    std::uint8_t ttl,
                    const std::set<MacAddress>& targets,
                    std::span<const std::uint8_t> payload) {
    if (!is_channel_active(channel_id)) {
        ESP_LOGW(g_tag, "send_raw: Channel not active: %x", channel_id);
        return;
    }

    const std::vector<MacAddress> tvec = _targets_vector(targets);
    (void)_build_and_send(channel_id, ttl, message::Type::Raw, tvec, payload);
}

void Node::send_heartbeat(std::uint8_t channel_id, std::uint8_t ttl) {
    if (!is_channel_active(channel_id)) return;

    (void)_build_and_send(channel_id, ttl, message::Type::Heartbeat, {}, {});
}

void Node::ensure_heartbeat(std::uint8_t channel_id, std::uint8_t ttl, TimePoint cutoff) {
    bool need = false;
    {
        std::scoped_lock l(m_heartbeats.mutex);
        need = m_heartbeats.last_message < cutoff;
    }
    if (need) {
        send_heartbeat(channel_id, ttl);
    }
}

TimePoint Node::last_heartbeat(std::uint8_t channel_id, const MacAddress& address) const {
    const std::pair<std::uint8_t, MacAddress> key = std::make_pair(channel_id, address);
    std::scoped_lock l(m_heartbeats.mutex);
    std::map<std::pair<std::uint8_t, MacAddress>, TimePoint>::const_iterator it = m_heartbeats.by_channel.find(key);
    if (it == m_heartbeats.by_channel.end()) return TimePoint{};
    return it->second;
}

std::vector<std::pair<MacAddress, TimePoint>> Node::neighbours(std::uint8_t channel_id,
                                                               std::optional<TimePoint> cutoff) const {
    std::vector<std::pair<MacAddress, TimePoint>> out;
    std::scoped_lock l(m_heartbeats.mutex);
    for (const std::pair<const std::pair<std::uint8_t, MacAddress>, TimePoint>& entry : m_heartbeats.by_channel) {
        const std::uint8_t ch = entry.first.first;
        const MacAddress& mac = entry.first.second;
        const TimePoint ts = entry.second;
        if (ch != channel_id) continue;
        if (cutoff.has_value() && ts < *cutoff) continue;
        out.emplace_back(mac, ts);
    }
    return out;
}

} // namespace bricks::disnet
