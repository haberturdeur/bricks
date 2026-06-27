#pragma once

#include "bricks/disnet/transport.hpp"
#include "bricks/utility/packed_size.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <deque>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>

namespace bricks::disnet {

template <Transport TransportT, typename ClockT = std::chrono::steady_clock>
class Hwmp {
public:
    struct Config {
        std::uint8_t ttl = 15;
        std::uint8_t proactive_ttl = 31;
        bool root = false;
        bool intermediate_replies = true;
        std::size_t max_pending_per_destination = 8;
        std::size_t max_pending_total = 32;
        std::chrono::milliseconds route_lifetime{128};
        std::chrono::milliseconds discovery_retry_interval{8};
    };

    using Transport = TransportT;
    using Address = typename Transport::Address;

    static_assert(std::is_trivially_copyable_v<Address>);

private:
    using TimePoint = typename ClockT::time_point;

    enum class FrameType : std::uint8_t {
        Data = 0,
        Preq = 1,
        Prep = 2,
        Perr = 3,
    };

    static constexpr std::uint8_t s_flag_root = 1 << 0;
    static constexpr std::uint8_t s_flag_destination_only = 1 << 1;

    struct DataHeader {
        FrameType type;
        std::uint8_t ttl;
        Address source;
        Address target;
        std::uint32_t source_seq;
    };

    struct PreqHeader {
        FrameType type;
        std::uint8_t ttl;
        std::uint8_t flags;
        std::uint32_t preq_id;
        Address originator;
        std::uint32_t originator_seq;
        Address target;
        std::uint32_t target_seq;
        std::uint32_t metric;
    };

    struct PrepHeader {
        FrameType type;
        std::uint8_t ttl;
        Address originator;
        Address target;
        std::uint32_t target_seq;
        std::uint32_t metric;
    };

    struct PerrHeader {
        FrameType type;
        Address destination;
        std::uint32_t destination_seq;
    };

    static constexpr std::size_t s_data_header_size = bricks::utility::packed_size<DataHeader>;
    static constexpr std::size_t s_preq_header_size = bricks::utility::packed_size<PreqHeader>;
    static constexpr std::size_t s_prep_header_size = bricks::utility::packed_size<PrepHeader>;
    static constexpr std::size_t s_perr_header_size = bricks::utility::packed_size<PerrHeader>;

public:
    static constexpr std::size_t max_payload_size =
        Transport::max_payload_size - s_data_header_size;
    static_assert(max_payload_size > 0 && max_payload_size < Transport::max_payload_size,
                  "Transport::max_payload_size is too small to hold an HWMP data frame header");

    static Address broadcast_address() {
        return Transport::broadcast_address();
    }

    explicit Hwmp(Transport& transport, Config config = {}) : m_transport(transport), m_config(config) {}

    Address my_address() const {
        return m_transport.my_address();
    }

    void send(TransportPacket<Address> packet) {
        std::vector<TransportPacket<Address>> outbox;
        {
            std::lock_guard lock(m_mutex);
            m_outbox.clear();
            _expire_stale_pending();

            if (packet.payload.size() > max_payload_size) {
                return;
            }

            packet.source = my_address();
            packet.source_seq = ++m_originator_seq;
            (void)_remember_data(packet.source, packet.source_seq);

            if (packet.target == broadcast_address()) {
                _send_broadcast_data(packet, m_config.ttl);
            } else if (const Route* route = _find_route(packet.target)) {
                _send_data_frame(packet, route->next_hop, m_config.ttl);
            } else {
                _queue_pending(packet, m_config.ttl);
                _send_or_retry_preq(packet.target);
            }

            outbox = std::move(m_outbox);
        }
        for (auto& pkt : outbox)
            m_transport.send(std::move(pkt));
    }

    void handle_packet(const TransportPacket<Address>& packet) {
        std::optional<TransportPacket<Address>> to_deliver;
        std::vector<TransportPacket<Address>> outbox;
        TransportReceiveCallback<Address> cb;

        {
            std::lock_guard lock(m_mutex);
            m_outbox.clear();
            cb = m_callback;
            _expire_stale_pending();

            DecodedFrame frame;
            if (_decode_frame(packet.payload, frame) && packet.source != my_address()) {
                switch (frame.type) {
                case FrameType::Data:
                    to_deliver = _handle_data(packet.source, frame);
                    break;
                case FrameType::Preq:
                    _handle_preq(packet.source, frame);
                    break;
                case FrameType::Prep:
                    _handle_prep(packet.source, frame);
                    break;
                case FrameType::Perr:
                    _handle_perr(packet.source, frame);
                    break;
                }
            }

            outbox = std::move(m_outbox);
        }

        for (auto& pkt : outbox)
            m_transport.send(std::move(pkt));
        if (to_deliver && cb)
            cb(std::move(*to_deliver));
    }

    void register_callback(TransportReceiveCallback<Address> callback) {
        std::lock_guard lock(m_mutex);
        m_callback = std::move(callback);
    }

    void announce_root() {
        std::vector<TransportPacket<Address>> outbox;
        {
            std::lock_guard lock(m_mutex);
            m_outbox.clear();
            _expire_stale_pending();

            if (m_config.root) {
                const std::uint32_t originator_seq = ++m_originator_seq;
                const std::uint32_t preq_id = ++m_preq_id;
                _remember_preq(my_address(), preq_id, 0);
                _broadcast_frame(_encode_preq(PreqFrame{
                    .ttl = m_config.proactive_ttl,
                    .flags = s_flag_root,
                    .preq_id = preq_id,
                    .originator = my_address(),
                    .originator_seq = originator_seq,
                    .target = broadcast_address(),
                    .target_seq = 0,
                    .metric = 0,
                }));
            }

            outbox = std::move(m_outbox);
        }
        for (auto& pkt : outbox)
            m_transport.send(std::move(pkt));
    }

    void invalidate_route(const Address& destination) {
        std::vector<TransportPacket<Address>> outbox;
        {
            std::lock_guard lock(m_mutex);
            m_outbox.clear();
            _expire_stale_pending();

            typename std::map<Address, Route>::iterator it = m_routes.find(destination);
            if (it != m_routes.end()) {
                it->second.valid = false;
                _broadcast_frame(_encode_perr(PerrFrame{
                    .destination = destination,
                    .destination_seq = it->second.destination_seq,
                }));
            }

            outbox = std::move(m_outbox);
        }
        for (auto& pkt : outbox)
            m_transport.send(std::move(pkt));
    }

private:
    static constexpr std::size_t s_seen_capacity = 256;

    struct Route {
        Address next_hop{};
        std::uint32_t destination_seq = 0;
        std::uint32_t metric = std::numeric_limits<std::uint32_t>::max();
        bool valid = false;
        bool root = false;
        TimePoint last_updated{};
    };

    struct PendingPacket {
        TransportPacket<Address> packet;
        std::uint8_t ttl = 0;
        TimePoint queued_at{};
    };

    struct DataFrame {
        std::uint8_t ttl = 0;
        Address source{};
        Address target{};
        std::uint32_t source_seq = 0;
        std::vector<std::uint8_t> payload;
    };

    struct PreqFrame {
        std::uint8_t ttl = 0;
        std::uint8_t flags = 0;
        std::uint32_t preq_id = 0;
        Address originator{};
        std::uint32_t originator_seq = 0;
        Address target{};
        std::uint32_t target_seq = 0;
        std::uint32_t metric = 0;
    };

    struct PrepFrame {
        std::uint8_t ttl = 0;
        Address originator{};
        Address target{};
        std::uint32_t target_seq = 0;
        std::uint32_t metric = 0;
    };

    struct PerrFrame {
        Address destination{};
        std::uint32_t destination_seq = 0;
    };

    struct DecodedFrame {
        FrameType type = FrameType::Data;
        DataFrame data{};
        PreqFrame preq{};
        PrepFrame prep{};
        PerrFrame perr{};
    };

    struct PreqKey {
        Address originator{};
        std::uint32_t preq_id = 0;

        auto operator<=>(const PreqKey&) const = default;
    };

    Transport& m_transport;
    Config m_config;
    TransportReceiveCallback<Address> m_callback;
    std::map<Address, Route> m_routes;
    std::map<Address, std::vector<PendingPacket>> m_pending_packets;
    std::map<Address, TimePoint> m_pending_preqs;
    std::map<PreqKey, std::uint32_t> m_seen_preqs;
    std::deque<PreqKey> m_seen_preq_order;
    std::deque<std::pair<Address, std::uint32_t>> m_seen_data;
    std::deque<std::pair<Address, std::uint32_t>> m_seen_perrs;
    std::uint32_t m_originator_seq = 0;
    std::uint32_t m_frame_seq = 0;
    std::uint32_t m_preq_id = 0;
    std::vector<TransportPacket<Address>> m_outbox;
    mutable std::mutex m_mutex;

    template <typename T>
    static void _append(std::vector<std::uint8_t>& out, const T& value) {
        const std::size_t offset = out.size();
        out.resize(offset + sizeof(T));
        std::memcpy(out.data() + offset, &value, sizeof(T));
    }

    template <typename T>
    static bool _read(const std::vector<std::uint8_t>& in, std::size_t& offset, T& value) {
        if (offset + sizeof(T) > in.size())
            return false;
        std::memcpy(&value, in.data() + offset, sizeof(T));
        offset += sizeof(T);
        return true;
    }

    static constexpr std::uint32_t _saturating_inc(std::uint32_t v) {
        return v == std::numeric_limits<std::uint32_t>::max() ? v : v + 1;
    }

    static std::vector<std::uint8_t> _encode_data(const DataFrame& frame) {
        std::vector<std::uint8_t> out;
        out.reserve(s_data_header_size + frame.payload.size());
        _append(out, FrameType::Data);
        _append(out, frame.ttl);
        _append(out, frame.source);
        _append(out, frame.target);
        _append(out, frame.source_seq);
        out.insert(out.end(), frame.payload.begin(), frame.payload.end());
        return out;
    }

    static std::vector<std::uint8_t> _encode_preq(const PreqFrame& frame) {
        std::vector<std::uint8_t> out;
        out.reserve(s_preq_header_size);
        _append(out, FrameType::Preq);
        _append(out, frame.ttl);
        _append(out, frame.flags);
        _append(out, frame.preq_id);
        _append(out, frame.originator);
        _append(out, frame.originator_seq);
        _append(out, frame.target);
        _append(out, frame.target_seq);
        _append(out, frame.metric);
        return out;
    }

    static std::vector<std::uint8_t> _encode_prep(const PrepFrame& frame) {
        std::vector<std::uint8_t> out;
        out.reserve(s_prep_header_size);
        _append(out, FrameType::Prep);
        _append(out, frame.ttl);
        _append(out, frame.originator);
        _append(out, frame.target);
        _append(out, frame.target_seq);
        _append(out, frame.metric);
        return out;
    }

    static std::vector<std::uint8_t> _encode_perr(const PerrFrame& frame) {
        std::vector<std::uint8_t> out;
        out.reserve(s_perr_header_size);
        _append(out, FrameType::Perr);
        _append(out, frame.destination);
        _append(out, frame.destination_seq);
        return out;
    }

    static bool _decode_frame(const std::vector<std::uint8_t>& encoded, DecodedFrame& frame) {
        std::size_t offset = 0;
        if (!_read(encoded, offset, frame.type))
            return false;

        switch (frame.type) {
        case FrameType::Data:
            if (!_read(encoded, offset, frame.data.ttl) || !_read(encoded, offset, frame.data.source)
                || !_read(encoded, offset, frame.data.target) || !_read(encoded, offset, frame.data.source_seq)) {
                return false;
            }
            frame.data.payload.assign(encoded.begin() + static_cast<std::ptrdiff_t>(offset), encoded.end());
            return true;

        case FrameType::Preq:
            return _read(encoded, offset, frame.preq.ttl) && _read(encoded, offset, frame.preq.flags)
                && _read(encoded, offset, frame.preq.preq_id) && _read(encoded, offset, frame.preq.originator)
                && _read(encoded, offset, frame.preq.originator_seq) && _read(encoded, offset, frame.preq.target)
                && _read(encoded, offset, frame.preq.target_seq) && _read(encoded, offset, frame.preq.metric);

        case FrameType::Prep:
            return _read(encoded, offset, frame.prep.ttl) && _read(encoded, offset, frame.prep.originator)
                && _read(encoded, offset, frame.prep.target) && _read(encoded, offset, frame.prep.target_seq)
                && _read(encoded, offset, frame.prep.metric);

        case FrameType::Perr:
            return _read(encoded, offset, frame.perr.destination) && _read(encoded, offset, frame.perr.destination_seq);
        }

        return false;
    }

    void _broadcast_frame(std::vector<std::uint8_t> payload) {
        m_outbox.push_back(TransportPacket<Address>{
            .source = my_address(),
            .target = broadcast_address(),
            .source_seq = ++m_frame_seq,
            .payload = std::move(payload),
        });
    }

    void _unicast_frame(const Address& next_hop, std::vector<std::uint8_t> payload) {
        m_outbox.push_back(TransportPacket<Address>{
            .source = my_address(),
            .target = next_hop,
            .source_seq = ++m_frame_seq,
            .payload = std::move(payload),
        });
    }

    void _queue_pending(const TransportPacket<Address>& packet, std::uint8_t ttl) {
        std::vector<PendingPacket>& pending = m_pending_packets[packet.target];
        if (m_config.max_pending_per_destination == 0 || m_config.max_pending_total == 0)
            return;

        if (pending.size() >= m_config.max_pending_per_destination)
            pending.erase(pending.begin());

        pending.push_back(PendingPacket{
            .packet = packet,
            .ttl = ttl,
            .queued_at = ClockT::now(),
        });

        while (_pending_packet_count() > m_config.max_pending_total) {
            _drop_oldest_pending();
        }
    }

    const Route* _find_route(const Address& destination) const {
        const auto now = ClockT::now();
        typename std::map<Address, Route>::const_iterator it = m_routes.find(destination);
        if (it == m_routes.end() || !_route_is_usable(it->second, now))
            return nullptr;
        return &it->second;
    }

    bool _update_route(const Address& destination, const Address& next_hop, std::uint32_t destination_seq,
                       std::uint32_t metric, bool root = false) {
        const auto now = ClockT::now();
        Route& route = m_routes[destination];
        const bool existing_is_usable = route.valid && _route_is_usable(route, now);

        if (!existing_is_usable || destination_seq > route.destination_seq
            || (destination_seq == route.destination_seq && metric < route.metric)) {
            route.next_hop = next_hop;
            route.destination_seq = destination_seq;
            route.metric = metric;
            route.valid = true;
            route.root = root;
            route.last_updated = now;
            return true;
        }
        return false;
    }

    bool _remember_preq(const Address& originator, std::uint32_t preq_id, std::uint32_t metric) {
        const PreqKey key{originator, preq_id};
        typename std::map<PreqKey, std::uint32_t>::iterator it = m_seen_preqs.find(key);
        if (it != m_seen_preqs.end() && it->second <= metric)
            return false;

        if (it == m_seen_preqs.end()) {
            m_seen_preq_order.push_back(key);
            if (m_seen_preq_order.size() > s_seen_capacity) {
                m_seen_preqs.erase(m_seen_preq_order.front());
                m_seen_preq_order.pop_front();
            }
        }
        m_seen_preqs[key] = metric;
        return true;
    }

    bool _remember_data(const Address& source, std::uint32_t source_seq) {
        const std::pair<Address, std::uint32_t> id{source, source_seq};
        if (std::find(m_seen_data.begin(), m_seen_data.end(), id) != m_seen_data.end())
            return false;
        m_seen_data.push_back(id);
        if (m_seen_data.size() > s_seen_capacity)
            m_seen_data.pop_front();
        return true;
    }

    bool _remember_perr(const Address& destination, std::uint32_t destination_seq) {
        const std::pair<Address, std::uint32_t> id{destination, destination_seq};
        if (std::find(m_seen_perrs.begin(), m_seen_perrs.end(), id) != m_seen_perrs.end())
            return false;
        m_seen_perrs.push_back(id);
        if (m_seen_perrs.size() > s_seen_capacity)
            m_seen_perrs.pop_front();
        return true;
    }

    bool _route_is_usable(const Route& route, const TimePoint& now) const {
        if (!route.valid)
            return false;
        return (now - route.last_updated) <= m_config.route_lifetime;
    }

    std::size_t _pending_packet_count() const {
        std::size_t total = 0;
        for (const auto& [destination, pending] : m_pending_packets) {
            (void)destination;
            total += pending.size();
        }
        return total;
    }

    void _drop_oldest_pending() {
        typename std::map<Address, std::vector<PendingPacket>>::iterator oldest_it = m_pending_packets.end();
        std::size_t oldest_index = 0;
        TimePoint oldest_time = TimePoint::max();

        for (typename std::map<Address, std::vector<PendingPacket>>::iterator it = m_pending_packets.begin();
             it != m_pending_packets.end(); ++it) {
            for (std::size_t index = 0; index < it->second.size(); ++index) {
                if (it->second[index].queued_at < oldest_time) {
                    oldest_time = it->second[index].queued_at;
                    oldest_it = it;
                    oldest_index = index;
                }
            }
        }

        if (oldest_it == m_pending_packets.end())
            return;

        const Address destination = oldest_it->first;
        oldest_it->second.erase(oldest_it->second.begin() + static_cast<std::ptrdiff_t>(oldest_index));
        if (oldest_it->second.empty()) {
            m_pending_packets.erase(oldest_it);
            m_pending_preqs.erase(destination);
        }
    }

    void _expire_stale_pending() {
        const auto now = ClockT::now();
        const auto pending_lifetime = std::max(m_config.route_lifetime,
                                               m_config.discovery_retry_interval + std::chrono::milliseconds{1});

        for (typename std::map<Address, std::vector<PendingPacket>>::iterator it = m_pending_packets.begin();
             it != m_pending_packets.end();) {
            std::vector<PendingPacket>& pending = it->second;
            pending.erase(std::remove_if(pending.begin(), pending.end(), [&](const PendingPacket& packet) {
                              return (now - packet.queued_at) > pending_lifetime;
                          }),
                          pending.end());

            if (pending.empty()) {
                m_pending_preqs.erase(it->first);
                it = m_pending_packets.erase(it);
                continue;
            }

            typename std::map<Address, TimePoint>::iterator preq_it = m_pending_preqs.find(it->first);
            if (preq_it != m_pending_preqs.end()
                && (now - preq_it->second) > m_config.discovery_retry_interval) {
                m_pending_preqs.erase(preq_it);
            }

            ++it;
        }
    }

    void _send_data_frame(const TransportPacket<Address>& packet, const Address& next_hop, std::uint8_t ttl) {
        _unicast_frame(next_hop, _encode_data(DataFrame{
                                   .ttl = ttl,
                                   .source = packet.source,
                                   .target = packet.target,
                                   .source_seq = packet.source_seq,
                                   .payload = packet.payload,
                               }));
    }

    void _send_broadcast_data(const TransportPacket<Address>& packet, std::uint8_t ttl) {
        _broadcast_frame(_encode_data(DataFrame{
            .ttl = ttl,
            .source = packet.source,
            .target = packet.target,
            .source_seq = packet.source_seq,
            .payload = packet.payload,
        }));
    }

    void _send_or_retry_preq(const Address& target) {
        const auto now = ClockT::now();
        typename std::map<Address, TimePoint>::const_iterator it = m_pending_preqs.find(target);
        if (it != m_pending_preqs.end() && (now - it->second) <= m_config.discovery_retry_interval)
            return;

        _send_preq(target);
        m_pending_preqs[target] = now;
    }

    void _send_preq(const Address& target) {
        const std::uint32_t originator_seq = ++m_originator_seq;
        const std::uint32_t preq_id = ++m_preq_id;
        _remember_preq(my_address(), preq_id, 0);
        _broadcast_frame(_encode_preq(PreqFrame{
            .ttl = m_config.ttl,
            .flags = static_cast<std::uint8_t>(m_config.intermediate_replies ? 0 : s_flag_destination_only),
            .preq_id = preq_id,
            .originator = my_address(),
            .originator_seq = originator_seq,
            .target = target,
            .target_seq = 0,
            .metric = 0,
        }));
    }

    void _send_prep(const Address& originator, const Address& target, std::uint32_t target_seq, std::uint32_t metric,
                    std::uint8_t ttl) {
        const Route* reverse_route = _find_route(originator);
        if (reverse_route == nullptr)
            return;

        _unicast_frame(reverse_route->next_hop, _encode_prep(PrepFrame{
                                                   .ttl = ttl,
                                                   .originator = originator,
                                                   .target = target,
                                                   .target_seq = target_seq,
                                                   .metric = metric,
                                               }));
    }

    void _flush_pending(const Address& destination) {
        m_pending_preqs.erase(destination);
        const Route* route = _find_route(destination);
        if (route == nullptr)
            return;

        typename std::map<Address, std::vector<PendingPacket>>::iterator it = m_pending_packets.find(destination);
        if (it == m_pending_packets.end())
            return;

        std::vector<PendingPacket> pending = std::move(it->second);
        m_pending_packets.erase(it);
        for (PendingPacket& queued : pending) {
            if (queued.ttl == 0)
                continue;
            _send_data_frame(queued.packet, route->next_hop, queued.ttl);
        }
    }

    std::optional<TransportPacket<Address>> _handle_data(const Address& previous_hop, const DecodedFrame& frame) {
        (void)previous_hop;

        if (!_remember_data(frame.data.source, frame.data.source_seq))
            return std::nullopt;

        std::optional<TransportPacket<Address>> to_deliver;
        if (frame.data.target == my_address() || frame.data.target == broadcast_address()) {
            to_deliver = TransportPacket<Address>{
                .source = frame.data.source,
                .target = frame.data.target,
                .source_seq = frame.data.source_seq,
                .payload = frame.data.payload,
            };
        }

        if (frame.data.ttl == 0 || frame.data.target == my_address())
            return to_deliver;

        TransportPacket<Address> packet{
            .source = frame.data.source,
            .target = frame.data.target,
            .source_seq = frame.data.source_seq,
            .payload = frame.data.payload,
        };

        if (frame.data.target == broadcast_address()) {
            _send_broadcast_data(packet, static_cast<std::uint8_t>(frame.data.ttl - 1));
            return to_deliver;
        }

        if (const Route* route = _find_route(frame.data.target)) {
            _send_data_frame(packet, route->next_hop, static_cast<std::uint8_t>(frame.data.ttl - 1));
            return to_deliver;
        }

        _queue_pending(packet, static_cast<std::uint8_t>(frame.data.ttl - 1));
        _send_or_retry_preq(frame.data.target);
        return to_deliver;
    }

    void _handle_preq(const Address& previous_hop, const DecodedFrame& frame) {
        const std::uint32_t metric = _saturating_inc(frame.preq.metric);
        _update_route(frame.preq.originator, previous_hop, frame.preq.originator_seq, metric,
                      (frame.preq.flags & s_flag_root) != 0);

        if (!_remember_preq(frame.preq.originator, frame.preq.preq_id, metric))
            return;

        if ((frame.preq.flags & s_flag_root) != 0) {
            if (frame.preq.ttl > 0) {
                PreqFrame forwarded = frame.preq;
                forwarded.ttl--;
                forwarded.metric = metric;
                _broadcast_frame(_encode_preq(forwarded));
            }
            return;
        }

        if (frame.preq.target == my_address()) {
            _send_prep(frame.preq.originator, my_address(), ++m_originator_seq, 0, m_config.ttl);
            return;
        }

        if ((frame.preq.flags & s_flag_destination_only) == 0) {
            const Route* target_route = _find_route(frame.preq.target);
            if (target_route != nullptr && target_route->destination_seq >= frame.preq.target_seq) {
                _send_prep(frame.preq.originator, frame.preq.target, target_route->destination_seq, target_route->metric,
                           m_config.ttl);
                return;
            }
        }

        if (frame.preq.ttl == 0)
            return;

        PreqFrame forwarded = frame.preq;
        forwarded.ttl--;
        forwarded.metric = metric;
        _broadcast_frame(_encode_preq(forwarded));
    }

    void _handle_prep(const Address& previous_hop, const DecodedFrame& frame) {
        const std::uint32_t metric = _saturating_inc(frame.prep.metric);
        _update_route(frame.prep.target, previous_hop, frame.prep.target_seq, metric);

        if (frame.prep.originator == my_address()) {
            _flush_pending(frame.prep.target);
            return;
        }

        if (frame.prep.ttl == 0)
            return;

        const Route* reverse_route = _find_route(frame.prep.originator);
        if (reverse_route == nullptr)
            return;

        PrepFrame forwarded = frame.prep;
        forwarded.ttl--;
        forwarded.metric = metric;
        _unicast_frame(reverse_route->next_hop, _encode_prep(forwarded));
    }

    void _handle_perr(const Address& previous_hop, const DecodedFrame& frame) {
        if (!_remember_perr(frame.perr.destination, frame.perr.destination_seq))
            return;

        typename std::map<Address, Route>::iterator it = m_routes.find(frame.perr.destination);
        bool should_rebroadcast = false;
        if (it != m_routes.end() && it->second.next_hop == previous_hop
            && it->second.destination_seq <= frame.perr.destination_seq) {
            should_rebroadcast = _route_is_usable(it->second, ClockT::now());
            it->second.valid = false;
        }

        m_pending_preqs.erase(frame.perr.destination);
        if (m_pending_packets.find(frame.perr.destination) != m_pending_packets.end()) {
            should_rebroadcast = true;
            _send_or_retry_preq(frame.perr.destination);
        }

        if (should_rebroadcast) {
            _broadcast_frame(_encode_perr(frame.perr));
        }
    }
};

} // namespace bricks::disnet
