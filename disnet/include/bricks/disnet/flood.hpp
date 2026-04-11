#pragma once

#include "bricks/disnet.hpp"

#include <cstring>
#include <deque>
#include <mutex>
#include <utility>

namespace bricks::disnet {

template <Transport TransportT>
class Flood {
public:
    struct Config {
        std::uint8_t ttl = 15;
    };
    static constexpr std::size_t s_header_size = sizeof(std::uint8_t);

    using Transport = TransportT;
    using Address = typename Transport::Address;
    static constexpr std::size_t max_payload_size = Transport::max_payload_size - s_header_size;
    static_assert(Transport::max_payload_size > s_header_size,
                  "Transport::max_payload_size is too small to hold a Flood packet");

    static Address broadcast_address() {
        return Transport::broadcast_address();
    }

    explicit Flood(Transport& transport, Config config = {}) : m_transport(transport), m_config(config) {}

    Address my_address() const {
        return m_transport.my_address();
    }

    void send(TransportPacket<Address> packet) {
        if (packet.payload.size() > max_payload_size)
            return;

        TransportPacket<Address> to_send{
            .source = my_address(),
            .target = packet.target,
            .source_seq = 0,
            .payload = _encode_payload(m_config.ttl, packet.payload),
        };

        {
            std::lock_guard lock(m_mutex);
            to_send.source_seq = m_source_seq++;
        }

        m_transport.send(std::move(to_send));
    }

    void handle_packet(const TransportPacket<Address>& packet) {
        bool should_forward = false;
        bool should_deliver = false;
        TransportPacket<Address> forwarded;
        TransportPacket<Address> delivered;
        TransportReceiveCallback<Address> cb;

        {
            std::lock_guard lock(m_mutex);

            DecodedPayload decoded;
            if (!_decode_payload(packet.payload, decoded))
                return;
            if (packet.source == m_transport.my_address())
                return;
            if (_check_seen_and_mark(packet.source, packet.source_seq))
                return;

            if (_should_forward(packet.target, decoded.ttl)) {
                forwarded = packet;
                forwarded.payload = _encode_payload(static_cast<std::uint8_t>(decoded.ttl - 1), decoded.payload);
                should_forward = true;
            }

            if (_should_deliver_locally(packet.target)) {
                delivered = TransportPacket<Address>{
                    .source = packet.source,
                    .target = packet.target,
                    .source_seq = packet.source_seq,
                    .payload = std::move(decoded.payload),
                };
                should_deliver = true;
            }

            cb = m_callback;
        }

        if (should_forward)
            m_transport.send(std::move(forwarded));
        if (should_deliver && cb)
            cb(std::move(delivered));
    }

    void register_callback(TransportReceiveCallback<Address> callback) {
        std::lock_guard lock(m_mutex);
        m_callback = std::move(callback);
    }

private:
    static constexpr std::size_t s_dedupe_capacity = 100;

    using PacketId = std::pair<Address, std::uint32_t>;
    struct DecodedPayload {
        std::uint8_t ttl = 0;
        std::vector<std::uint8_t> payload;
    };

    Transport& m_transport;
    Config m_config;
    TransportReceiveCallback<Address> m_callback;
    std::deque<PacketId> m_seen_packets;
    std::uint32_t m_source_seq = 0;
    mutable std::mutex m_mutex;

    static std::vector<std::uint8_t> _encode_payload(std::uint8_t ttl, const std::vector<std::uint8_t>& payload) {
        std::vector<std::uint8_t> encoded(s_header_size + payload.size());
        encoded[0] = ttl;
        if (!payload.empty()) {
            std::memcpy(encoded.data() + s_header_size, payload.data(), payload.size());
        }
        return encoded;
    }

    static bool _decode_payload(const std::vector<std::uint8_t>& encoded, DecodedPayload& decoded) {
        if (encoded.size() < s_header_size)
            return false;
        decoded.ttl = encoded[0];
        decoded.payload.assign(encoded.begin() + static_cast<std::ptrdiff_t>(s_header_size), encoded.end());
        return true;
    }

    bool _is_broadcast(const Address& target) const {
        return target == Transport::broadcast_address();
    }

    bool _should_deliver_locally(const Address& target) const {
        return target == my_address() || _is_broadcast(target);
    }

    bool _should_forward(const Address& target, std::uint8_t ttl) const {
        return ttl > 0 && target != my_address();
    }

    bool _check_seen_and_mark(const Address& source, std::uint32_t source_seq) {
        const PacketId id{source, source_seq};
        for (const PacketId& seen : m_seen_packets) {
            if (seen == id)
                return true;
        }

        if (m_seen_packets.size() >= s_dedupe_capacity)
            m_seen_packets.pop_front();
        m_seen_packets.push_back(id);
        return false;
    }
};

} // namespace bricks::disnet
