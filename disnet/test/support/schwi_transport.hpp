#pragma once

#include "bricks/disnet.hpp"
#include "bricks/schwi.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <utility>
#include <vector>

namespace bricks::disnet::test {

struct SchwiAddress {
    std::uint8_t value = 0;

    auto operator<=>(const SchwiAddress&) const = default;
};

class SchwiTransport {
public:
    using Address = SchwiAddress;
    static constexpr std::size_t max_payload_size = 256;

    explicit SchwiTransport(Address self) : m_self(self) {}

    static constexpr Address broadcast_address() {
        return Address{0xFF};
    }

    Address my_address() const {
        return m_self;
    }

    void bind(bricks::schwi::Context& ctx) {
        m_ctx = &ctx;
    }

    void send(TransportPacket<Address> packet) {
        assert(m_ctx != nullptr);

        std::vector<std::byte> payload(k_header_size + packet.payload.size());
        payload[0] = static_cast<std::byte>(packet.source.value);
        payload[1] = static_cast<std::byte>(packet.target.value);
        std::memcpy(payload.data() + 2, &packet.source_seq, sizeof(packet.source_seq));
        if (!packet.payload.empty()) {
            std::memcpy(payload.data() + k_header_size, packet.payload.data(), packet.payload.size());
        }

        m_ctx->broadcast(std::move(payload));
    }

    void register_callback(TransportReceiveCallback<Address> callback) {
        m_callback = std::move(callback);
    }

    void handle_radio_receive(const std::vector<std::byte>& payload) const {
        if (!m_callback || payload.size() < k_header_size) {
            return;
        }

        TransportPacket<Address> packet{
            .source = Address{static_cast<std::uint8_t>(payload[0])},
            .target = Address{static_cast<std::uint8_t>(payload[1])},
            .source_seq = 0,
            .payload = {},
        };
        std::memcpy(&packet.source_seq, payload.data() + 2, sizeof(packet.source_seq));
        packet.payload.resize(payload.size() - k_header_size);
        if (!packet.payload.empty()) {
            std::memcpy(packet.payload.data(), payload.data() + k_header_size, packet.payload.size());
        }

        m_callback(std::move(packet));
    }

private:
    static constexpr std::size_t k_header_size = 2 + sizeof(std::uint32_t);

    Address m_self{};
    bricks::schwi::Context* m_ctx = nullptr;
    TransportReceiveCallback<Address> m_callback;
};

static_assert(Transport<SchwiTransport>);

} // namespace bricks::disnet::test
