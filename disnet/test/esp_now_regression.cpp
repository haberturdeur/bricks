#include "bricks/disnet/esp_now.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

namespace {

std::vector<std::uint8_t> make_frame(const bricks::disnet::MacAddress& payload_source,
                                     const bricks::disnet::MacAddress& payload_target, std::uint32_t source_seq,
                                     const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> frame(2 * 6 + sizeof(source_seq) + payload.size());
    std::memcpy(frame.data(), payload_source.data(), 6);
    std::memcpy(frame.data() + 6, payload_target.data(), 6);
    std::memcpy(frame.data() + 12, &source_seq, sizeof(source_seq));
    if (!payload.empty())
        std::memcpy(frame.data() + 16, payload.data(), payload.size());
    return frame;
}

void test_receive_uses_radio_source_not_payload_source() {
    using bricks::disnet::TransportPacket;
    using bricks::disnet::esp_now::EspNow;

    EspNow& transport = EspNow::singleton();
    std::optional<TransportPacket<EspNow::Address>> received;
    transport.register_callback([&](TransportPacket<EspNow::Address> packet) { received = std::move(packet); });

    const EspNow::Address radio_source{{0x10, 0x11, 0x12, 0x13, 0x14, 0x15}};
    const EspNow::Address payload_source{{0x20, 0x21, 0x22, 0x23, 0x24, 0x25}};
    const EspNow::Address target{{0x30, 0x31, 0x32, 0x33, 0x34, 0x35}};
    const auto frame = make_frame(payload_source, target, 77, {1, 2, 3});

    const esp_now_recv_info_t info{.src_addr = radio_source.data()};
    transport.handle_receive(&info, frame.data(), static_cast<int>(frame.size()));

    assert(received.has_value());
    assert(received->source == radio_source);
    assert(received->target == target);
    assert(received->source_seq == 77);
    assert((received->payload == std::vector<std::uint8_t>{1, 2, 3}));
}

void test_send_uses_packet_target_as_radio_peer() {
    using bricks::disnet::TransportPacket;
    using bricks::disnet::esp_now::EspNow;

    EspNow& transport = EspNow::singleton();
    const EspNow::Address source{{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}};
    const EspNow::Address target{{0x10, 0x11, 0x12, 0x13, 0x14, 0x15}};

    g_last_send_peer = nullptr;
    g_last_send_data = nullptr;
    g_last_send_len = 0;

    transport.send(TransportPacket<EspNow::Address>{
        .source = source,
        .target = target,
        .source_seq = 9,
        .payload = {0xAA, 0xBB},
    });

    assert(g_last_send_peer != nullptr);
    assert(std::memcmp(g_last_send_peer, target.data(), 6) == 0);
}

} // namespace

int main() {
    test_receive_uses_radio_source_not_payload_source();
    test_send_uses_packet_target_as_radio_peer();
}
