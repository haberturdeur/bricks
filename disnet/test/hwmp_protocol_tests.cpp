#include "support/hwmp_test_support.hpp"

#include <chrono>
#include <cassert>
#include <cstdint>
#include <vector>
#include <utility>

namespace {

using namespace bricks::disnet::test;
using namespace std::chrono_literals;
using bricks::disnet::TransportPacket;

std::vector<std::uint8_t> short_frame(HwmpFrameType type) {
    return {static_cast<std::uint8_t>(type)};
}

template <typename Fn>
void with_router(Fn&& fn) {
    run_test(std::forward<Fn>(fn));
}

template <typename RouterT>
void install_route_to(RouterT& router, FakeTransport& transport, FakeAddress destination, FakeAddress next_hop,
                      std::uint32_t target_seq = 7, std::uint32_t metric = 0) {
    router.handle_packet({
        .source = next_hop,
        .target = transport.my_address(),
        .source_seq = 100,
        .payload = encode_prep(transport.my_address(), destination, target_seq, metric),
    });
}

void test_handle_packet_rejects_short_frames() {
    with_router([] {
        FakeTransport transport(FakeAddress{1});
        bricks::disnet::Hwmp<FakeTransport> router(transport);
        std::vector<std::vector<std::uint8_t>> delivered;
        router.register_callback([&](TransportPacket<FakeAddress> packet) {
            delivered.push_back(std::move(packet.payload));
        });

        router.handle_packet({
            .source = FakeAddress{2},
            .target = transport.broadcast_address(),
            .source_seq = 1,
            .payload = short_frame(HwmpFrameType::Data),
        });
        router.handle_packet({
            .source = FakeAddress{2},
            .target = transport.broadcast_address(),
            .source_seq = 2,
            .payload = short_frame(HwmpFrameType::Preq),
        });
        router.handle_packet({
            .source = FakeAddress{2},
            .target = transport.broadcast_address(),
            .source_seq = 3,
            .payload = short_frame(HwmpFrameType::Prep),
        });
        router.handle_packet({
            .source = FakeAddress{2},
            .target = transport.broadcast_address(),
            .source_seq = 4,
            .payload = short_frame(HwmpFrameType::Perr),
        });

        assert(transport.sent.empty());
        assert(delivered.empty());
    });
}

void test_handle_packet_ignores_self_originated_packets() {
    with_router([] {
        FakeTransport transport(FakeAddress{1});
        bricks::disnet::Hwmp<FakeTransport> router(transport);
        std::vector<std::vector<std::uint8_t>> delivered;
        router.register_callback([&](TransportPacket<FakeAddress> packet) {
            delivered.push_back(std::move(packet.payload));
        });

        router.handle_packet({
            .source = transport.my_address(),
            .target = transport.broadcast_address(),
            .source_seq = 7,
            .payload = encode_data(FakeAddress{9}, transport.broadcast_address(), 42, {0xAB, 0xCD}),
        });

        assert(transport.sent.empty());
        assert(delivered.empty());
    });
}

void test_unicast_data_forwarding_uses_route_and_decrements_ttl() {
    with_router([] {
        FakeTransport transport(FakeAddress{1});
        bricks::disnet::Hwmp<FakeTransport> router(transport, {
                                                                      .ttl = 6,
                                                                      .proactive_ttl = 6,
                                                                      .root = false,
                                                                      .intermediate_replies = true,
                                                                      .max_pending_per_destination = 4,
                                                                      .max_pending_total = 8,
                                                                      .route_lifetime = 32ms,
                                                                  });
        install_route_to(router, transport, FakeAddress{9}, FakeAddress{2});
        transport.sent.clear();

        std::vector<std::vector<std::uint8_t>> delivered;
        router.register_callback([&](TransportPacket<FakeAddress> packet) {
            delivered.push_back(std::move(packet.payload));
        });

        router.handle_packet({
            .source = FakeAddress{3},
            .target = FakeAddress{1},
            .source_seq = 12,
            .payload = encode_data(FakeAddress{7}, FakeAddress{9}, 99, {0x11, 0x22, 0x33}, 4),
        });

        assert(delivered.empty());
        assert(transport.sent.size() == 1);
        const auto& forwarded = transport.sent.front();
        assert(forwarded.target == FakeAddress{2});
        assert(frame_type(forwarded) == HwmpFrameType::Data);
        assert(data_ttl(forwarded) == 3);
        assert((data_payload(forwarded) == std::vector<std::uint8_t>{0x11, 0x22, 0x33}));
    });
}

void test_broadcast_data_rebroadcasts_with_decremented_ttl() {
    with_router([] {
        FakeTransport transport(FakeAddress{1});
        bricks::disnet::Hwmp<FakeTransport> router(transport);
        std::vector<TransportPacket<FakeAddress>> delivered;
        router.register_callback([&](TransportPacket<FakeAddress> packet) {
            delivered.push_back(std::move(packet));
        });

        router.handle_packet({
            .source = FakeAddress{2},
            .target = FakeAddress{1},
            .source_seq = 5,
            .payload = encode_data(FakeAddress{7}, transport.broadcast_address(), 13, {0x44, 0x55}, 4),
        });

        assert(delivered.size() == 1);
        assert(transport.sent.size() == 1);
        const auto& rebroadcast = transport.sent.front();
        assert(rebroadcast.target == transport.broadcast_address());
        assert(frame_type(rebroadcast) == HwmpFrameType::Data);
        assert(data_ttl(rebroadcast) == 3);
        assert((data_payload(rebroadcast) == std::vector<std::uint8_t>{0x44, 0x55}));
    });
}

void test_ttl_zero_broadcast_data_delivers_locally_without_forwarding() {
    with_router([] {
        FakeTransport transport(FakeAddress{1});
        bricks::disnet::Hwmp<FakeTransport> router(transport);
        std::vector<std::vector<std::uint8_t>> delivered;
        router.register_callback([&](TransportPacket<FakeAddress> packet) {
            delivered.push_back(std::move(packet.payload));
        });

        router.handle_packet({
            .source = FakeAddress{2},
            .target = FakeAddress{1},
            .source_seq = 6,
            .payload = encode_data(FakeAddress{8}, transport.broadcast_address(), 14, {0x66}, 0),
        });

        assert(delivered.size() == 1);
        assert(transport.sent.empty());
        assert((delivered.front() == std::vector<std::uint8_t>{0x66}));
    });
}

void test_data_for_other_target_is_not_delivered_but_is_forwarded() {
    with_router([] {
        FakeTransport transport(FakeAddress{1});
        bricks::disnet::Hwmp<FakeTransport> router(transport, {
                                                                      .ttl = 6,
                                                                      .proactive_ttl = 6,
                                                                      .root = false,
                                                                      .intermediate_replies = true,
                                                                      .max_pending_per_destination = 4,
                                                                      .max_pending_total = 8,
                                                                      .route_lifetime = 32ms,
                                                                  });
        install_route_to(router, transport, FakeAddress{9}, FakeAddress{2});
        transport.sent.clear();

        std::vector<std::vector<std::uint8_t>> delivered;
        router.register_callback([&](TransportPacket<FakeAddress> packet) {
            delivered.push_back(std::move(packet.payload));
        });

        router.handle_packet({
            .source = FakeAddress{3},
            .target = FakeAddress{1},
            .source_seq = 7,
            .payload = encode_data(FakeAddress{7}, FakeAddress{9}, 15, {0x77}, 4),
        });

        assert(delivered.empty());
        assert(transport.sent.size() == 1);
        const auto& forwarded = transport.sent.front();
        assert(forwarded.target == FakeAddress{2});
        assert(frame_type(forwarded) == HwmpFrameType::Data);
        assert(data_ttl(forwarded) == 3);
    });
}

void test_data_for_self_is_delivered_and_not_forwarded() {
    with_router([] {
        FakeTransport transport(FakeAddress{1});
        bricks::disnet::Hwmp<FakeTransport> router(transport);
        std::vector<std::vector<std::uint8_t>> delivered;
        router.register_callback([&](TransportPacket<FakeAddress> packet) {
            delivered.push_back(std::move(packet.payload));
        });

        router.handle_packet({
            .source = FakeAddress{2},
            .target = FakeAddress{1},
            .source_seq = 8,
            .payload = encode_data(FakeAddress{7}, transport.my_address(), 16, {0x88, 0x99}, 0),
        });

        assert(delivered.size() == 1);
        assert(transport.sent.empty());
        assert((delivered.front() == std::vector<std::uint8_t>{0x88, 0x99}));
    });
}

void test_preq_flags_reflect_intermediate_replies_true() {
    with_router([] {
        FakeTransport transport(FakeAddress{1});
        bricks::disnet::Hwmp<FakeTransport> router(transport, {
                                                                      .ttl = 6,
                                                                      .proactive_ttl = 6,
                                                                      .root = false,
                                                                      .intermediate_replies = true,
                                                                      .max_pending_per_destination = 4,
                                                                      .max_pending_total = 8,
                                                                      .route_lifetime = 32ms,
                                                                  });

        router.send({
            .source = {},
            .target = FakeAddress{9},
            .source_seq = 0,
            .payload = {0xA1},
        });

        assert(transport.sent.size() == 1);
        assert(frame_type(transport.sent.front()) == HwmpFrameType::Preq);
        assert(preq_flags(transport.sent.front()) == 0);
    });
}

void test_preq_flags_reflect_intermediate_replies_false() {
    with_router([] {
        FakeTransport transport(FakeAddress{1});
        bricks::disnet::Hwmp<FakeTransport> router(transport, {
                                                                      .ttl = 6,
                                                                      .proactive_ttl = 6,
                                                                      .root = false,
                                                                      .intermediate_replies = false,
                                                                      .max_pending_per_destination = 4,
                                                                      .max_pending_total = 8,
                                                                      .route_lifetime = 32ms,
                                                                  });

        router.send({
            .source = {},
            .target = FakeAddress{9},
            .source_seq = 0,
            .payload = {0xA2},
        });

        assert(transport.sent.size() == 1);
        assert(frame_type(transport.sent.front()) == HwmpFrameType::Preq);
        assert(preq_flags(transport.sent.front()) == 2);
    });
}

} // namespace

int main() {
    test_handle_packet_rejects_short_frames();
    test_handle_packet_ignores_self_originated_packets();
    test_unicast_data_forwarding_uses_route_and_decrements_ttl();
    test_broadcast_data_rebroadcasts_with_decremented_ttl();
    test_ttl_zero_broadcast_data_delivers_locally_without_forwarding();
    test_data_for_other_target_is_not_delivered_but_is_forwarded();
    test_data_for_self_is_delivered_and_not_forwarded();
    test_preq_flags_reflect_intermediate_replies_true();
    test_preq_flags_reflect_intermediate_replies_false();
}
