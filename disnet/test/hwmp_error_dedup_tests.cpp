#include "support/hwmp_test_support.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <vector>

namespace {

using namespace std::chrono_literals;
using bricks::disnet::Hwmp;
using bricks::disnet::TransportPacket;
using bricks::disnet::test::FakeAddress;
using bricks::disnet::test::FakeClock;
using bricks::disnet::test::FakeTransport;
using bricks::disnet::test::HwmpFrameType;
using bricks::disnet::test::count_frames;
using bricks::disnet::test::data_payload;
using bricks::disnet::test::data_ttl;
using bricks::disnet::test::encode_data;
using bricks::disnet::test::encode_perr;
using bricks::disnet::test::encode_prep;
using bricks::disnet::test::encode_preq;
using bricks::disnet::test::frame_type;
using bricks::disnet::test::run_test;

using Router = Hwmp<FakeTransport, FakeClock>;

Router make_router(FakeTransport& transport, Router::Config config = {}) {
    return Router(transport, config);
}

std::uint32_t perr_destination_seq(const TransportPacket<FakeAddress>& packet) {
    std::size_t offset = sizeof(HwmpFrameType) + sizeof(FakeAddress);
    return bricks::disnet::test::read_bytes<std::uint32_t>(packet.payload, offset);
}

FakeAddress perr_destination(const TransportPacket<FakeAddress>& packet) {
    std::size_t offset = sizeof(HwmpFrameType);
    return bricks::disnet::test::read_bytes<FakeAddress>(packet.payload, offset);
}

void test_duplicate_data_is_suppressed() {
    FakeTransport transport(FakeAddress{1});
    auto router = make_router(transport);

    std::vector<std::vector<std::uint8_t>> delivered;
    router.register_callback([&](TransportPacket<FakeAddress> packet) {
        delivered.push_back(std::move(packet.payload));
    });

    const auto packet = TransportPacket<FakeAddress>{
        .source = FakeAddress{7},
        .target = transport.my_address(),
        .source_seq = 42,
        .payload = encode_data(FakeAddress{7}, transport.my_address(), 42, {0xCA, 0xFE}),
    };

    router.handle_packet(packet);
    router.handle_packet(packet);

    assert(delivered.size() == 1);
    assert((delivered.front() == std::vector<std::uint8_t>{0xCA, 0xFE}));
    assert(transport.sent.empty());
}

void test_preq_dedup_allows_improved_metric() {
    FakeTransport transport(FakeAddress{1});
    auto router = make_router(transport, {
                                             .ttl = 4,
                                             .proactive_ttl = 6,
                                             .root = false,
                                             .intermediate_replies = true,
                                             .max_pending_per_destination = 4,
                                             .max_pending_total = 8,
                                             .route_lifetime = 16ms,
                                         });

    router.handle_packet({
        .source = FakeAddress{6},
        .target = transport.my_address(),
        .source_seq = 1,
        .payload = encode_prep(transport.my_address(), FakeAddress{9}, 9, 0),
    });

    router.handle_packet({
        .source = FakeAddress{2},
        .target = transport.broadcast_address(),
        .source_seq = 10,
        .payload = encode_preq(FakeAddress{7}, 77, FakeAddress{9}, 3, 0, 5),
    });
    assert(count_frames(transport.sent, HwmpFrameType::Prep) == 1);
    assert(transport.sent.back().target == FakeAddress{2});

    router.handle_packet({
        .source = FakeAddress{3},
        .target = transport.broadcast_address(),
        .source_seq = 11,
        .payload = encode_preq(FakeAddress{7}, 77, FakeAddress{9}, 3, 0, 5),
    });
    assert(count_frames(transport.sent, HwmpFrameType::Prep) == 1);

    router.handle_packet({
        .source = FakeAddress{4},
        .target = transport.broadcast_address(),
        .source_seq = 12,
        .payload = encode_preq(FakeAddress{7}, 77, FakeAddress{9}, 3, 0, 6),
    });
    assert(count_frames(transport.sent, HwmpFrameType::Prep) == 1);

    router.handle_packet({
        .source = FakeAddress{5},
        .target = transport.broadcast_address(),
        .source_seq = 13,
        .payload = encode_preq(FakeAddress{7}, 77, FakeAddress{9}, 3, 0, 4),
    });
    assert(count_frames(transport.sent, HwmpFrameType::Prep) == 2);
    assert(transport.sent.back().target == FakeAddress{5});
}

void test_duplicate_perr_is_suppressed() {
    FakeTransport transport(FakeAddress{1});
    auto router = make_router(transport, {
                                             .ttl = 4,
                                             .proactive_ttl = 6,
                                             .root = false,
                                             .intermediate_replies = true,
                                             .max_pending_per_destination = 4,
                                             .max_pending_total = 8,
                                             .route_lifetime = 16ms,
                                         });

    router.handle_packet({
        .source = FakeAddress{2},
        .target = transport.my_address(),
        .source_seq = 1,
        .payload = encode_prep(transport.my_address(), FakeAddress{9}, 5, 0),
    });
    transport.sent.clear();

    const auto perr = TransportPacket<FakeAddress>{
        .source = FakeAddress{2},
        .target = transport.broadcast_address(),
        .source_seq = 20,
        .payload = encode_perr(FakeAddress{9}, 5),
    };

    router.handle_packet(perr);
    router.handle_packet(perr);

    assert(count_frames(transport.sent, HwmpFrameType::Perr) == 1);
    assert(perr_destination(find_nth_frame(transport.sent, HwmpFrameType::Perr)) == FakeAddress{9});
    assert(perr_destination_seq(find_nth_frame(transport.sent, HwmpFrameType::Perr)) == 5);
}

void test_perr_from_non_active_next_hop_does_not_invalidate_route() {
    FakeTransport transport(FakeAddress{1});
    auto router = make_router(transport, {
                                             .ttl = 4,
                                             .proactive_ttl = 6,
                                             .root = false,
                                             .intermediate_replies = true,
                                             .max_pending_per_destination = 4,
                                             .max_pending_total = 8,
                                             .route_lifetime = 16ms,
                                         });

    router.handle_packet({
        .source = FakeAddress{2},
        .target = transport.my_address(),
        .source_seq = 1,
        .payload = encode_prep(transport.my_address(), FakeAddress{9}, 5, 0),
    });
    transport.sent.clear();

    router.handle_packet({
        .source = FakeAddress{3},
        .target = transport.broadcast_address(),
        .source_seq = 20,
        .payload = encode_perr(FakeAddress{9}, 5),
    });

    assert(transport.sent.empty());

    router.send({
        .source = {},
        .target = FakeAddress{9},
        .source_seq = 0,
        .payload = {0x11},
    });

    assert(transport.sent.size() == 1);
    assert(frame_type(transport.sent.front()) == HwmpFrameType::Data);
    assert(transport.sent.front().target == FakeAddress{2});
}

void test_local_invalidate_route_rebroadcasts_once() {
    FakeTransport transport(FakeAddress{1});
    auto router = make_router(transport, {
                                             .ttl = 4,
                                             .proactive_ttl = 6,
                                             .root = false,
                                             .intermediate_replies = true,
                                             .max_pending_per_destination = 4,
                                             .max_pending_total = 8,
                                             .route_lifetime = 16ms,
                                         });

    router.handle_packet({
        .source = FakeAddress{2},
        .target = transport.my_address(),
        .source_seq = 1,
        .payload = encode_prep(transport.my_address(), FakeAddress{9}, 5, 0),
    });
    transport.sent.clear();

    router.invalidate_route(FakeAddress{9});

    assert(transport.sent.size() == 1);
    assert(frame_type(transport.sent.front()) == HwmpFrameType::Perr);
    assert(perr_destination(transport.sent.front()) == FakeAddress{9});
    assert(perr_destination_seq(transport.sent.front()) == 5);
}

void test_pending_packets_survive_perr_and_flush_after_later_prep() {
    FakeClock::reset();

    FakeTransport transport(FakeAddress{1});
    auto router = make_router(transport, {
                                             .ttl = 4,
                                             .proactive_ttl = 6,
                                             .root = false,
                                             .intermediate_replies = true,
                                             .max_pending_per_destination = 4,
                                             .max_pending_total = 8,
                                             .route_lifetime = 16ms,
                                             .discovery_retry_interval = 2ms,
                                         });

    FakeClock::advance(1ms);
    router.send({
        .source = {},
        .target = FakeAddress{9},
        .source_seq = 0,
        .payload = {0xA1},
    });

    FakeClock::advance(1ms);
    router.send({
        .source = {},
        .target = FakeAddress{9},
        .source_seq = 0,
        .payload = {0xA2},
    });
    assert(count_frames(transport.sent, HwmpFrameType::Preq) == 1);

    FakeClock::advance(8ms);
    router.handle_packet({
        .source = FakeAddress{2},
        .target = transport.broadcast_address(),
        .source_seq = 99,
        .payload = encode_perr(FakeAddress{9}, 1),
    });
    assert(count_frames(transport.sent, HwmpFrameType::Preq) == 2);

    router.handle_packet({
        .source = FakeAddress{3},
        .target = transport.my_address(),
        .source_seq = 100,
        .payload = encode_prep(transport.my_address(), FakeAddress{9}, 7, 0),
    });

    std::vector<const TransportPacket<FakeAddress>*> data_frames;
    for (const auto& packet : transport.sent) {
        if (frame_type(packet) == HwmpFrameType::Data)
            data_frames.push_back(&packet);
    }

    assert(data_frames.size() == 2);
    assert((data_payload(*data_frames[0]) == std::vector<std::uint8_t>{0xA1}));
    assert((data_payload(*data_frames[1]) == std::vector<std::uint8_t>{0xA2}));
    assert(data_ttl(*data_frames[0]) == 4);
    assert(data_ttl(*data_frames[1]) == 4);
}

} // namespace

int main() {
    run_test(test_duplicate_data_is_suppressed);
    run_test(test_preq_dedup_allows_improved_metric);
    run_test(test_duplicate_perr_is_suppressed);
    run_test(test_perr_from_non_active_next_hop_does_not_invalidate_route);
    run_test(test_local_invalidate_route_rebroadcasts_once);
    run_test(test_pending_packets_survive_perr_and_flush_after_later_prep);
}
