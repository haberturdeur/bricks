#include "support/hwmp_test_support.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <vector>

namespace {

using namespace bricks::disnet::test;
using namespace std::chrono_literals;

using Router = bricks::disnet::Hwmp<FakeTransport, FakeClock>;
using Packet = bricks::disnet::TransportPacket<FakeAddress>;

template <typename RouterConfigT = Router::Config>
Router make_router(FakeTransport& transport, RouterConfigT config = {}) {
    return Router(transport, config);
}

void install_route(bricks::disnet::Hwmp<FakeTransport, FakeClock>& router, FakeAddress previous_hop,
                   FakeAddress destination, std::uint32_t target_seq, std::uint32_t metric) {
    router.handle_packet({
        .source = previous_hop,
        .target = FakeTransport::broadcast_address(),
        .source_seq = 100,
        .payload = encode_prep(router.my_address(), destination, target_seq, metric),
    });
}

const Packet& only_data_packet(const std::vector<Packet>& packets) {
    return find_nth_frame(packets, HwmpFrameType::Data, 0);
}

void test_newer_destination_sequence_wins() {
    run_test([] {
        FakeTransport transport(FakeAddress{1});
        auto router = make_router(transport, {
                                                   .ttl = 7,
                                                   .proactive_ttl = 11,
                                                   .root = false,
                                                   .intermediate_replies = true,
                                                   .max_pending_per_destination = 4,
                                                   .max_pending_total = 8,
                                                   .route_lifetime = 32ms,
                                                   .discovery_retry_interval = 2ms,
                                               });

        install_route(router, FakeAddress{2}, FakeAddress{9}, 5, 20);
        install_route(router, FakeAddress{3}, FakeAddress{9}, 6, 50);

        transport.sent.clear();
        router.send({
            .source = {},
            .target = FakeAddress{9},
            .source_seq = 0,
            .payload = {0xAA},
        });

        assert(transport.sent.size() == 1);
        assert(frame_type(only_data_packet(transport.sent)) == HwmpFrameType::Data);
        assert(only_data_packet(transport.sent).target == FakeAddress{3});
        assert((data_payload(only_data_packet(transport.sent)) == std::vector<std::uint8_t>{0xAA}));
    });
}

void test_same_destination_sequence_lower_metric_wins() {
    run_test([] {
        FakeTransport transport(FakeAddress{1});
        auto router = make_router(transport, {
                                                   .ttl = 7,
                                                   .proactive_ttl = 11,
                                                   .root = false,
                                                   .intermediate_replies = true,
                                                   .max_pending_per_destination = 4,
                                                   .max_pending_total = 8,
                                                   .route_lifetime = 32ms,
                                                   .discovery_retry_interval = 2ms,
                                               });

        install_route(router, FakeAddress{2}, FakeAddress{9}, 6, 20);
        install_route(router, FakeAddress{3}, FakeAddress{9}, 6, 5);

        transport.sent.clear();
        router.send({
            .source = {},
            .target = FakeAddress{9},
            .source_seq = 0,
            .payload = {0xBB},
        });

        assert(transport.sent.size() == 1);
        assert(only_data_packet(transport.sent).target == FakeAddress{3});
        assert((data_payload(only_data_packet(transport.sent)) == std::vector<std::uint8_t>{0xBB}));
    });
}

void test_older_or_worse_route_is_ignored() {
    run_test([] {
        FakeTransport transport(FakeAddress{1});
        auto router = make_router(transport, {
                                                   .ttl = 7,
                                                   .proactive_ttl = 11,
                                                   .root = false,
                                                   .intermediate_replies = true,
                                                   .max_pending_per_destination = 4,
                                                   .max_pending_total = 8,
                                                   .route_lifetime = 32ms,
                                                   .discovery_retry_interval = 2ms,
                                               });

        install_route(router, FakeAddress{2}, FakeAddress{9}, 6, 20);
        install_route(router, FakeAddress{3}, FakeAddress{9}, 5, 1);
        install_route(router, FakeAddress{4}, FakeAddress{9}, 6, 50);

        transport.sent.clear();
        router.send({
            .source = {},
            .target = FakeAddress{9},
            .source_seq = 0,
            .payload = {0xCC},
        });

        assert(transport.sent.size() == 1);
        assert(only_data_packet(transport.sent).target == FakeAddress{2});
        assert((data_payload(only_data_packet(transport.sent)) == std::vector<std::uint8_t>{0xCC}));
    });
}

void test_stale_route_cannot_forward_data() {
    run_test([] {
        FakeTransport transport(FakeAddress{1});
        auto router = make_router(transport, {
                                                   .ttl = 4,
                                                   .proactive_ttl = 11,
                                                   .root = false,
                                                   .intermediate_replies = true,
                                                   .max_pending_per_destination = 4,
                                                   .max_pending_total = 8,
                                                   .route_lifetime = 1ms,
                                                   .discovery_retry_interval = 1ms,
                                               });

        install_route(router, FakeAddress{2}, FakeAddress{9}, 7, 2);
        transport.sent.clear();

        FakeClock::advance(3ms);
        router.send({
            .source = {},
            .target = FakeAddress{9},
            .source_seq = 0,
            .payload = {0xDD},
        });

        assert(frame_type(transport.sent.front()) == HwmpFrameType::Preq);
        assert(count_frames(transport.sent, HwmpFrameType::Data) == 0);
        assert(preq_target(find_nth_frame(transport.sent, HwmpFrameType::Preq)) == FakeAddress{9});
    });
}

void test_stale_route_cannot_answer_preq() {
    run_test([] {
        FakeTransport transport(FakeAddress{1});
        auto router = make_router(transport, {
                                                   .ttl = 4,
                                                   .proactive_ttl = 11,
                                                   .root = false,
                                                   .intermediate_replies = true,
                                                   .max_pending_per_destination = 4,
                                                   .max_pending_total = 8,
                                                   .route_lifetime = 1ms,
                                                   .discovery_retry_interval = 1ms,
                                               });

        install_route(router, FakeAddress{2}, FakeAddress{9}, 7, 2);
        transport.sent.clear();

        FakeClock::advance(3ms);
        router.handle_packet({
            .source = FakeAddress{4},
            .target = FakeTransport::broadcast_address(),
            .source_seq = 11,
            .payload = encode_preq(FakeAddress{6}, 1, FakeAddress{9}, 3, 0, 0, 5, 0),
        });

        assert(count_frames(transport.sent, HwmpFrameType::Prep) == 0);
        assert(count_frames(transport.sent, HwmpFrameType::Preq) == 1);
        assert(preq_target(find_nth_frame(transport.sent, HwmpFrameType::Preq)) == FakeAddress{9});
    });
}

void test_preq_retry_respects_discovery_retry_interval() {
    run_test([] {
        FakeTransport transport(FakeAddress{1});
        auto router = make_router(transport, {
                                                   .ttl = 4,
                                                   .proactive_ttl = 11,
                                                   .root = false,
                                                   .intermediate_replies = true,
                                                   .max_pending_per_destination = 4,
                                                   .max_pending_total = 8,
                                                   .route_lifetime = 32ms,
                                                   .discovery_retry_interval = 5ms,
                                               });

        router.send({
            .source = {},
            .target = FakeAddress{9},
            .source_seq = 0,
            .payload = {0x11},
        });
        assert(count_frames(transport.sent, HwmpFrameType::Preq) == 1);

        FakeClock::advance(1ms);
        router.send({
            .source = {},
            .target = FakeAddress{9},
            .source_seq = 0,
            .payload = {0x22},
        });
        assert(count_frames(transport.sent, HwmpFrameType::Preq) == 1);

        FakeClock::advance(5ms);
        router.send({
            .source = {},
            .target = FakeAddress{9},
            .source_seq = 0,
            .payload = {0x33},
        });
        assert(count_frames(transport.sent, HwmpFrameType::Preq) == 2);
    });
}

void test_pending_packets_expire_before_late_prep() {
    run_test([] {
        FakeTransport transport(FakeAddress{1});
        auto router = make_router(transport, {
                                                   .ttl = 7,
                                                   .proactive_ttl = 11,
                                                   .root = false,
                                                   .intermediate_replies = true,
                                                   .max_pending_per_destination = 4,
                                                   .max_pending_total = 8,
                                                   .route_lifetime = 1ms,
                                                   .discovery_retry_interval = 1ms,
                                               });

        router.send({
            .source = {},
            .target = FakeAddress{9},
            .source_seq = 0,
            .payload = {0x44},
        });
        transport.sent.clear();

        FakeClock::advance(3ms);
        router.handle_packet({
            .source = FakeAddress{2},
            .target = FakeTransport::broadcast_address(),
            .source_seq = 7,
            .payload = encode_prep(router.my_address(), FakeAddress{9}, 12, 1),
        });

        assert(transport.sent.empty());
    });
}

void test_pending_flush_preserves_order_and_ttl() {
    run_test([] {
        FakeTransport transport(FakeAddress{1});
        auto router = make_router(transport, {
                                                   .ttl = 7,
                                                   .proactive_ttl = 11,
                                                   .root = false,
                                                   .intermediate_replies = true,
                                                   .max_pending_per_destination = 8,
                                                   .max_pending_total = 8,
                                                   .route_lifetime = 32ms,
                                                   .discovery_retry_interval = 1ms,
                                               });

        router.send({
            .source = {},
            .target = FakeAddress{9},
            .source_seq = 0,
            .payload = {0x01},
        });
        router.send({
            .source = {},
            .target = FakeAddress{9},
            .source_seq = 0,
            .payload = {0x02},
        });
        router.send({
            .source = {},
            .target = FakeAddress{9},
            .source_seq = 0,
            .payload = {0x03},
        });

        transport.sent.clear();
        router.handle_packet({
            .source = FakeAddress{2},
            .target = FakeTransport::broadcast_address(),
            .source_seq = 11,
            .payload = encode_prep(router.my_address(), FakeAddress{9}, 12, 1),
        });

        assert(count_frames(transport.sent, HwmpFrameType::Data) == 3);
        assert(frame_type(find_nth_frame(transport.sent, HwmpFrameType::Data, 0)) == HwmpFrameType::Data);
        assert(frame_type(find_nth_frame(transport.sent, HwmpFrameType::Data, 1)) == HwmpFrameType::Data);
        assert(frame_type(find_nth_frame(transport.sent, HwmpFrameType::Data, 2)) == HwmpFrameType::Data);
        assert(data_ttl(find_nth_frame(transport.sent, HwmpFrameType::Data, 0)) == 7);
        assert(data_ttl(find_nth_frame(transport.sent, HwmpFrameType::Data, 1)) == 7);
        assert(data_ttl(find_nth_frame(transport.sent, HwmpFrameType::Data, 2)) == 7);
        assert((data_payload(find_nth_frame(transport.sent, HwmpFrameType::Data, 0)) ==
                std::vector<std::uint8_t>{0x01}));
        assert((data_payload(find_nth_frame(transport.sent, HwmpFrameType::Data, 1)) ==
                std::vector<std::uint8_t>{0x02}));
        assert((data_payload(find_nth_frame(transport.sent, HwmpFrameType::Data, 2)) ==
                std::vector<std::uint8_t>{0x03}));
    });
}

} // namespace

int main() {
    test_newer_destination_sequence_wins();
    test_same_destination_sequence_lower_metric_wins();
    test_older_or_worse_route_is_ignored();
    test_stale_route_cannot_forward_data();
    test_stale_route_cannot_answer_preq();
    test_preq_retry_respects_discovery_retry_interval();
    test_pending_packets_expire_before_late_prep();
    test_pending_flush_preserves_order_and_ttl();
}
