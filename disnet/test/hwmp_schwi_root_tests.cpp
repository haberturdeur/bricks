#include "support/hwmp_schwi_test_support.hpp"

#include <cassert>
#include <chrono>
#include <cstdint>
#include <vector>

namespace {

using namespace std::chrono_literals;
using bricks::disnet::test::HwmpFrameType;
using bricks::disnet::test::InjectPacket;
using bricks::disnet::test::RouterNode;
using bricks::disnet::test::SchwiAddress;
using bricks::disnet::test::SchwiTransport;
using bricks::disnet::test::SendPacket;
using bricks::disnet::test::count_frames;
using bricks::disnet::test::frame_ttl;
using bricks::disnet::test::frame_type;
using bricks::disnet::test::make_line_simulation;
using bricks::disnet::test::read_bytes;
using bricks::disnet::test::preq_flags;

using Router = bricks::disnet::Hwmp<SchwiTransport>;

struct AnnounceRoot {};
struct ClearObservations {};

template <typename RouterT>
auto make_root_router_class(bricks::schwi::Simulation& sim, typename RouterT::Config config = {}) {
    auto factory = [next_address = std::uint8_t{1}, config]() mutable {
        return RouterNode<RouterT>{SchwiAddress{next_address++}, config};
    };

    return sim.add_device_class(
        std::move(factory),
        bricks::schwi::on<SendPacket>([](bricks::schwi::Context& ctx, RouterNode<RouterT>& self, const SendPacket& event) {
            self.transport->bind(ctx);
            self.router->send({
                .source = {},
                .target = event.target,
                .source_seq = 0,
                .payload = event.payload,
            });
        }),
        bricks::schwi::on<InjectPacket>([](bricks::schwi::Context&, RouterNode<RouterT>& self, const InjectPacket& event) {
            self.router->handle_packet(event.packet);
        }),
        bricks::schwi::on<AnnounceRoot>([](bricks::schwi::Context& ctx, RouterNode<RouterT>& self, const AnnounceRoot&) {
            self.transport->bind(ctx);
            self.router->announce_root();
        }),
        bricks::schwi::on<ClearObservations>([](bricks::schwi::Context&, RouterNode<RouterT>& self, const ClearObservations&) {
            self.inbound_packets.clear();
            self.delivered_payloads.clear();
        }),
        bricks::schwi::on<bricks::schwi::PacketReceived>(
            [](bricks::schwi::Context& ctx, RouterNode<RouterT>& self, const bricks::schwi::PacketReceived& event) {
                self.transport->bind(ctx);
                self.transport->handle_radio_receive(event.payload);
            }));
}

Router::Config make_config(bool root, bool intermediate_replies = true, std::chrono::milliseconds route_lifetime = 16ms,
                           std::uint8_t ttl = 4, std::uint8_t proactive_ttl = 6) {
    Router::Config config{};
    config.ttl = ttl;
    config.proactive_ttl = proactive_ttl;
    config.root = root;
    config.intermediate_replies = intermediate_replies;
    config.max_pending_per_destination = 4;
    config.max_pending_total = 8;
    config.route_lifetime = route_lifetime;
    config.discovery_retry_interval = 1ms;
    return config;
}

SchwiAddress preq_originator(const bricks::disnet::TransportPacket<SchwiAddress>& packet) {
    std::size_t offset = sizeof(HwmpFrameType) + sizeof(std::uint8_t) + sizeof(std::uint8_t) + sizeof(std::uint32_t);
    return read_bytes<SchwiAddress>(packet.payload, offset);
}

SchwiAddress preq_target(const bricks::disnet::TransportPacket<SchwiAddress>& packet) {
    std::size_t offset = sizeof(HwmpFrameType) + sizeof(std::uint8_t) + sizeof(std::uint8_t) + sizeof(std::uint32_t)
                       + sizeof(SchwiAddress) + sizeof(std::uint32_t);
    return read_bytes<SchwiAddress>(packet.payload, offset);
}

void test_announce_root_does_nothing_when_disabled() {
    bricks::schwi::Simulation sim = make_line_simulation();

    const auto router_class = make_root_router_class<Router>(sim, make_config(false));
    const auto node_a = sim.add_device(router_class);
    const auto node_b = sim.add_device(router_class);

    sim.set_position(node_a, {0.0, 0.0});
    sim.set_position(node_b, {5.0, 0.0});

    sim.at(1ms, node_a, AnnounceRoot{});
    sim.run();

    assert(sim.state(node_a).inbound_packets.empty());
    assert(sim.state(node_b).inbound_packets.empty());
}

void test_announce_root_emits_preq_when_enabled() {
    bricks::schwi::Simulation sim = make_line_simulation();

    const auto router_class = make_root_router_class<Router>(sim, make_config(true));
    const auto node_a = sim.add_device(router_class);
    const auto node_b = sim.add_device(router_class);

    sim.set_position(node_a, {0.0, 0.0});
    sim.set_position(node_b, {5.0, 0.0});

    sim.at(1ms, node_a, AnnounceRoot{});
    sim.run();

    assert(count_frames(sim.state(node_b).inbound_packets, HwmpFrameType::Preq) == 1);
    const auto& preq = sim.state(node_b).inbound_packets.front();
    assert(frame_type(preq) == HwmpFrameType::Preq);
    assert(preq_originator(preq) == SchwiAddress{1});
    assert(preq_target(preq) == SchwiTransport::broadcast_address());
    assert(preq_flags(preq) & 0x01);
}

void test_root_preq_propagates_with_ttl_decrement() {
    bricks::schwi::Simulation sim = make_line_simulation();

    const auto router_class = make_root_router_class<Router>(sim, make_config(true, true, 16ms, 4, 6));
    const auto node_a = sim.add_device(router_class);
    const auto node_b = sim.add_device(router_class);
    const auto node_c = sim.add_device(router_class);

    sim.set_position(node_a, {0.0, 0.0});
    sim.set_position(node_b, {5.0, 0.0});
    sim.set_position(node_c, {10.0, 0.0});

    sim.at(1ms, node_a, AnnounceRoot{});
    sim.run();

    assert(count_frames(sim.state(node_b).inbound_packets, HwmpFrameType::Preq) >= 1);
    assert(count_frames(sim.state(node_c).inbound_packets, HwmpFrameType::Preq) >= 1);
    assert(frame_ttl(sim.state(node_b).inbound_packets.front()) == 6);
    assert(frame_ttl(sim.state(node_c).inbound_packets.front()) == 5);
}

void test_downstream_node_can_send_to_root_without_reactive_discovery() {
    bricks::schwi::Simulation sim = make_line_simulation();

    const auto router_class = make_root_router_class<Router>(sim, make_config(true));
    const auto node_a = sim.add_device(router_class);
    const auto node_b = sim.add_device(router_class);
    const auto node_c = sim.add_device(router_class);

    sim.set_position(node_a, {0.0, 0.0});
    sim.set_position(node_b, {5.0, 0.0});
    sim.set_position(node_c, {10.0, 0.0});

    sim.at(1ms, node_a, AnnounceRoot{});
    sim.at(2ms, node_a, ClearObservations{});
    sim.at(2ms, node_b, ClearObservations{});
    sim.at(2ms, node_c, ClearObservations{});
    sim.at(3ms, node_c, SendPacket{
                            .target = SchwiAddress{1},
                            .payload = {0xCA, 0xFE},
                        });
    sim.run();

    assert((sim.state(node_a).delivered_payloads == std::vector<std::vector<std::uint8_t>>{{0xCA, 0xFE}}));
    assert(count_frames(sim.state(node_b).inbound_packets, HwmpFrameType::Preq) == 0);
    assert(count_frames(sim.state(node_c).inbound_packets, HwmpFrameType::Preq) == 0);
    assert(count_frames(sim.state(node_b).inbound_packets, HwmpFrameType::Data) == 1);
}

void test_repeated_root_announcements_refresh_route_before_expiry() {
    bricks::schwi::Simulation sim = make_line_simulation();

    const auto router_class = make_root_router_class<Router>(sim, make_config(true, true, 5ms, 4, 6));
    const auto node_a = sim.add_device(router_class);
    const auto node_b = sim.add_device(router_class);
    const auto node_c = sim.add_device(router_class);

    sim.set_position(node_a, {0.0, 0.0});
    sim.set_position(node_b, {5.0, 0.0});
    sim.set_position(node_c, {10.0, 0.0});

    sim.at(1ms, node_a, AnnounceRoot{});
    sim.at(4ms, node_a, AnnounceRoot{});
    sim.at(7ms, node_c, SendPacket{
                            .target = SchwiAddress{1},
                            .payload = {0x11, 0x22},
                        });
    sim.run();

    assert((sim.state(node_a).delivered_payloads == std::vector<std::vector<std::uint8_t>>{{0x11, 0x22}}));
    assert(count_frames(sim.state(node_b).inbound_packets, HwmpFrameType::Preq) >= 2);
    assert(count_frames(sim.state(node_c).inbound_packets, HwmpFrameType::Preq) >= 2);
}

void test_root_preq_is_not_destination_only_when_intermediate_replies_disabled() {
    bricks::schwi::Simulation sim = make_line_simulation();

    const auto router_class = make_root_router_class<Router>(sim, make_config(true, false));
    const auto node_a = sim.add_device(router_class);
    const auto node_b = sim.add_device(router_class);

    sim.set_position(node_a, {0.0, 0.0});
    sim.set_position(node_b, {5.0, 0.0});

    sim.at(1ms, node_a, AnnounceRoot{});
    sim.run();

    assert(count_frames(sim.state(node_b).inbound_packets, HwmpFrameType::Preq) == 1);
    const auto& preq = sim.state(node_b).inbound_packets.front();
    assert(frame_type(preq) == HwmpFrameType::Preq);
    assert((preq_flags(preq) & 0x01) != 0);
    assert((preq_flags(preq) & 0x02) == 0);
}

} // namespace

int main() {
    test_announce_root_does_nothing_when_disabled();
    test_announce_root_emits_preq_when_enabled();
    test_root_preq_propagates_with_ttl_decrement();
    test_downstream_node_can_send_to_root_without_reactive_discovery();
    test_repeated_root_announcements_refresh_route_before_expiry();
    test_root_preq_is_not_destination_only_when_intermediate_replies_disabled();
}
