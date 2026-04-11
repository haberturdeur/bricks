#include "support/hwmp_schwi_test_support.hpp"

#include <cassert>
#include <chrono>
#include <cstdint>
#include <vector>

namespace {

using namespace std::chrono_literals;
using bricks::disnet::test::HwmpFrameType;
using bricks::disnet::test::RouterNode;
using bricks::disnet::test::SchwiAddress;
using bricks::disnet::test::SchwiTransport;
using bricks::disnet::test::SendPacket;

struct Relocate {
    bricks::schwi::Position position{};
};

struct InvalidateRoute {
    SchwiAddress destination{};
};

template <typename RouterT>
auto make_router_class(bricks::schwi::Simulation& sim, typename RouterT::Config config = {}) {
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
        bricks::schwi::on<Relocate>([](bricks::schwi::Context& ctx, RouterNode<RouterT>&, const Relocate& event) {
            ctx.move_to(event.position);
        }),
        bricks::schwi::on<InvalidateRoute>([](bricks::schwi::Context&, RouterNode<RouterT>& self,
                                             const InvalidateRoute& event) { self.router->invalidate_route(event.destination); }),
        bricks::schwi::on<bricks::schwi::PacketReceived>(
            [](bricks::schwi::Context& ctx, RouterNode<RouterT>& self, const bricks::schwi::PacketReceived& event) {
                self.transport->bind(ctx);
                self.transport->handle_radio_receive(event.payload);
            }));
}

template <typename T>
std::vector<std::vector<std::uint8_t>> data_frames(const std::vector<T>& packets) {
    std::vector<std::vector<std::uint8_t>> out;
    for (const auto& packet : packets) {
        if (bricks::disnet::test::frame_type(packet) == HwmpFrameType::Data) {
            out.push_back(bricks::disnet::test::data_payload(packet));
        }
    }
    return out;
}

template <typename T>
const T& first_frame(const std::vector<T>& packets, HwmpFrameType type) {
    for (const auto& packet : packets) {
        if (bricks::disnet::test::frame_type(packet) == type) {
            return packet;
        }
    }
    assert(false && "expected frame not found");
    return packets.front();
}

void test_three_hop_reactive_route_discovery_and_delivery() {
    bricks::schwi::Simulation sim = bricks::disnet::test::make_line_simulation();

    const auto hwmp_class = make_router_class<bricks::disnet::Hwmp<SchwiTransport>>(sim, {
                                                                                              .ttl = 4,
                                                                                              .proactive_ttl = 6,
                                                                                              .root = false,
                                                                                              .intermediate_replies = true,
                                                                                              .max_pending_per_destination = 4,
                                                                                              .max_pending_total = 8,
                                                                                              .route_lifetime = 32ms,
                                                                                              .discovery_retry_interval = 1ms,
                                                                                          });
    const auto node_a = sim.add_device(hwmp_class);
    const auto node_b = sim.add_device(hwmp_class);
    const auto node_c = sim.add_device(hwmp_class);
    const auto node_d = sim.add_device(hwmp_class);

    sim.set_position(node_a, {0.0, 0.0});
    sim.set_position(node_b, {5.0, 0.0});
    sim.set_position(node_c, {10.0, 0.0});
    sim.set_position(node_d, {15.0, 0.0});

    sim.at(1ms, node_a, SendPacket{
                            .target = SchwiAddress{4},
                            .payload = {0x11, 0x22},
                        });
    sim.run();

    assert(sim.state(node_a).delivered_payloads.empty());
    assert((sim.state(node_d).delivered_payloads == std::vector<std::vector<std::uint8_t>>{{0x11, 0x22}}));

    const auto& inbound_b = sim.state(node_b).inbound_packets;
    const auto& inbound_c = sim.state(node_c).inbound_packets;

    assert(bricks::disnet::test::count_frames(inbound_b, HwmpFrameType::Data) == 2);
    assert(bricks::disnet::test::count_frames(inbound_c, HwmpFrameType::Data) == 1);
    assert(bricks::disnet::test::frame_ttl(first_frame(inbound_b, HwmpFrameType::Data)) == 4);
    assert(bricks::disnet::test::frame_ttl(first_frame(inbound_c, HwmpFrameType::Data)) == 3);
    assert((bricks::disnet::test::data_payload(first_frame(inbound_b, HwmpFrameType::Data))
            == std::vector<std::uint8_t>{0x11, 0x22}));
    assert((bricks::disnet::test::data_payload(first_frame(inbound_c, HwmpFrameType::Data))
            == std::vector<std::uint8_t>{0x11, 0x22}));
}

void test_alternate_path_recovers_after_topology_move() {
    bricks::schwi::Simulation sim = bricks::disnet::test::make_line_simulation();

    const auto hwmp_class = make_router_class<bricks::disnet::Hwmp<SchwiTransport>>(sim, {
                                                                                              .ttl = 4,
                                                                                              .proactive_ttl = 6,
                                                                                              .root = false,
                                                                                              .intermediate_replies = true,
                                                                                              .max_pending_per_destination = 4,
                                                                                              .max_pending_total = 8,
                                                                                              .route_lifetime = 32ms,
                                                                                              .discovery_retry_interval = 1ms,
                                                                                          });
    const auto node_a = sim.add_device(hwmp_class);
    const auto node_b = sim.add_device(hwmp_class);
    const auto node_c = sim.add_device(hwmp_class);
    const auto node_d = sim.add_device(hwmp_class);

    sim.set_position(node_a, {0.0, 0.0});
    sim.set_position(node_b, {5.0, 0.0});
    sim.set_position(node_c, {30.0, 0.0});
    sim.set_position(node_d, {10.0, 0.0});

    sim.at(1ms, node_a, SendPacket{
                            .target = SchwiAddress{4},
                            .payload = {0xA1},
                        });
    sim.at(10ms, node_b, Relocate{.position = {50.0, 0.0}});
    sim.at(10ms, node_c, Relocate{.position = {5.0, 0.0}});
    sim.at(11ms, node_a, InvalidateRoute{.destination = SchwiAddress{4}});
    sim.at(12ms, node_a, SendPacket{
                             .target = SchwiAddress{4},
                             .payload = {0xB2},
                         });
    sim.run();

    assert((sim.state(node_d).delivered_payloads == std::vector<std::vector<std::uint8_t>>{{0xA1}, {0xB2}}));

    const auto b_data = data_frames(sim.state(node_b).inbound_packets);
    const auto c_data = data_frames(sim.state(node_c).inbound_packets);

    assert((b_data == std::vector<std::vector<std::uint8_t>>{{0xA1}}));
    assert((c_data == std::vector<std::vector<std::uint8_t>>{{0xB2}}));
}

void test_unreachable_destination_does_not_deliver_payload() {
    bricks::schwi::Simulation sim = bricks::disnet::test::make_line_simulation();

    const auto hwmp_class = make_router_class<bricks::disnet::Hwmp<SchwiTransport>>(sim, {
                                                                                              .ttl = 4,
                                                                                              .proactive_ttl = 6,
                                                                                              .root = false,
                                                                                              .intermediate_replies = true,
                                                                                              .max_pending_per_destination = 4,
                                                                                              .max_pending_total = 8,
                                                                                              .route_lifetime = 32ms,
                                                                                              .discovery_retry_interval = 1ms,
                                                                                          });
    const auto node_a = sim.add_device(hwmp_class);
    const auto node_b = sim.add_device(hwmp_class);

    sim.set_position(node_a, {0.0, 0.0});
    sim.set_position(node_b, {5.0, 0.0});

    sim.at(1ms, node_a, SendPacket{
                            .target = SchwiAddress{9},
                            .payload = {0x55},
                        });
    sim.run();

    assert(sim.state(node_a).delivered_payloads.empty());
    assert(sim.state(node_b).delivered_payloads.empty());
}

void test_concurrent_discoveries_do_not_interfere() {
    bricks::schwi::Simulation sim = bricks::disnet::test::make_line_simulation();

    const auto hwmp_class = make_router_class<bricks::disnet::Hwmp<SchwiTransport>>(sim, {
                                                                                              .ttl = 4,
                                                                                              .proactive_ttl = 6,
                                                                                              .root = false,
                                                                                              .intermediate_replies = true,
                                                                                              .max_pending_per_destination = 4,
                                                                                              .max_pending_total = 8,
                                                                                              .route_lifetime = 32ms,
                                                                                              .discovery_retry_interval = 1ms,
                                                                                          });
    const auto node_a = sim.add_device(hwmp_class);
    const auto node_b = sim.add_device(hwmp_class);
    const auto node_c = sim.add_device(hwmp_class);
    const auto node_d = sim.add_device(hwmp_class);
    const auto node_e = sim.add_device(hwmp_class);

    sim.set_position(node_a, {0.0, 0.0});
    sim.set_position(node_b, {5.0, 0.0});
    sim.set_position(node_c, {0.0, 5.0});
    sim.set_position(node_d, {10.0, 0.0});
    sim.set_position(node_e, {0.0, 10.0});

    sim.at(1ms, node_a, SendPacket{
                            .target = SchwiAddress{4},
                            .payload = {0x31},
                        });
    sim.at(1ms + 1ns, node_a, SendPacket{
                                   .target = SchwiAddress{5},
                                   .payload = {0x41},
                               });
    sim.run();

    assert(sim.state(node_a).delivered_payloads.empty());
    assert((sim.state(node_d).delivered_payloads == std::vector<std::vector<std::uint8_t>>{{0x31}}));
    assert((sim.state(node_e).delivered_payloads == std::vector<std::vector<std::uint8_t>>{{0x41}}));
}

void test_broadcast_reaches_downstream_peers_without_originator_redelivery() {
    bricks::schwi::Simulation sim = bricks::disnet::test::make_line_simulation();

    const auto hwmp_class = make_router_class<bricks::disnet::Hwmp<SchwiTransport>>(sim, {
                                                                                              .ttl = 4,
                                                                                              .proactive_ttl = 6,
                                                                                              .root = false,
                                                                                              .intermediate_replies = true,
                                                                                              .max_pending_per_destination = 4,
                                                                                              .max_pending_total = 8,
                                                                                              .route_lifetime = 32ms,
                                                                                              .discovery_retry_interval = 1ms,
                                                                                          });
    const auto node_a = sim.add_device(hwmp_class);
    const auto node_b = sim.add_device(hwmp_class);
    const auto node_c = sim.add_device(hwmp_class);

    sim.set_position(node_a, {0.0, 0.0});
    sim.set_position(node_b, {5.0, 0.0});
    sim.set_position(node_c, {10.0, 0.0});

    sim.at(1ms, node_a, SendPacket{
                            .target = SchwiTransport::broadcast_address(),
                            .payload = {0x7A},
                        });
    sim.run();

    assert(sim.state(node_a).delivered_payloads.empty());
    assert((sim.state(node_b).delivered_payloads == std::vector<std::vector<std::uint8_t>>{{0x7A}}));
    assert((sim.state(node_c).delivered_payloads == std::vector<std::vector<std::uint8_t>>{{0x7A}}));
}

} // namespace

int main() {
    test_three_hop_reactive_route_discovery_and_delivery();
    test_alternate_path_recovers_after_topology_move();
    test_unreachable_destination_does_not_deliver_payload();
    test_concurrent_discoveries_do_not_interfere();
    test_broadcast_reaches_downstream_peers_without_originator_redelivery();
}
