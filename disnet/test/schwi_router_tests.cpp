#include "bricks/disnet/flood.hpp"
#include "bricks/disnet/hwmp.hpp"
#include "bricks/schwi.hpp"
#include "support/schwi_transport.hpp"

#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace {

using namespace std::chrono_literals;
using bricks::disnet::test::SchwiAddress;
using bricks::disnet::test::SchwiTransport;

struct SendPacket {
    SchwiAddress target{};
    std::vector<std::uint8_t> payload;
};

struct InjectPacket {
    bricks::disnet::TransportPacket<SchwiAddress> packet;
};

template <typename RouterT>
struct RouterNode {
    using Address = SchwiAddress;
    using Config = typename RouterT::Config;

    Address address{};
    std::unique_ptr<SchwiTransport> transport;
    std::unique_ptr<RouterT> router;
    std::vector<std::vector<std::uint8_t>> delivered_payloads;
    std::vector<bricks::disnet::TransportPacket<Address>> inbound_packets;

    RouterNode(Address self, Config config = {})
        : address(self),
          transport(std::make_unique<SchwiTransport>(self)),
          router(std::make_unique<RouterT>(*transport, config)) {
        install_callbacks();
    }

    RouterNode(const RouterNode&) = delete;
    RouterNode& operator=(const RouterNode&) = delete;

    RouterNode(RouterNode&& other) noexcept
        : address(other.address),
          transport(std::move(other.transport)),
          router(std::move(other.router)),
          delivered_payloads(std::move(other.delivered_payloads)),
          inbound_packets(std::move(other.inbound_packets)) {
        install_callbacks();
    }

    RouterNode& operator=(RouterNode&& other) noexcept {
        if (this != &other) {
            address = other.address;
            transport = std::move(other.transport);
            router = std::move(other.router);
            delivered_payloads = std::move(other.delivered_payloads);
            inbound_packets = std::move(other.inbound_packets);
            install_callbacks();
        }
        return *this;
    }

private:
    void install_callbacks() {
        transport->register_callback([this](bricks::disnet::TransportPacket<Address> packet) {
            inbound_packets.push_back(packet);
            router->handle_packet(packet);
        });
        router->register_callback([this](bricks::disnet::TransportPacket<Address> packet) {
            delivered_payloads.push_back(std::move(packet.payload));
        });
    }
};

enum class FrameType : std::uint8_t {
    Data = 0,
    Preq = 1,
    Prep = 2,
    Perr = 3,
};

template <typename T>
void append(std::vector<std::uint8_t>& out, const T& value) {
    const std::size_t offset = out.size();
    out.resize(offset + sizeof(T));
    std::memcpy(out.data() + offset, &value, sizeof(T));
}

template <typename T>
T read(const std::vector<std::uint8_t>& in, std::size_t& offset) {
    T value{};
    assert(offset + sizeof(T) <= in.size());
    std::memcpy(&value, in.data() + offset, sizeof(T));
    offset += sizeof(T);
    return value;
}

std::vector<std::uint8_t> encode_prep(SchwiAddress originator, SchwiAddress target, std::uint32_t target_seq,
                                      std::uint32_t metric, std::uint8_t ttl = 5) {
    std::vector<std::uint8_t> out;
    append(out, FrameType::Prep);
    append(out, ttl);
    append(out, originator);
    append(out, target);
    append(out, target_seq);
    append(out, metric);
    return out;
}

std::vector<std::uint8_t> encode_perr(SchwiAddress destination, std::uint32_t destination_seq) {
    std::vector<std::uint8_t> out;
    append(out, FrameType::Perr);
    append(out, destination);
    append(out, destination_seq);
    return out;
}

FrameType frame_type(const bricks::disnet::TransportPacket<SchwiAddress>& packet) {
    std::size_t offset = 0;
    return read<FrameType>(packet.payload, offset);
}

std::vector<std::uint8_t> data_payload(const bricks::disnet::TransportPacket<SchwiAddress>& packet) {
    std::size_t offset = 0;
    const FrameType type = read<FrameType>(packet.payload, offset);
    assert(type == FrameType::Data);
    offset += sizeof(std::uint8_t);
    offset += sizeof(SchwiAddress);
    offset += sizeof(SchwiAddress);
    offset += sizeof(std::uint32_t);
    return {packet.payload.begin() + static_cast<std::ptrdiff_t>(offset), packet.payload.end()};
}

std::uint8_t data_ttl(const bricks::disnet::TransportPacket<SchwiAddress>& packet) {
    std::size_t offset = 0;
    const FrameType type = read<FrameType>(packet.payload, offset);
    assert(type == FrameType::Data);
    return read<std::uint8_t>(packet.payload, offset);
}

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
        bricks::schwi::on<InjectPacket>([](bricks::schwi::Context&, RouterNode<RouterT>& self, const InjectPacket& event) {
            self.router->handle_packet(event.packet);
        }),
        bricks::schwi::on<bricks::schwi::PacketReceived>(
            [](bricks::schwi::Context& ctx, RouterNode<RouterT>& self, const bricks::schwi::PacketReceived& event) {
                self.transport->bind(ctx);
                self.transport->handle_radio_receive(event.payload);
            }));
}

bricks::schwi::Simulation make_line_simulation() {
    return bricks::schwi::Simulation({
        .radio = {
            .rssi_from_distance = [](double distance) { return -30.0 - distance; },
            .reachability_threshold = -36.0,
        },
    });
}

void test_flood_reaches_two_hops_over_schwi() {
    bricks::schwi::Simulation sim = make_line_simulation();

    const auto flood_class = make_router_class<bricks::disnet::Flood<SchwiTransport>>(sim);
    const auto node_a = sim.add_device(flood_class);
    const auto node_b = sim.add_device(flood_class);
    const auto node_c = sim.add_device(flood_class);

    sim.set_position(node_a, {0.0, 0.0});
    sim.set_position(node_b, {5.0, 0.0});
    sim.set_position(node_c, {10.0, 0.0});

    sim.at(1ms, node_a, SendPacket{
                            .target = SchwiTransport::broadcast_address(),
                            .payload = {0x42},
                        });
    sim.run();

    assert((sim.state(node_a).delivered_payloads.empty()));
    assert((sim.state(node_b).delivered_payloads == std::vector<std::vector<std::uint8_t>>{{0x42}}));
    assert((sim.state(node_c).delivered_payloads == std::vector<std::vector<std::uint8_t>>{{0x42}}));
}

void test_hwmp_discovers_route_and_delivers_over_schwi() {
    bricks::schwi::Simulation sim = make_line_simulation();

    const auto hwmp_class = make_router_class<bricks::disnet::Hwmp<SchwiTransport>>(sim, bricks::disnet::Hwmp<SchwiTransport>::Config{
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
                            .target = SchwiAddress{3},
                            .payload = {0xCA, 0xFE},
                        });
    sim.run();

    assert(sim.state(node_a).delivered_payloads.empty());
    assert(sim.state(node_b).delivered_payloads.empty());
    assert((sim.state(node_c).delivered_payloads == std::vector<std::vector<std::uint8_t>>{{0xCA, 0xFE}}));
}

void test_hwmp_originator_does_not_redeliver_own_broadcast_over_schwi() {
    bricks::schwi::Simulation sim = make_line_simulation();

    const auto hwmp_class = make_router_class<bricks::disnet::Hwmp<SchwiTransport>>(sim, {
                                                                                              .ttl = 4,
                                                                                              .proactive_ttl = 6,
                                                                                              .root = false,
                                                                                              .intermediate_replies = true,
                                                                                              .max_pending_per_destination = 4,
                                                                                              .max_pending_total = 8,
                                                                                              .route_lifetime = 16ms,
                                                                                          });
    const auto node_a = sim.add_device(hwmp_class);
    const auto node_b = sim.add_device(hwmp_class);

    sim.set_position(node_a, {0.0, 0.0});
    sim.set_position(node_b, {5.0, 0.0});

    sim.at(1ms, node_a, SendPacket{
                            .target = SchwiTransport::broadcast_address(),
                            .payload = {7, 8},
                        });
    sim.run();

    assert(sim.state(node_a).delivered_payloads.empty());
    assert((sim.state(node_b).delivered_payloads == std::vector<std::vector<std::uint8_t>>{{7, 8}}));
}

void test_hwmp_perr_keeps_pending_packets_for_future_route_resolution_over_schwi() {
    bricks::schwi::Simulation sim = make_line_simulation();

    const auto hwmp_class = make_router_class<bricks::disnet::Hwmp<SchwiTransport>>(sim, {
                                                                                              .ttl = 4,
                                                                                              .proactive_ttl = 6,
                                                                                              .root = false,
                                                                                              .intermediate_replies = true,
                                                                                              .max_pending_per_destination = 4,
                                                                                              .max_pending_total = 8,
                                                                                              .route_lifetime = 16ms,
                                                                                          });
    const auto node_a = sim.add_device(hwmp_class);
    const auto node_b = sim.add_device(hwmp_class);

    sim.set_position(node_a, {0.0, 0.0});
    sim.set_position(node_b, {5.0, 0.0});

    sim.at(1ms, node_a, SendPacket{
                            .target = SchwiAddress{9},
                            .payload = {1},
                        });
    sim.at(2ms, node_a, [node_a](bricks::schwi::Simulation& s) { s.state(node_a).inbound_packets.clear(); });
    sim.at(3ms, node_a, InjectPacket{
                            .packet =
                                {
                                    .source = SchwiAddress{2},
                                    .target = SchwiTransport::broadcast_address(),
                                    .source_seq = 22,
                                    .payload = encode_perr(SchwiAddress{9}, 1),
                                },
                        });
    sim.at(4ms, node_a, InjectPacket{
                            .packet =
                                {
                                    .source = SchwiAddress{2},
                                    .target = SchwiAddress{1},
                                    .source_seq = 23,
                                    .payload = encode_prep(SchwiAddress{1}, SchwiAddress{9}, 2, 0),
                                },
                        });
    sim.run();

    const auto& inbound_at_b = sim.state(node_b).inbound_packets;
    const auto data_it = std::find_if(inbound_at_b.begin(), inbound_at_b.end(), [](const auto& packet) {
        return frame_type(packet) == FrameType::Data;
    });
    assert(data_it != inbound_at_b.end());
    assert(data_ttl(*data_it) == 4);
    assert((data_payload(*data_it) == std::vector<std::uint8_t>{1}));
}

void test_hwmp_pending_queue_is_bounded_and_preq_is_suppressed_over_schwi() {
    bricks::schwi::Simulation sim = make_line_simulation();

    const auto hwmp_class = make_router_class<bricks::disnet::Hwmp<SchwiTransport>>(sim, {
                                                                                              .ttl = 4,
                                                                                              .proactive_ttl = 6,
                                                                                              .root = false,
                                                                                              .intermediate_replies = true,
                                                                                              .max_pending_per_destination = 2,
                                                                                              .max_pending_total = 2,
                                                                                              .route_lifetime = 32ms,
                                                                                          });
    const auto node_a = sim.add_device(hwmp_class);
    const auto node_b = sim.add_device(hwmp_class);

    sim.set_position(node_a, {0.0, 0.0});
    sim.set_position(node_b, {5.0, 0.0});

    sim.at(1ms, node_a, SendPacket{
                            .target = SchwiAddress{9},
                            .payload = {1},
                        });
    sim.at(2ms, node_a, SendPacket{
                            .target = SchwiAddress{9},
                            .payload = {2},
                        });
    sim.at(3ms, node_a, SendPacket{
                            .target = SchwiAddress{9},
                            .payload = {3},
                        });
    sim.at(4ms, node_a, InjectPacket{
                            .packet =
                                {
                                    .source = SchwiAddress{2},
                                    .target = SchwiAddress{1},
                                    .source_seq = 77,
                                    .payload = encode_prep(SchwiAddress{1}, SchwiAddress{9}, 10, 0),
                                },
                        });
    sim.run();

    const auto& inbound_at_b = sim.state(node_b).inbound_packets;
    const std::size_t preq_count = static_cast<std::size_t>(
        std::count_if(inbound_at_b.begin(), inbound_at_b.end(), [](const auto& packet) {
            return frame_type(packet) == FrameType::Preq;
        }));
    assert(preq_count == 1);

    std::vector<std::vector<std::uint8_t>> data_payloads;
    for (const auto& packet : inbound_at_b) {
        if (frame_type(packet) == FrameType::Data)
            data_payloads.push_back(data_payload(packet));
    }

    assert(data_payloads.size() == 2);
    assert((data_payloads[0] == std::vector<std::uint8_t>{2}));
    assert((data_payloads[1] == std::vector<std::uint8_t>{3}));
}

} // namespace

int main() {
    test_flood_reaches_two_hops_over_schwi();
    test_hwmp_discovers_route_and_delivers_over_schwi();
    test_hwmp_originator_does_not_redeliver_own_broadcast_over_schwi();
    test_hwmp_perr_keeps_pending_packets_for_future_route_resolution_over_schwi();
    test_hwmp_pending_queue_is_bounded_and_preq_is_suppressed_over_schwi();
}
