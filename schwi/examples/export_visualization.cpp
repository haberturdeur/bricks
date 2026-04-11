#include <bricks/schwi.hpp>

#include <chrono>
#include <cstddef>
#include <fstream>
#include <vector>

using namespace std::chrono_literals;

struct ButtonPress {
    int value = 0;
};

struct MoveNode {
    bricks::schwi::Position position{};
};

struct NodeState {
    std::vector<int> received;
};

int main() {
    bricks::schwi::Simulation sim({
        .radio = {
            .rssi_from_distance = [](double distance) { return -30.0 - distance; },
            .reachability_threshold = -40.0,
            .delivery_delay = 5ms,
        },
    });

    const auto sender_class = sim.add_device_class(
        [] { return NodeState{}; },
        bricks::schwi::on<ButtonPress>([](bricks::schwi::Context& ctx, NodeState&, const ButtonPress& event) {
            ctx.broadcast(std::vector<std::byte>{static_cast<std::byte>(event.value)});
        }),
        bricks::schwi::on<MoveNode>([](bricks::schwi::Context& ctx, NodeState&, const MoveNode& event) { ctx.move_to(event.position); }));

    const auto receiver_class = sim.add_device_class(
        [] { return NodeState{}; },
        bricks::schwi::on<bricks::schwi::PacketReceived>(
            [](bricks::schwi::Context&, NodeState& self, const bricks::schwi::PacketReceived& event) {
                self.received.push_back(static_cast<int>(event.payload.at(0)));
            }));

    const auto sender = sim.add_device(sender_class);
    const auto receiver = sim.add_device(receiver_class);

    sim.set_position(sender, {0.0, 0.0});
    sim.set_position(receiver, {5.0, 0.0});
    sim.at(10ms, sender, ButtonPress{.value = 7});
    sim.at(12ms, sender, MoveNode{.position = {1.0, 2.0}});
    sim.run();

    bricks::schwi::VisualizationNamingRegistry naming;
    naming.state_key<NodeState>("radio-node");
    naming.state<NodeState>("radio-node");
    naming.event_key<ButtonPress>("button-press");
    naming.event<ButtonPress>("button-press");
    naming.event_key<MoveNode>("move-node");
    naming.event<MoveNode>("move-node");
    naming.event_key<bricks::schwi::PacketReceived>("packet-received");
    naming.event<bricks::schwi::PacketReceived>("packet-received");

    std::ofstream out("schwi_visualization.json");
    out << bricks::schwi::visualization_json(sim, naming);
}
