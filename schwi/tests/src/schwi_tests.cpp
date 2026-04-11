#include "bricks/schwi.hpp"

#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <stdexcept>
#include <type_traits>
#include <typeinfo>
#include <vector>

namespace {

using namespace std::chrono_literals;

struct ButtonPress {
    int button = 0;
};

struct EnvironmentChanged {
    int value = 0;
};

struct SchedulePastAbsolute {
};

struct MoveNode {
};

struct ThrowingEvent {
};

struct FollowupEvent {
};

struct NodeState {
    int button_presses = 0;
    int environment_sum = 0;
    std::vector<int> received_values;
};

struct TimingState {
    int ticks = 0;
};

struct ThrowState {
    int followups = 0;
};

struct PressCounter {
    int presses = 0;
};

struct MoveOnlyState {
    std::unique_ptr<int> value;

    explicit MoveOnlyState(int initial) : value(std::make_unique<int>(initial)) {}

    MoveOnlyState(const MoveOnlyState&) = delete;
    MoveOnlyState& operator=(const MoveOnlyState&) = delete;
    MoveOnlyState(MoveOnlyState&&) noexcept = default;
    MoveOnlyState& operator=(MoveOnlyState&&) noexcept = default;
};

void test_generic_events_and_radio_behavior() {
    bricks::schwi::Simulation sim({
        .radio = {
            .rssi_from_distance = [](double distance) { return -30.0 - distance; },
            .reachability_threshold = -40.0,
        },
    });

    const auto node_a_class = sim.add_device_class(
        [] { return NodeState{}; },
        bricks::schwi::on<ButtonPress>([](bricks::schwi::Context& ctx, NodeState& self, const ButtonPress& event) {
            ++self.button_presses;
            ctx.broadcast(std::vector<std::byte>{static_cast<std::byte>(event.button)});
        }),
        bricks::schwi::on<EnvironmentChanged>(
            [](bricks::schwi::Context&, NodeState& self, const EnvironmentChanged& event) {
                self.environment_sum += event.value;
            }));
    const auto node_a = sim.add_device(node_a_class);

    const auto node_b_class = sim.add_device_class(
        [] { return NodeState{}; },
        bricks::schwi::on<EnvironmentChanged>(
            [](bricks::schwi::Context&, NodeState& self, const EnvironmentChanged& event) {
                self.environment_sum += event.value;
            }),
        bricks::schwi::on<bricks::schwi::PacketReceived>(
            [](bricks::schwi::Context&, NodeState& self, const bricks::schwi::PacketReceived& event) {
                self.received_values.push_back(static_cast<int>(event.payload.at(0)));
            }));
    const auto node_b = sim.add_device(node_b_class);

    sim.set_position(node_a, {0.0, 0.0});
    sim.set_position(node_b, {5.0, 0.0});

    sim.at(10ms, node_a, ButtonPress{.button = 7});
    sim.at(15ms, EnvironmentChanged{.value = 3});
    sim.at(20ms, [node_b](bricks::schwi::Simulation& s) { s.set_position(node_b, {20.0, 0.0}); });
    sim.at(25ms, node_a, ButtonPress{.button = 9});
    sim.run();

    const auto& state_a = sim.state<NodeState>(node_a);
    const auto& state_b = sim.state<NodeState>(node_b);

    assert(state_a.button_presses == 2);
    assert(state_a.environment_sum == 3);
    assert(state_b.environment_sum == 3);
    assert((state_b.received_values == std::vector<int>{7}));

    const auto& log = sim.log();
    assert(log.size() >= 8);
    assert(log[0].kind == bricks::schwi::LogEntry::Kind::DeviceAdded);
    assert(log[1].kind == bricks::schwi::LogEntry::Kind::DeviceAdded);

    const auto& trace = sim.trace();
    assert(trace.size() == 5);
    assert(!trace[0].parent_id.has_value());
    assert(!trace[1].parent_id.has_value());
    assert(!trace[2].parent_id.has_value());
    assert(!trace[3].parent_id.has_value());
    assert(trace[4].parent_id == std::optional{trace[0].id});

    bool saw_delivery = false;
    bool saw_drop = false;
    bool saw_global = false;
    bool saw_move = false;
    bool saw_uncaused_move = false;
    bool saw_caused_delivery = false;
    bool saw_caused_drop = false;
    bool saw_packet_dispatch = false;
    for (const bricks::schwi::LogEntry& entry : log) {
        saw_delivery |= entry.kind == bricks::schwi::LogEntry::Kind::PacketDelivered;
        saw_drop |= entry.kind == bricks::schwi::LogEntry::Kind::PacketDropped;
        saw_global |= entry.kind == bricks::schwi::LogEntry::Kind::GlobalEventDispatched;
        saw_move |= entry.kind == bricks::schwi::LogEntry::Kind::DeviceMoved;
        saw_uncaused_move |= entry.kind == bricks::schwi::LogEntry::Kind::DeviceMoved && !entry.caused_by_event_id.has_value();
        saw_caused_delivery |= entry.kind == bricks::schwi::LogEntry::Kind::PacketDelivered &&
                               entry.caused_by_event_id == std::optional{trace[0].id};
        saw_caused_drop |= entry.kind == bricks::schwi::LogEntry::Kind::PacketDropped &&
                           entry.caused_by_event_id == std::optional{trace[3].id};
        saw_packet_dispatch |= entry.kind == bricks::schwi::LogEntry::Kind::TargetedEventDispatched &&
                               entry.caused_by_event_id == std::optional{trace[4].id};
    }

    assert(saw_delivery);
    assert(saw_drop);
    assert(saw_global);
    assert(saw_move);
    assert(saw_uncaused_move);
    assert(saw_caused_delivery);
    assert(saw_caused_drop);
    assert(saw_packet_dispatch);
}

void test_absolute_duration_scheduling_rejects_past_times() {
    bricks::schwi::Simulation sim;

    const auto node_class = sim.add_device_class(
        [] { return TimingState{}; },
        bricks::schwi::on<SchedulePastAbsolute>(
            [](bricks::schwi::Context& ctx, TimingState& self, const SchedulePastAbsolute&) {
                ++self.ticks;
                bool threw = false;
                try {
                    ctx.at(5ms, ctx.self(), SchedulePastAbsolute{});
                } catch (const std::invalid_argument&) {
                    threw = true;
                }
                assert(threw);
            }));
    const auto node = sim.add_device(node_class);

    sim.at(10ms, node, SchedulePastAbsolute{});
    sim.run();

    assert(sim.state<TimingState>(node).ticks == 1);
    assert(sim.now() == bricks::schwi::Simulation::TimePoint{10ms});
    assert(sim.trace().size() == 1);
}

void test_device_move_logs_keep_event_causality() {
    bricks::schwi::Simulation sim;

    const auto node_class = sim.add_device_class(
        [] { return NodeState{}; },
        bricks::schwi::on<MoveNode>([](bricks::schwi::Context& ctx, NodeState&, const MoveNode&) { ctx.move_to({1.0, 2.0}); }));
    const auto node = sim.add_device(node_class);

    sim.at(10ms, node, MoveNode{});
    sim.run();

    const auto& trace = sim.trace();
    assert(trace.size() == 1);

    bool saw_caused_move = false;
    for (const auto& entry : sim.log()) {
        if (entry.kind == bricks::schwi::LogEntry::Kind::DeviceMoved) {
            saw_caused_move |= entry.caused_by_event_id == std::optional{trace[0].id};
            assert(entry.position.has_value());
            assert(entry.position->x == 1.0);
            assert(entry.position->y == 2.0);
        }
    }

    assert(saw_caused_move);
}

void test_visualization_export_includes_positions_trace_and_radio_metadata() {
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
            ctx.broadcast(std::vector<std::byte>{static_cast<std::byte>(event.button)});
        }),
        bricks::schwi::on<MoveNode>([](bricks::schwi::Context& ctx, NodeState&, const MoveNode&) { ctx.move_to({1.0, 2.0}); }));
    const auto receiver_class = sim.add_device_class(
        [] { return NodeState{}; },
        bricks::schwi::on<bricks::schwi::PacketReceived>(
            [](bricks::schwi::Context&, NodeState& self, const bricks::schwi::PacketReceived& event) {
                self.received_values.push_back(static_cast<int>(event.payload.at(0)));
            }));

    const auto sender = sim.add_device(sender_class);
    const auto receiver = sim.add_device(receiver_class);
    sim.set_position(sender, {0.0, 0.0});
    sim.set_position(receiver, {5.0, 0.0});
    sim.at(10ms, sender, ButtonPress{.button = 7});
    sim.at(12ms, sender, MoveNode{});
    sim.run();

    bricks::schwi::VisualizationNamingRegistry registry;
    registry.state_key<NodeState>("node");
    registry.state<NodeState>("node-state");
    registry.event_key<ButtonPress>("press");
    registry.event_key<bricks::schwi::PacketReceived>("packet");
    registry.event<ButtonPress>("button-press");
    registry.event<bricks::schwi::PacketReceived>("packet-received");

    const std::string json = bricks::schwi::visualization_json(sim, registry);

    assert(json.find("\"format\":\"bricks.schwi.visualization\"") != std::string::npos);
    assert(json.find("\"schema_version\":1") != std::string::npos);
    assert(json.find("\"time_unit_ns\":1") != std::string::npos);
    assert(json.find("\"reachability_threshold\":-40") != std::string::npos);
    assert(json.find("\"delivery_delay_ns\":5000000") != std::string::npos);
    assert(json.find("\"devices\":[") != std::string::npos);
    assert(json.find("\"trace\":[") != std::string::npos);
    assert(json.find("\"log\":[") != std::string::npos);
    assert(json.find("\"state_key\":\"node\"") != std::string::npos);
    assert(json.find("\"event_key\":\"press\"") != std::string::npos);
    assert(json.find("\"event_key\":\"packet\"") != std::string::npos);
    assert(json.find("\"kind\":\"DeviceMoved\"") != std::string::npos);
    assert(json.find("\"position\":{\"x\":1,\"y\":2}") != std::string::npos);
    assert(json.find("\"current_position\":{\"x\":1,\"y\":2}") != std::string::npos);
    assert(json.find("\"kind\":\"PacketDelivered\"") != std::string::npos);
    assert(json.find("\"kind\":\"DeviceAdded\",\"time_ns\":0,\"source\":0,\"target\":null") != std::string::npos);
    assert(json.find("\"peer\":null") != std::string::npos);
    assert(json.find("\"state_name\":\"node-state\"") != std::string::npos);
    assert(json.find("\"event_name\":\"packet-received\"") != std::string::npos);
}

void test_throwing_handlers_do_not_leak_parent_event_context() {
    bricks::schwi::Simulation sim;

    const auto node_class = sim.add_device_class(
        [] { return ThrowState{}; },
        bricks::schwi::on<ThrowingEvent>(
            [](bricks::schwi::Context&, ThrowState&, const ThrowingEvent&) { throw std::runtime_error("boom"); }),
        bricks::schwi::on<FollowupEvent>(
            [](bricks::schwi::Context&, ThrowState& self, const FollowupEvent&) { ++self.followups; }));
    const auto node = sim.add_device(node_class);

    sim.at(10ms, node, ThrowingEvent{});
    bool threw = false;
    try {
        sim.run();
    } catch (const std::runtime_error&) {
        threw = true;
    }
    assert(threw);

    sim.at(20ms, node, FollowupEvent{});
    sim.run();

    const auto& trace = sim.trace();
    assert(trace.size() == 2);
    assert(!trace[1].parent_id.has_value());
    assert(sim.state<ThrowState>(node).followups == 1);
}

void test_device_classes_can_create_many_instances_from_one_factory() {
    bricks::schwi::Simulation sim;

    const auto phone = sim.add_device_class(
        [] { return PressCounter{.presses = 3}; },
        bricks::schwi::on<ButtonPress>(
            [](bricks::schwi::Context&, PressCounter& self, const ButtonPress&) { ++self.presses; }));

    const auto alice_phone = sim.add_device(phone);
    const auto bob_phone = sim.add_device(phone);

    sim.at(10ms, alice_phone, ButtonPress{});
    sim.at(20ms, bob_phone, ButtonPress{});
    sim.run();

    assert(sim.state(alice_phone).presses == 4);
    assert(sim.state(bob_phone).presses == 4);
}

void test_move_only_state_is_supported() {
    bricks::schwi::Simulation sim;

    const auto node_class = sim.add_device_class(
        [] { return MoveOnlyState{5}; },
        bricks::schwi::on<ButtonPress>([](bricks::schwi::Context&, MoveOnlyState& self, const ButtonPress&) {
            ++*self.value;
        }));

    const auto first = sim.add_device(node_class);
    const auto second = sim.add_device(node_class);

    sim.at(10ms, first, ButtonPress{});
    sim.at(20ms, second, ButtonPress{});
    sim.run();

    assert(*sim.state(first).value == 6);
    assert(*sim.state(second).value == 6);
}

static_assert(!std::is_copy_constructible_v<MoveOnlyState>);

void test_state_access_throws_on_wrong_type() {
    bricks::schwi::Simulation sim;

    const auto node_class = sim.add_device_class([] { return NodeState{}; });
    const auto node = sim.add_device(node_class);

    bool threw = false;
    try {
        (void)sim.state<ThrowState>(node);
    } catch (const std::bad_cast&) {
        threw = true;
    }

    assert(threw);
}

void test_device_factory_can_hold_mutable_state_between_instantiations() {
    bricks::schwi::Simulation sim;

    const auto node_class = sim.add_device_class([next_value = 1]() mutable {
        return PressCounter{.presses = next_value++};
    });

    const auto first = sim.add_device(node_class);
    const auto second = sim.add_device(node_class);

    assert(sim.state(first).presses == 1);
    assert(sim.state(second).presses == 2);
}

void test_broadcast_delivery_obeys_configured_radio_delay() {
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
            ctx.broadcast(std::vector<std::byte>{static_cast<std::byte>(event.button)});
        }));
    const auto receiver_class = sim.add_device_class(
        [] { return NodeState{}; },
        bricks::schwi::on<bricks::schwi::PacketReceived>(
            [](bricks::schwi::Context&, NodeState& self, const bricks::schwi::PacketReceived& event) {
                self.received_values.push_back(static_cast<int>(event.payload.at(0)));
            }));

    const auto sender = sim.add_device(sender_class);
    const auto receiver = sim.add_device(receiver_class);

    sim.set_position(sender, {0.0, 0.0});
    sim.set_position(receiver, {5.0, 0.0});

    sim.at(10ms, sender, ButtonPress{.button = 7});

    sim.run_until(bricks::schwi::Simulation::TimePoint{14ms});
    assert(sim.state(receiver).received_values.empty());

    sim.run_until(bricks::schwi::Simulation::TimePoint{15ms});
    assert((sim.state(receiver).received_values == std::vector<int>{7}));

    bool saw_delayed_delivery = false;
    bool saw_delayed_dispatch = false;
    for (const auto& entry : sim.log()) {
        if (entry.kind == bricks::schwi::LogEntry::Kind::PacketDelivered) {
            saw_delayed_delivery |= entry.time == bricks::schwi::Simulation::TimePoint{15ms};
        }
        if (entry.kind == bricks::schwi::LogEntry::Kind::TargetedEventDispatched) {
            saw_delayed_dispatch |= entry.time == bricks::schwi::Simulation::TimePoint{15ms};
        }
    }

    assert(saw_delayed_delivery);
    assert(saw_delayed_dispatch);
}

void test_default_radio_delay_is_nonzero_and_defers_delivery() {
    bricks::schwi::Simulation sim({
        .radio = {
            .rssi_from_distance = [](double distance) { return -30.0 - distance; },
            .reachability_threshold = -40.0,
        },
    });

    const auto sender_class = sim.add_device_class(
        [] { return NodeState{}; },
        bricks::schwi::on<ButtonPress>([](bricks::schwi::Context& ctx, NodeState&, const ButtonPress& event) {
            ctx.broadcast(std::vector<std::byte>{static_cast<std::byte>(event.button)});
        }));
    const auto receiver_class = sim.add_device_class(
        [] { return NodeState{}; },
        bricks::schwi::on<bricks::schwi::PacketReceived>(
            [](bricks::schwi::Context&, NodeState& self, const bricks::schwi::PacketReceived& event) {
                self.received_values.push_back(static_cast<int>(event.payload.at(0)));
            }));

    const auto sender = sim.add_device(sender_class);
    const auto receiver = sim.add_device(receiver_class);

    sim.set_position(sender, {0.0, 0.0});
    sim.set_position(receiver, {5.0, 0.0});

    sim.at(10ms, sender, ButtonPress{.button = 7});

    sim.run_until(bricks::schwi::Simulation::TimePoint{10ms});
    assert(sim.state(receiver).received_values.empty());

    sim.run_until(bricks::schwi::Simulation::TimePoint{10ms + 1ns});
    assert((sim.state(receiver).received_values == std::vector<int>{7}));
}

void test_testing_helpers_can_dump_log_and_trace() {
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
            ctx.broadcast(std::vector<std::byte>{static_cast<std::byte>(event.button)});
        }));
    const auto receiver_class = sim.add_device_class(
        [] { return NodeState{}; },
        bricks::schwi::on<bricks::schwi::PacketReceived>(
            [](bricks::schwi::Context&, NodeState&, const bricks::schwi::PacketReceived&) {}));

    const auto sender = sim.add_device(sender_class);
    const auto receiver = sim.add_device(receiver_class);
    sim.set_position(sender, {0.0, 0.0});
    sim.set_position(receiver, {5.0, 0.0});
    sim.at(10ms, sender, ButtonPress{.button = 7});
    sim.run();

    std::ostringstream log_stream;
    std::ostringstream trace_stream;
    bricks::schwi::testing::print_log(sim, log_stream);
    bricks::schwi::testing::print_trace(sim, trace_stream);

    const std::string log_text = log_stream.str();
    const std::string trace_text = trace_stream.str();

    assert(log_text.find("DeviceAdded") != std::string::npos);
    assert(log_text.find("BroadcastSent") != std::string::npos);
    assert(log_text.find("PacketDelivered") != std::string::npos);
    assert(log_text.find("source=0") != std::string::npos);
    assert(log_text.find("target=1") != std::string::npos);

    assert(trace_text.find("TargetedEvent") != std::string::npos);
    assert(trace_text.find("ButtonPress") != std::string::npos);
    assert(trace_text.find("PacketReceived") != std::string::npos);
    assert(trace_text.find("parent=1") != std::string::npos);
}

} // namespace

int main() {
    test_generic_events_and_radio_behavior();
    test_absolute_duration_scheduling_rejects_past_times();
    test_device_move_logs_keep_event_causality();
    test_visualization_export_includes_positions_trace_and_radio_metadata();
    test_throwing_handlers_do_not_leak_parent_event_context();
    test_device_classes_can_create_many_instances_from_one_factory();
    test_move_only_state_is_supported();
    test_state_access_throws_on_wrong_type();
    test_device_factory_can_hold_mutable_state_between_instantiations();
    test_broadcast_delivery_obeys_configured_radio_delay();
    test_default_radio_delay_is_nonzero_and_defers_delivery();
    test_testing_helpers_can_dump_log_and_trace();
}
