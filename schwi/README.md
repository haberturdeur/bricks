# Schwi

Host-side discrete-event simulation for small networks of stateful devices.

`schwi` is a header-only C++20 library. Devices hold arbitrary state, react to
typed events, can move in 2D space, and can exchange broadcast packets when the
configured RSSI model says they are reachable. Reusable device definitions can
be declared once with `add_device_class(...)` and instantiated multiple times
with `add_device(...)`.
Broadcast delivery uses a tiny nonzero propagation delay by default so send and
receive events remain distinct in the timeline.

## Build

```cmake
add_subdirectory(path/to/schwi)
target_link_libraries(your_target PRIVATE bricks::schwi)
```

To build the export example as part of the standalone `schwi` project:

```sh
cmake -S path/to/schwi -B path/to/schwi/build
cmake --build path/to/schwi/build --target schwi_visualization_export
```

## Minimal Example

```cpp
#include <bricks/schwi.hpp>

#include <chrono>
#include <cstddef>
#include <vector>

using namespace std::chrono_literals;

struct ButtonPress {
    int value = 0;
};

struct NodeState {
    int presses = 0;
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

    const auto phone = sim.add_device_class(
        NodeState{},
        bricks::schwi::on<ButtonPress>([](bricks::schwi::SimContext& ctx, NodeState& self, const ButtonPress& event) {
            ++self.presses;
            ctx.broadcast(std::vector<std::byte>{static_cast<std::byte>(event.value)});
        }));

    const auto receiver_class = sim.add_device_class(
        NodeState{},
        bricks::schwi::on<bricks::schwi::PacketReceived>(
            [](bricks::schwi::SimContext&, NodeState& self, const bricks::schwi::PacketReceived& event) {
                self.received.push_back(static_cast<int>(event.payload.at(0)));
            }));

    const auto sender = sim.add_device(phone);
    const auto receiver = sim.add_device(receiver_class);

    sim.set_position(sender, {0.0, 0.0});
    sim.set_position(receiver, {5.0, 0.0});

    sim.at(10ms, sender, ButtonPress{.value = 7});
    sim.run();

    return sim.state<NodeState>(receiver).received == std::vector<int>{7} ? 0 : 1;
}
```

## Scheduling Model

- `at(time_point, ...)` schedules work at an absolute simulation time.
- `at(duration, ...)` also uses absolute time, measured from simulation start.
- `after(duration, ...)` schedules relative to the current simulation time.
- Scheduling into the past throws `std::invalid_argument`.
- Radio broadcasts are delivered after `radio.delivery_delay`, which defaults to `1ns`.

## Device Classes

- `add_device_class(default_state, handlers...)` creates a reusable device definition.
- `add_device(device_class)` instantiates the definition with its default state.
- `add_device(device_class, override_state)` instantiates it with a different initial state.

## Observability

- `sim.log()` records device creation, moves, broadcasts, deliveries, and drops.
- `sim.trace()` records every scheduled event or action with parent-child links.
- `bricks::schwi::testing::print_log(sim, out)` and `print_trace(sim, out)` dump readable post-run text to an output stream.
- `bricks::schwi::visualization_json(sim)` exports `log()`, `trace()`, device metadata, and radio config as JSON for browser-based inspection.
- `bricks::schwi::visualization_json(sim, naming_registry)` lets callers override exported `state_key`/`event_key` and `state_name`/`event_name` fields explicitly.
- The exported payload uses format id `bricks.schwi.visualization` with schema version `1`.

## Headers

- [`bricks/schwi/core.hpp`](./include/bricks/schwi/core.hpp) contains the simulation core.
- [`bricks/schwi/testing.hpp`](./include/bricks/schwi/testing.hpp) contains small test helpers for log/trace assertions.
- [`bricks/schwi/visualization.hpp`](./include/bricks/schwi/visualization.hpp) contains the JSON export and naming-registry API.
- [`bricks/schwi.hpp`](./include/bricks/schwi.hpp) is the umbrella include that pulls in all three.

## Visualization

`schwi` includes a minimal export path and a standalone inspector UI:

- Export simulation data with `bricks::schwi::visualization_json(sim)`.
- Open [`examples/inspector.html`](./examples/inspector.html) in a browser.
- Paste the exported JSON or load it from a file to inspect timeline, topology, and causality together.

The included [`examples/export_visualization.cpp`](./examples/export_visualization.cpp) shows a small end-to-end flow that writes `schwi_visualization.json`.

From the standalone `schwi` project you can build and run the example directly:

```sh
cmake -S schwi -B /tmp/schwi-build
cmake --build /tmp/schwi-build --target schwi_visualization_export
cd /tmp && /tmp/schwi-build/schwi_visualization_export
```

Then open [`examples/inspector.html`](./examples/inspector.html) and load the generated `schwi_visualization.json` file.

```cpp
#include <bricks/schwi.hpp>
#include <fstream>

// ... build and run a Simulation named sim ...

bricks::schwi::VisualizationNamingRegistry naming;
naming.state_key<MyState>("node");
naming.state<MyState>("node");
naming.event_key<MyEvent>("button-press");
naming.event<MyEvent>("button-press");

std::ofstream out("schwi_visualization.json");
out << bricks::schwi::visualization_json(sim, naming);
```
