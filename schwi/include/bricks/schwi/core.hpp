#pragma once

#include <cassert>
#include <algorithm>
#include <charconv>
#include <chrono>
#include <cmath>
#include <compare>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <queue>
#include <stdexcept>
#include <type_traits>
#include <typeindex>
#include <tuple>
#include <typeinfo>
#include <unordered_map>
#include <utility>
#include <vector>
#include <string>
#include <string_view>

namespace bricks::schwi {

/**
 * @brief Stable identifier for a device registered in a simulation.
 */
struct DeviceHandle {
    std::size_t value = 0;

    auto operator<=>(const DeviceHandle&) const = default;
};

/**
 * @brief Strongly typed handle for a device whose state type is known.
 */
template <typename State>
struct TypedDeviceHandle {
    DeviceHandle raw{};

    operator DeviceHandle() const {
        return raw;
    }

    auto operator<=>(const TypedDeviceHandle&) const = default;
};

/**
 * @brief Cartesian position used for radio reachability calculations.
 */
struct Position {
    double x = 0.0;
    double y = 0.0;
};

/**
 * @brief Unique identifier assigned to each scheduled item in the trace.
 */
using EventId = std::uint64_t;

/**
 * @brief Synthetic event delivered when a broadcast reaches another device.
 */
struct PacketReceived {
    DeviceHandle source{};
    double rssi = 0.0;
    std::vector<std::byte> payload;
};

/**
 * @brief Operational log entry emitted as the simulation runs.
 */
struct LogEntry {
    enum class Kind {
        DeviceAdded,
        DeviceMoved,
        TargetedEventDispatched,
        GlobalEventDispatched,
        BroadcastSent,
        PacketDelivered,
        PacketDropped,
    };

    using TimePoint = std::chrono::steady_clock::time_point;

    Kind kind{};
    TimePoint time{};
    DeviceHandle source{};
    DeviceHandle target{};
    DeviceHandle peer{};
    double rssi = 0.0;
    std::size_t payload_size = 0;
    std::optional<Position> position;
    std::optional<EventId> caused_by_event_id;
};

/**
 * @brief Scheduling trace entry for a targeted event, global event, or action.
 */
struct TraceEntry {
    enum class Kind {
        TargetedEvent,
        GlobalEvent,
        Action,
    };

    using TimePoint = std::chrono::steady_clock::time_point;

    EventId id = 0;
    std::optional<EventId> parent_id;
    TimePoint time{};
    Kind kind{};
    std::optional<DeviceHandle> target;
    std::type_index event_type = std::type_index(typeid(void));
    std::string event_type_name;
};

/**
 * @brief Radio propagation knobs used by broadcast delivery.
 */
struct RadioConfig {
    std::function<double(double)> rssi_from_distance = [](double distance) { return -30.0 - 20.0 * std::log10(std::max(distance, 1.0)); };
    double reachability_threshold = -75.0;
    std::chrono::steady_clock::duration delivery_delay = std::chrono::nanoseconds{1};
};

/**
 * @brief Top-level simulation configuration.
 */
struct Config {
    RadioConfig radio{};
};

namespace detail {
template <typename T>
constexpr std::string_view type_name();
} // namespace detail

struct VisualizationNamingRegistry;

/**
 * @brief Event subscription produced by @ref on and consumed by @ref Simulation::add_device_class.
 */
template <typename Event, typename Fn>
struct EventBinding {
    using event_type = Event;
    using fn_type = std::decay_t<Fn>;

    fn_type fn;
};

/**
 * @brief Bind an event type to a device handler.
 *
 * Handlers must be invocable as `(Context&, State&, const Event&)`.
 */
template <typename Event, typename Fn>
EventBinding<Event, Fn> on(Fn&& fn) {
    return EventBinding<Event, Fn>{std::forward<Fn>(fn)};
}

/**
 * @brief Reusable device definition consisting of a state factory and handlers.
 */
template <typename State, typename... Bindings>
struct DeviceClass {
    using state_type = State;

    struct FactoryConcept {
        virtual ~FactoryConcept() = default;
        virtual State create() = 0;
    };

    template <typename Factory>
    struct FactoryModel final : FactoryConcept {
        Factory factory;

        explicit FactoryModel(Factory factory) : factory(std::move(factory)) {}

        State create() override {
            return std::invoke(factory);
        }
    };

    std::shared_ptr<FactoryConcept> factory;
    std::tuple<Bindings...> bindings;
};

class Simulation;

/**
 * @brief Per-handler view of the running simulation.
 *
 * The context exposes the current time and device handle, plus helpers for
 * radio transmission, movement, and scheduling follow-up work.
 */
class Context {
public:
    using TimePoint = std::chrono::steady_clock::time_point;
    using Duration = std::chrono::steady_clock::duration;

    Context(Simulation& sim, DeviceHandle current) : m_sim(sim), m_current(current) {}

    /**
     * @brief Current simulation time.
     */
    [[nodiscard]] TimePoint now() const;
    /**
     * @brief Handle of the device whose handler is currently running.
     */
    [[nodiscard]] DeviceHandle self() const { return m_current; }

    /**
     * @brief Broadcast a payload to all reachable peers.
     */
    void broadcast(std::vector<std::byte> payload);
    /**
     * @brief Move the current device to a new position.
     */
    void move_to(Position position);
    /**
     * @brief Read the current position of another device.
     */
    [[nodiscard]] Position position(DeviceHandle handle) const;

    /**
     * @brief Schedule a targeted event at an absolute simulation time.
     */
    template <typename Event>
    void at(TimePoint when, DeviceHandle target, Event event);

    /**
     * @brief Schedule a targeted event at an absolute duration since time zero.
     */
    template <typename Rep, typename Period, typename Event>
    void at(std::chrono::duration<Rep, Period> when, DeviceHandle target, Event event);

    /**
     * @brief Schedule a global event at an absolute simulation time.
     */
    template <typename Event>
    void at(TimePoint when, Event event);

    /**
     * @brief Schedule a global event at an absolute duration since time zero.
     */
    template <typename Rep, typename Period, typename Event>
    void at(std::chrono::duration<Rep, Period> when, Event event);

    /**
     * @brief Schedule a targeted event relative to the current simulation time.
     */
    template <typename Event>
    void after(Duration delay, DeviceHandle target, Event event);

    /**
     * @brief Schedule a global event relative to the current simulation time.
     */
    template <typename Event>
    void after(Duration delay, Event event);

private:
    Simulation& m_sim;
    DeviceHandle m_current;
};

/**
 * @brief Discrete-event host-side simulator for device interactions.
 *
 * Devices own arbitrary runtime state stored behind move-only type erasure and
 * receive typed events through bindings registered with @ref add_device_class.
 */
class Simulation {
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;
    using Duration = Clock::duration;

    /**
     * @brief Create a simulation with optional radio configuration overrides.
     */
    explicit Simulation(Config config = {}) : m_config(std::move(config)) {}

    /**
     * @brief Add a reusable device definition backed by a state factory and one or more event bindings.
     */
    template <typename Factory, typename... Bindings>
    auto add_device_class(Factory&& factory, Bindings&&... bindings) {
        static_assert(std::is_invocable_v<Factory&>, "Factory must be callable with no arguments");
        using State = std::remove_cvref_t<std::invoke_result_t<Factory&>>;
        using DeviceClassT = DeviceClass<State, std::decay_t<Bindings>...>;
        using FactoryModelT = typename DeviceClassT::template FactoryModel<std::decay_t<Factory>>;

        return DeviceClassT{
            .factory = std::make_shared<FactoryModelT>(std::forward<Factory>(factory)),
            .bindings = std::tuple<std::decay_t<Bindings>...>{std::forward<Bindings>(bindings)...},
        };
    }

    /**
     * @brief Instantiate a device from a reusable device definition.
     */
    template <typename State, typename... Bindings>
    TypedDeviceHandle<State> add_device(const DeviceClass<State, Bindings...>& device_class) {
        return TypedDeviceHandle<State>{.raw = _instantiate_device(device_class.factory->create(), device_class.bindings,
                                                                   std::index_sequence_for<Bindings...>{})};
    }

    /**
     * @brief Access mutable device state by handle.
     */
    template <typename State>
    State& state(DeviceHandle handle) {
        Device& device = _device_at(handle);
        _require_state_type<State>(device);
        return *static_cast<State*>(device.state.get());
    }

    /**
     * @brief Access mutable device state through a typed device handle.
     */
    template <typename State>
    State& state(TypedDeviceHandle<State> handle) {
        return state<State>(handle.raw);
    }

    /**
     * @brief Access immutable device state by handle.
     */
    template <typename State>
    const State& state(DeviceHandle handle) const {
        const Device& device = _device_at(handle);
        _require_state_type<State>(device);
        return *static_cast<const State*>(device.state.get());
    }

    /**
     * @brief Access immutable device state through a typed device handle.
     */
    template <typename State>
    const State& state(TypedDeviceHandle<State> handle) const {
        return state<State>(handle.raw);
    }

    /**
     * @brief Current simulation time.
     */
    [[nodiscard]] TimePoint now() const {
        return m_now;
    }

    /**
     * @brief Run until the event queue is empty.
     */
    void run() {
        while (!m_queue.empty()) {
            ScheduledEvent event = std::move(const_cast<ScheduledEvent&>(m_queue.top()));
            m_queue.pop();
            m_now = event.time;
            m_current_event_id = event.id;
            struct CurrentEventReset {
                std::optional<EventId>& current_event_id;
                ~CurrentEventReset() {
                    current_event_id.reset();
                }
            } reset{m_current_event_id};
            event.action(*this);
        }
    }

    /**
     * @brief Run all scheduled work up to and including @p until.
     */
    void run_until(TimePoint until) {
        while (!m_queue.empty() && m_queue.top().time <= until) {
            ScheduledEvent event = std::move(const_cast<ScheduledEvent&>(m_queue.top()));
            m_queue.pop();
            m_now = event.time;
            m_current_event_id = event.id;
            struct CurrentEventReset {
                std::optional<EventId>& current_event_id;
                ~CurrentEventReset() {
                    current_event_id.reset();
                }
            } reset{m_current_event_id};
            event.action(*this);
        }
        m_now = std::max(m_now, until);
    }

    /**
     * @brief Schedule a targeted event at an absolute simulation time.
     *
     * @throws std::invalid_argument if @p when is earlier than @ref now().
     */
    template <typename Event>
    void at(TimePoint when, DeviceHandle target, Event event) {
        _schedule(when, TraceEntry::Kind::TargetedEvent, target, std::type_index(typeid(Event)),
                 std::string(detail::type_name<Event>()),
                 [this, target, event = std::move(event)](Simulation& sim) mutable {
                     sim.m_log.push_back(LogEntry{
                         .kind = LogEntry::Kind::TargetedEventDispatched,
                         .time = sim.m_now,
                         .source = target,
                         .target = target,
                         .position = std::nullopt,
                         .caused_by_event_id = sim.m_current_event_id,
                     });
                     sim._dispatch_to(target, event);
                 });
    }

    /**
     * @brief Schedule a targeted event at an absolute duration since time zero.
     *
     * @throws std::invalid_argument if @p when is earlier than @ref now().
     */
    template <typename Rep, typename Period, typename Event>
    void at(std::chrono::duration<Rep, Period> when, DeviceHandle target, Event event) {
        at(TimePoint{std::chrono::duration_cast<Duration>(when)}, target, std::move(event));
    }

    /**
     * @brief Schedule a global event at an absolute simulation time.
     *
     * @throws std::invalid_argument if @p when is earlier than @ref now().
     */
    template <typename Event>
        requires (!std::invocable<Event, Simulation&>)
    void at(TimePoint when, Event event) {
        _schedule(when, TraceEntry::Kind::GlobalEvent, std::nullopt, std::type_index(typeid(Event)),
                 std::string(detail::type_name<Event>()),
                 [this, event = std::move(event)](Simulation& sim) mutable {
                     sim.m_log.push_back(LogEntry{
                         .kind = LogEntry::Kind::GlobalEventDispatched,
                         .time = sim.m_now,
                         .position = std::nullopt,
                         .caused_by_event_id = sim.m_current_event_id,
                     });
                     sim._dispatch_global(event);
                 });
    }

    /**
     * @brief Schedule a global event at an absolute duration since time zero.
     *
     * @throws std::invalid_argument if @p when is earlier than @ref now().
     */
    template <typename Rep, typename Period, typename Event>
        requires (!std::invocable<Event, Simulation&>)
    void at(std::chrono::duration<Rep, Period> when, Event event) {
        at(TimePoint{std::chrono::duration_cast<Duration>(when)}, std::move(event));
    }

    /**
     * @brief Schedule an arbitrary action at an absolute simulation time.
     *
     * @throws std::invalid_argument if @p when is earlier than @ref now().
     */
    template <typename Fn>
        requires std::invocable<Fn, Simulation&>
    void at(TimePoint when, Fn&& fn) {
        using ActionType = std::decay_t<Fn>;
        _schedule(when, TraceEntry::Kind::Action, std::nullopt, std::type_index(typeid(ActionType)),
                 std::string(detail::type_name<ActionType>()),
                 [callable = std::forward<Fn>(fn)](Simulation& sim) mutable { callable(sim); });
    }

    /**
     * @brief Schedule an arbitrary action at an absolute duration since time zero.
     *
     * @throws std::invalid_argument if @p when is earlier than @ref now().
     */
    template <typename Rep, typename Period, typename Fn>
        requires std::invocable<Fn, Simulation&>
    void at(std::chrono::duration<Rep, Period> when, Fn&& fn) {
        at(TimePoint{std::chrono::duration_cast<Duration>(when)}, std::forward<Fn>(fn));
    }

    /**
     * @brief Schedule a targeted event relative to the current simulation time.
     */
    template <typename Event>
    void after(Duration delay, DeviceHandle target, Event event) {
        at(m_now + delay, target, std::move(event));
    }

    /**
     * @brief Schedule a global event relative to the current simulation time.
     */
    template <typename Event>
        requires (!std::invocable<Event, Simulation&>)
    void after(Duration delay, Event event) {
        at(m_now + delay, std::move(event));
    }

    /**
     * @brief Schedule an arbitrary action relative to the current simulation time.
     */
    template <typename Fn>
        requires std::invocable<Fn, Simulation&>
    void after(Duration delay, Fn&& fn) {
        at(m_now + delay, std::forward<Fn>(fn));
    }

    /**
     * @brief Set the position of a device for future radio calculations.
     */
    void set_position(DeviceHandle handle, Position position) {
        Device& device = _device_at(handle);
        device.position = position;
        device.has_position = true;
        m_log.push_back(LogEntry{
            .kind = LogEntry::Kind::DeviceMoved,
            .time = m_now,
            .source = handle,
            .position = position,
            .caused_by_event_id = m_current_event_id,
        });
    }

    /**
     * @brief Read the current position of a device.
     */
    [[nodiscard]] Position position(DeviceHandle handle) const {
        return _device_at(handle).position;
    }

    /**
     * @brief Chronological operational log emitted during simulation.
     */
    [[nodiscard]] const std::vector<LogEntry>& log() const {
        return m_log;
    }

    /**
     * @brief Scheduling trace for all events and actions created in the simulation.
     */
    [[nodiscard]] const std::vector<TraceEntry>& trace() const {
        return m_trace;
    }

private:
    friend class Context;
    friend std::string visualization_json(const Simulation& sim);
    friend std::string visualization_json(const Simulation& sim, const VisualizationNamingRegistry& registry);

    template <typename State, typename... Bindings>
    DeviceHandle _add_device_instance(State initial_state, Bindings&&... bindings) {
        DeviceHandle handle{m_devices.size()};
        Device device;
        device.state = _make_state_storage(std::move(initial_state));
        device.state_type = std::type_index(typeid(State));
        device.state_type_name = std::string(detail::type_name<State>());
        (_register_binding<State>(device, std::forward<Bindings>(bindings)), ...);
        m_devices.push_back(std::move(device));
        m_log.push_back(LogEntry{
            .kind = LogEntry::Kind::DeviceAdded,
            .time = m_now,
            .source = handle,
            .position = std::nullopt,
            .caused_by_event_id = std::nullopt,
        });
        return handle;
    }

    struct ErasedHandler {
        std::function<void(Context&, void*, const void*)> invoke;
    };

    struct Device {
        std::unique_ptr<void, void (*)(void*)> state{nullptr, +[](void*) {}};
        std::type_index state_type{typeid(void)};
        std::string state_type_name;
        Position position{};
        bool has_position = false;
        std::unordered_map<std::type_index, std::vector<ErasedHandler>> handlers;
    };

    struct ScheduledEvent {
        EventId id = 0;
        TimePoint time{};
        std::uint64_t order = 0;
        std::function<void(Simulation&)> action;
    };

    struct ScheduledEventCompare {
        auto operator()(const ScheduledEvent& lhs, const ScheduledEvent& rhs) const -> bool {
            if (lhs.time != rhs.time)
                return lhs.time > rhs.time;
            return lhs.order > rhs.order;
        }
    };

    template <typename State, typename Binding>
    void _register_binding(Device& device, Binding&& binding) {
        using DecayedBinding = std::decay_t<Binding>;
        using Event = typename DecayedBinding::event_type;
        auto& bucket = device.handlers[std::type_index(typeid(Event))];
        bucket.push_back(ErasedHandler{
            .invoke =
                [fn = std::forward<Binding>(binding).fn](Context& ctx, void* erased_state, const void* erased_event) mutable {
                    static_assert(std::is_invocable_v<decltype(fn), Context&, State&, const Event&>,
                                  "Event handler must be invocable with (Context&, State&, const Event&)");
                    State& state = *static_cast<State*>(erased_state);
                    const Event& event = *static_cast<const Event*>(erased_event);
                    fn(ctx, state, event);
                },
        });
    }

    template <typename State, typename Tuple, std::size_t... I>
    DeviceHandle _instantiate_device(State initial_state, const Tuple& bindings, std::index_sequence<I...>) {
        return _add_device_instance(std::move(initial_state), std::get<I>(bindings)...);
    }

    template <typename State>
    static std::unique_ptr<void, void (*)(void*)> _make_state_storage(State&& state) {
        using StoredState = std::remove_cvref_t<State>;
        return {new StoredState(std::forward<State>(state)),
                +[](void* ptr) { delete static_cast<StoredState*>(ptr); }};
    }

    template <typename State>
    static void _require_state_type(const Device& device) {
        if (device.state_type != std::type_index(typeid(State)))
            throw std::bad_cast{};
    }

    void _schedule(TimePoint when, TraceEntry::Kind kind, std::optional<DeviceHandle> target, std::type_index event_type,
                  std::string event_type_name, std::function<void(Simulation&)> action) {
        if (when < m_now)
            throw std::invalid_argument("cannot schedule an event in the past");
        const EventId id = m_next_event_id++;
        m_trace.push_back(TraceEntry{
            .id = id,
            .parent_id = m_current_event_id,
            .time = when,
            .kind = kind,
            .target = target,
            .event_type = event_type,
            .event_type_name = std::move(event_type_name),
        });
        m_queue.push(ScheduledEvent{
            .id = id,
            .time = when,
            .order = m_next_order++,
            .action = std::move(action),
        });
    }

    template <typename Event>
    void _dispatch_to(DeviceHandle handle, const Event& event) {
        Device& device = _device_at(handle);
        auto it = device.handlers.find(std::type_index(typeid(Event)));
        if (it == device.handlers.end())
            return;

        Context ctx(*this, handle);
        for (const ErasedHandler& handler : it->second)
            handler.invoke(ctx, device.state.get(), &event);
    }

    template <typename Event>
    void _dispatch_global(const Event& event) {
        for (std::size_t index = 0; index < m_devices.size(); ++index)
            _dispatch_to(DeviceHandle{index}, event);
    }

    void _broadcast(DeviceHandle source, std::vector<std::byte> payload) {
        const Device& sender = _device_at(source);
        m_log.push_back(LogEntry{
            .kind = LogEntry::Kind::BroadcastSent,
            .time = m_now,
            .source = source,
            .payload_size = payload.size(),
            .position = std::nullopt,
            .caused_by_event_id = m_current_event_id,
        });

        if (!sender.has_position)
            return;

        for (std::size_t index = 0; index < m_devices.size(); ++index) {
            DeviceHandle target{index};
            if (target == source)
                continue;

            const Device& receiver = m_devices[index];
            if (!receiver.has_position)
                continue;

            const double rssi = _compute_rssi(sender.position, receiver.position);
            if (rssi >= m_config.radio.reachability_threshold) {
                const TimePoint delivery_time = m_now + m_config.radio.delivery_delay;
                m_log.push_back(LogEntry{
                    .kind = LogEntry::Kind::PacketDelivered,
                    .time = delivery_time,
                    .source = source,
                    .target = target,
                    .rssi = rssi,
                    .payload_size = payload.size(),
                    .position = std::nullopt,
                    .caused_by_event_id = m_current_event_id,
                });
                at(delivery_time, target, PacketReceived{
                                          .source = source,
                                          .rssi = rssi,
                                          .payload = payload,
                                      });
            } else {
                m_log.push_back(LogEntry{
                    .kind = LogEntry::Kind::PacketDropped,
                    .time = m_now,
                    .source = source,
                    .target = target,
                    .rssi = rssi,
                    .payload_size = payload.size(),
                    .position = std::nullopt,
                    .caused_by_event_id = m_current_event_id,
                });
            }
        }
    }

    [[nodiscard]] double _compute_rssi(Position lhs, Position rhs) const {
        const double dx = lhs.x - rhs.x;
        const double dy = lhs.y - rhs.y;
        const double distance = std::sqrt(dx * dx + dy * dy);
        return m_config.radio.rssi_from_distance(distance);
    }

    Device& _device_at(DeviceHandle handle) {
        if (handle.value >= m_devices.size())
            throw std::out_of_range("invalid device handle");
        return m_devices[handle.value];
    }

    const Device& _device_at(DeviceHandle handle) const {
        if (handle.value >= m_devices.size())
            throw std::out_of_range("invalid device handle");
        return m_devices[handle.value];
    }

    Config m_config;
    TimePoint m_now{};
    std::vector<Device> m_devices;
    std::priority_queue<ScheduledEvent, std::vector<ScheduledEvent>, ScheduledEventCompare> m_queue;
    std::uint64_t m_next_order = 0;
    EventId m_next_event_id = 1;
    std::optional<EventId> m_current_event_id;
    std::vector<LogEntry> m_log;
    std::vector<TraceEntry> m_trace;
};

inline Context::TimePoint Context::now() const {
    return m_sim.now();
}

inline void Context::broadcast(std::vector<std::byte> payload) {
    m_sim._broadcast(m_current, std::move(payload));
}

inline void Context::move_to(Position position) {
    m_sim.set_position(m_current, position);
}

inline Position Context::position(DeviceHandle handle) const {
    return m_sim.position(handle);
}

template <typename Event>
inline void Context::at(TimePoint when, DeviceHandle target, Event event) {
    m_sim.at(when, target, std::move(event));
}

template <typename Rep, typename Period, typename Event>
inline void Context::at(std::chrono::duration<Rep, Period> when, DeviceHandle target, Event event) {
    m_sim.at(when, target, std::move(event));
}

template <typename Event>
inline void Context::at(TimePoint when, Event event) {
    m_sim.at(when, std::move(event));
}

template <typename Rep, typename Period, typename Event>
inline void Context::at(std::chrono::duration<Rep, Period> when, Event event) {
    m_sim.at(when, std::move(event));
}

template <typename Event>
inline void Context::after(Duration delay, DeviceHandle target, Event event) {
    m_sim.after(delay, target, std::move(event));
}

template <typename Event>
inline void Context::after(Duration delay, Event event) {
    m_sim.after(delay, std::move(event));
}

} // namespace bricks::schwi

namespace bricks::schwi {

namespace detail {

template <typename T>
constexpr std::string_view type_name() {
#if defined(__clang__) || defined(__GNUC__)
    constexpr std::string_view signature = __PRETTY_FUNCTION__;
    constexpr std::string_view key = "T = ";
    const std::size_t start = signature.find(key);
    if (start == std::string_view::npos)
        return signature;
    const std::size_t value_start = start + key.size();
    const std::size_t value_end = signature.find_first_of(";]", value_start);
    return signature.substr(value_start, value_end - value_start);
#elif defined(_MSC_VER)
    constexpr std::string_view signature = __FUNCSIG__;
    constexpr std::string_view key = "type_name<";
    const std::size_t start = signature.find(key);
    if (start == std::string_view::npos)
        return signature;
    const std::size_t value_start = start + key.size();
    const std::size_t value_end = signature.find(">(void)", value_start);
    return signature.substr(value_start, value_end - value_start);
#else
    return "unknown";
#endif
}

} // namespace detail

} // namespace bricks::schwi
