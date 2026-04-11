#pragma once

#include "core.hpp"

namespace bricks::schwi {

struct VisualizationNamingRegistry {
    std::unordered_map<std::type_index, std::string> state_keys;
    std::unordered_map<std::type_index, std::string> state_names;
    std::unordered_map<std::type_index, std::string> event_keys;
    std::unordered_map<std::type_index, std::string> event_names;

    template <typename State>
    VisualizationNamingRegistry& state_key(std::string key) {
        state_keys[std::type_index(typeid(State))] = std::move(key);
        return *this;
    }

    template <typename State>
    VisualizationNamingRegistry& state(std::string name) {
        state_names[std::type_index(typeid(State))] = std::move(name);
        return *this;
    }

    template <typename Event>
    VisualizationNamingRegistry& event_key(std::string key) {
        event_keys[std::type_index(typeid(Event))] = std::move(key);
        return *this;
    }

    template <typename Event>
    VisualizationNamingRegistry& event(std::string name) {
        event_names[std::type_index(typeid(Event))] = std::move(name);
        return *this;
    }
};

namespace detail {

inline const char* log_kind_name(LogEntry::Kind kind) {
    switch (kind) {
        case LogEntry::Kind::DeviceAdded:
            return "DeviceAdded";
        case LogEntry::Kind::DeviceMoved:
            return "DeviceMoved";
        case LogEntry::Kind::TargetedEventDispatched:
            return "TargetedEventDispatched";
        case LogEntry::Kind::GlobalEventDispatched:
            return "GlobalEventDispatched";
        case LogEntry::Kind::BroadcastSent:
            return "BroadcastSent";
        case LogEntry::Kind::PacketDelivered:
            return "PacketDelivered";
        case LogEntry::Kind::PacketDropped:
            return "PacketDropped";
    }
    return "Unknown";
}

inline const char* trace_kind_name(TraceEntry::Kind kind) {
    switch (kind) {
        case TraceEntry::Kind::TargetedEvent:
            return "TargetedEvent";
        case TraceEntry::Kind::GlobalEvent:
            return "GlobalEvent";
        case TraceEntry::Kind::Action:
            return "Action";
    }
    return "Unknown";
}

template <typename Rep, typename Period>
inline auto duration_count(std::chrono::duration<Rep, Period> duration) -> std::int64_t {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();
}

inline void append_json_string(std::string& out, const std::string& value) {
    out.push_back('"');
    for (unsigned char c : value) {
        switch (c) {
            case '\\':
                out += "\\\\";
                break;
            case '"':
                out += "\\\"";
                break;
            case '\b':
                out += "\\b";
                break;
            case '\f':
                out += "\\f";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (c < 0x20) {
                    static constexpr char hex[] = "0123456789abcdef";
                    out += "\\u00";
                    out.push_back(hex[(c >> 4) & 0x0F]);
                    out.push_back(hex[c & 0x0F]);
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    out.push_back('"');
}

template <typename T>
inline void append_json_number(std::string& out, T value) {
    char buffer[64];
    const auto [ptr, ec] = std::to_chars(buffer, buffer + sizeof(buffer), value);
    if (ec != std::errc{})
        throw std::runtime_error("failed to format JSON number");
    out.append(buffer, ptr);
}

inline void append_json_position(std::string& out, Position position) {
    out += "{\"x\":";
    append_json_number(out, position.x);
    out += ",\"y\":";
    append_json_number(out, position.y);
    out += "}";
}

inline void append_json_handle(std::string& out, std::optional<DeviceHandle> handle) {
    if (!handle.has_value()) {
        out += "null";
        return;
    }
    append_json_number(out, handle->value);
}

inline void append_json_event_id(std::string& out, std::optional<EventId> id) {
    if (!id.has_value()) {
        out += "null";
        return;
    }
    append_json_number(out, *id);
}

inline std::optional<DeviceHandle> exported_log_source(const LogEntry& entry) {
    switch (entry.kind) {
        case LogEntry::Kind::GlobalEventDispatched:
            return std::nullopt;
        default:
            return entry.source;
    }
}

inline std::optional<DeviceHandle> exported_log_target(const LogEntry& entry) {
    switch (entry.kind) {
        case LogEntry::Kind::TargetedEventDispatched:
        case LogEntry::Kind::PacketDelivered:
        case LogEntry::Kind::PacketDropped:
            return entry.target;
        default:
            return std::nullopt;
    }
}

inline std::optional<DeviceHandle> exported_log_peer(const LogEntry&) {
    return std::nullopt;
}

inline const std::string& key_for(std::unordered_map<std::type_index, std::string>& keys,
                                  std::type_index type,
                                  std::size_t& next,
                                  const char* prefix) {
    auto [it, inserted] = keys.emplace(type, std::string{});
    if (inserted)
        it->second = std::string(prefix) + std::to_string(next++);
    return it->second;
}

inline std::string key_name(const std::unordered_map<std::type_index, std::string>& overrides,
                            std::unordered_map<std::type_index, std::string>& generated,
                            std::type_index type,
                            std::size_t& next,
                            const char* prefix) {
    if (const auto it = overrides.find(type); it != overrides.end())
        return it->second;
    return key_for(generated, type, next, prefix);
}

inline std::string display_name(const std::unordered_map<std::type_index, std::string>& overrides,
                                std::type_index type,
                                const std::string& fallback) {
    if (const auto it = overrides.find(type); it != overrides.end())
        return it->second;
    return fallback;
}

} // namespace detail

inline std::string visualization_json(const Simulation& sim, const VisualizationNamingRegistry& registry) {
    std::string out;
    out.reserve(4096);

    std::unordered_map<std::type_index, std::string> state_keys;
    std::unordered_map<std::type_index, std::string> event_keys;
    std::size_t next_state_key = 0;
    std::size_t next_event_key = 0;

    out += "{\"format\":\"bricks.schwi.visualization\",\"schema_version\":1,\"time_unit_ns\":1,\"config\":{\"radio\":{";
    out += "\"reachability_threshold\":";
    detail::append_json_number(out, sim.m_config.radio.reachability_threshold);
    out += ",\"delivery_delay_ns\":";
    detail::append_json_number(out, detail::duration_count(sim.m_config.radio.delivery_delay));
    out += "}},\"devices\":[";

    for (std::size_t index = 0; index < sim.m_devices.size(); ++index) {
        if (index != 0)
            out.push_back(',');
        const auto& device = sim.m_devices[index];
        out += "{\"id\":";
        detail::append_json_number(out, index);
        out += ",\"state_key\":";
        detail::append_json_string(out, detail::key_name(registry.state_keys, state_keys, device.state_type, next_state_key, "state_"));
        out += ",\"state_name\":";
        detail::append_json_string(out, detail::display_name(registry.state_names, device.state_type, device.state_type_name));
        out += ",\"has_position\":";
        out += device.has_position ? "true" : "false";
        out += ",\"current_position\":";
        if (device.has_position) {
            detail::append_json_position(out, device.position);
        } else {
            out += "null";
        }
        out += "}";
    }

    out += "],\"trace\":[";
    for (std::size_t index = 0; index < sim.m_trace.size(); ++index) {
        if (index != 0)
            out.push_back(',');
        const auto& entry = sim.m_trace[index];
        out += "{\"id\":";
        detail::append_json_number(out, entry.id);
        out += ",\"parent_id\":";
        detail::append_json_event_id(out, entry.parent_id);
        out += ",\"time_ns\":";
        detail::append_json_number(out, detail::duration_count(entry.time.time_since_epoch()));
        out += ",\"kind\":";
        detail::append_json_string(out, detail::trace_kind_name(entry.kind));
        out += ",\"event_key\":";
        detail::append_json_string(out, detail::key_name(registry.event_keys, event_keys, entry.event_type, next_event_key, "event_"));
        out += ",\"event_name\":";
        detail::append_json_string(out, detail::display_name(registry.event_names, entry.event_type, entry.event_type_name));
        out += ",\"target\":";
        detail::append_json_handle(out, entry.target);
        out += "}";
    }

    out += "],\"log\":[";
    for (std::size_t index = 0; index < sim.m_log.size(); ++index) {
        if (index != 0)
            out.push_back(',');
        const auto& entry = sim.m_log[index];
        out += "{\"kind\":";
        detail::append_json_string(out, detail::log_kind_name(entry.kind));
        out += ",\"time_ns\":";
        detail::append_json_number(out, detail::duration_count(entry.time.time_since_epoch()));
        out += ",\"source\":";
        detail::append_json_handle(out, detail::exported_log_source(entry));
        out += ",\"target\":";
        detail::append_json_handle(out, detail::exported_log_target(entry));
        out += ",\"peer\":";
        detail::append_json_handle(out, detail::exported_log_peer(entry));
        out += ",\"rssi\":";
        detail::append_json_number(out, entry.rssi);
        out += ",\"payload_size\":";
        detail::append_json_number(out, entry.payload_size);
        out += ",\"position\":";
        if (entry.position.has_value()) {
            detail::append_json_position(out, *entry.position);
        } else {
            out += "null";
        }
        out += ",\"caused_by_event_id\":";
        detail::append_json_event_id(out, entry.caused_by_event_id);
        out += "}";
    }

    out += "]}";
    return out;
}

inline std::string visualization_json(const Simulation& sim) {
    return visualization_json(sim, VisualizationNamingRegistry{});
}

} // namespace bricks::schwi
