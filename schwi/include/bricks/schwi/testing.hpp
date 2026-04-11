#pragma once

#include "core.hpp"

#include <ostream>
#include <sstream>

namespace bricks::schwi::testing {

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

template <typename Duration>
auto ns_count(Duration duration) -> std::int64_t {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();
}

} // namespace detail

template <typename Predicate>
bool any_log_entry(const Simulation& sim, Predicate&& predicate) {
    return std::ranges::any_of(sim.log(), std::forward<Predicate>(predicate));
}

template <typename Predicate>
bool any_trace_entry(const Simulation& sim, Predicate&& predicate) {
    return std::ranges::any_of(sim.trace(), std::forward<Predicate>(predicate));
}

inline void print_log(const Simulation& sim, std::ostream& out) {
    for (const auto& entry : sim.log()) {
        out << detail::ns_count(entry.time.time_since_epoch())
            << "ns kind=" << detail::log_kind_name(entry.kind)
            << " source=" << entry.source.value;
        if (entry.kind == LogEntry::Kind::TargetedEventDispatched ||
            entry.kind == LogEntry::Kind::PacketDelivered ||
            entry.kind == LogEntry::Kind::PacketDropped) {
            out << " target=" << entry.target.value;
        }
        if (entry.kind == LogEntry::Kind::PacketDelivered || entry.kind == LogEntry::Kind::PacketDropped) {
            out << " rssi=" << entry.rssi;
        }
        if (entry.payload_size != 0) {
            out << " payload=" << entry.payload_size;
        }
        if (entry.position.has_value()) {
            out << " position=(" << entry.position->x << "," << entry.position->y << ")";
        }
        if (entry.caused_by_event_id.has_value()) {
            out << " cause=" << *entry.caused_by_event_id;
        }
        out << '\n';
    }
}

inline void print_trace(const Simulation& sim, std::ostream& out) {
    for (const auto& entry : sim.trace()) {
        out << "id=" << entry.id
            << " time=" << detail::ns_count(entry.time.time_since_epoch()) << "ns"
            << " kind=" << detail::trace_kind_name(entry.kind)
            << " event=" << entry.event_type_name;
        if (entry.target.has_value()) {
            out << " target=" << entry.target->value;
        }
        if (entry.parent_id.has_value()) {
            out << " parent=" << *entry.parent_id;
        }
        out << '\n';
    }
}

inline std::string log_text(const Simulation& sim) {
    std::ostringstream out;
    print_log(sim, out);
    return out.str();
}

inline std::string trace_text(const Simulation& sim) {
    std::ostringstream out;
    print_trace(sim, out);
    return out.str();
}

} // namespace bricks::schwi::testing
