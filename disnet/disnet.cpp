#include "bricks/disnet.hpp"
#include "bricks/disnet/instance.hpp"

#include <memory>

namespace {

using Instance = bricks::disnet::instance::Instance;
using InstancePtr = bricks::disnet::instance::InstancePtr;

Instance& global_instance() {
    static InstancePtr inst = bricks::disnet::instance::create();
    return *inst;
}

} // namespace

namespace bricks::disnet {

bool default_input_filter(const message::Header& header) {
    return instance::default_input_filter(global_instance(), header);
}

bool default_processing_filter(const message::Header& header) {
    return instance::default_processing_filter(global_instance(), header);
}

bool default_forwarding_filter(const message::Header& header) {
    return instance::default_forwarding_filter(global_instance(), header);
}

void init() {
    instance::init(global_instance());
}

bool is_initialized() {
    return instance::is_initialized(global_instance());
}

void shutdown() {
    instance::shutdown(global_instance());
}

void activate_channel(std::uint8_t channel) {
    instance::activate_channel(global_instance(), channel);
}

bool is_channel_active(std::uint8_t channel) {
    return instance::is_channel_active(global_instance(), channel);
}

void register_handler(std::uint8_t channel, Callback cb) {
    instance::register_handler(global_instance(), channel, std::move(cb));
}

void set_input_filter(Predicate predicate) {
    instance::set_input_filter(global_instance(), std::move(predicate));
}

void set_processing_filter(Predicate predicate) {
    instance::set_processing_filter(global_instance(), std::move(predicate));
}

void set_forwarding_filter(Predicate predicate) {
    instance::set_forwarding_filter(global_instance(), std::move(predicate));
}

bool process_one(std::chrono::milliseconds time_to_wait) {
    return instance::process_one(global_instance(), time_to_wait);
}

void send_raw(std::uint8_t channel,
              std::uint8_t ttl,
              const std::set<MacAddress>& targets,
              std::span<const std::uint8_t> payload) {
    instance::send_raw(global_instance(), channel, ttl, targets, payload);
}

AckFuture send_reliable(std::uint8_t channel,
                        std::uint8_t ttl,
                        const std::set<MacAddress>& targets,
                        std::span<const std::uint8_t> payload) {
    return instance::send_reliable(global_instance(), channel, ttl, targets, payload);
}

AckFuture send_segmented(std::uint8_t channel,
                         std::uint8_t ttl,
                         const std::set<MacAddress>& targets,
                         std::span<const std::uint8_t> payload) {
    return instance::send_segmented(global_instance(), channel, ttl, targets, payload);
}

void send_heartbeat(std::uint8_t channel, std::uint8_t ttl) {
    instance::send_heartbeat(global_instance(), channel, ttl);
}

void ensure_heartbeat(std::uint8_t channel, std::uint8_t ttl, TimePoint cutoff) {
    instance::ensure_heartbeat(global_instance(), channel, ttl, cutoff);
}

TimePoint last_heartbeat(std::uint8_t channel, const MacAddress& address) {
    return instance::last_heartbeat(global_instance(), channel, address);
}

std::vector<std::pair<MacAddress, TimePoint>> neighbours(std::uint8_t channel, std::optional<TimePoint> cutoff) {
    return instance::neighbours(global_instance(), channel, cutoff);
}

namespace core {

message::Id build_and_send(std::uint8_t channel,
                           std::uint8_t ttl,
                           message::Type type,
                           std::span<const MacAddress> targets,
                           std::span<const std::uint8_t> payload) {
    return instance::core::build_and_send(global_instance(), channel, ttl, type, targets, payload);
}

void dispatch(const MacAddress& source, std::uint8_t channel, std::span<const std::uint8_t> payload) {
    instance::core::dispatch(global_instance(), source, channel, payload);
}

} // namespace core

namespace reliable {

void handle_ack(std::span<const std::uint8_t> payload_span) {
    instance::reliable::handle_ack(global_instance(), payload_span);
}
 
} // namespace reliable

namespace segmented {

void handle_segmented_announce(const message::Header& hdr, std::span<const std::uint8_t> payload) {
    instance::segmented::handle_segmented_announce(global_instance(), hdr, payload);
}

void handle_segmented_symbol(const message::Header& hdr, std::span<const std::uint8_t> payload) {
    instance::segmented::handle_segmented_symbol(global_instance(), hdr, payload);
}

void handle_segmented_ack(const message::Header& hdr, std::span<const std::uint8_t> payload) {
    instance::segmented::handle_segmented_ack(global_instance(), hdr, payload);
}

void handle_segmented_nack(const message::Header& hdr, std::span<const std::uint8_t> payload) {
    instance::segmented::handle_segmented_nack(global_instance(), hdr, payload);
}

} // namespace segmented

} // namespace bricks::disnet
