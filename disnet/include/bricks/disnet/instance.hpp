#pragma once

#include "bricks/disnet.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <vector>
#include <functional>

namespace bricks::disnet::instance {

struct RadioOps {
    using RxCallback = std::function<void(const MacAddress&, const std::uint8_t*, int)>;

    std::function<esp_err_t()> init;
    std::function<esp_err_t()> deinit;
    std::function<esp_err_t(RxCallback)> register_recv_cb;
    std::function<esp_err_t()> unregister_recv_cb;
    std::function<esp_err_t(const MacAddress&)> add_broadcast_peer;
    std::function<esp_err_t(const MacAddress&, const std::uint8_t*, int)> send;
};

RadioOps default_radio_ops();

struct Instance;

using InstancePtr = std::unique_ptr<Instance, void(*)(Instance*)>;

InstancePtr create();
InstancePtr create(RadioOps ops);
void destroy(Instance* inst);

bool default_input_filter(const Instance& inst, const message::Header& header);
bool default_processing_filter(const Instance& inst, const message::Header& header);
bool default_forwarding_filter(const Instance& inst, const message::Header& header);

void init(Instance& inst);
bool is_initialized(const Instance& inst);
void shutdown(Instance& inst);

void activate_channel(Instance& inst, std::uint8_t channel);
bool is_channel_active(const Instance& inst, std::uint8_t channel);

void register_handler(Instance& inst, std::uint8_t channel, Callback cb);

void set_input_filter(Instance& inst, Predicate predicate);
void set_processing_filter(Instance& inst, Predicate predicate);
void set_forwarding_filter(Instance& inst, Predicate predicate);

bool process_one(Instance& inst, std::chrono::milliseconds time_to_wait = {});

void send_raw(Instance& inst,
              std::uint8_t channel,
              std::uint8_t ttl,
              const std::set<MacAddress>& targets,
              std::span<const std::uint8_t> payload);

AckFuture send_reliable(Instance& inst,
                        std::uint8_t channel,
                        std::uint8_t ttl,
                        const std::set<MacAddress>& targets,
                        std::span<const std::uint8_t> payload);

AckFuture send_segmented(Instance& inst,
                         std::uint8_t channel,
                         std::uint8_t ttl,
                         const std::set<MacAddress>& targets,
                         std::span<const std::uint8_t> payload);

void send_heartbeat(Instance& inst, std::uint8_t channel, std::uint8_t ttl);

void ensure_heartbeat(Instance& inst, std::uint8_t channel, std::uint8_t ttl, TimePoint cutoff);

TimePoint last_heartbeat(const Instance& inst, std::uint8_t channel, const MacAddress& address);

std::vector<std::pair<MacAddress, TimePoint>> neighbours(const Instance& inst, std::uint8_t channel, std::optional<TimePoint> cutoff = std::nullopt);

namespace core {

message::Id build_and_send(Instance& inst,
                           std::uint8_t channel,
                           std::uint8_t ttl,
                           message::Type type,
                           std::span<const MacAddress> targets,
                           std::span<const std::uint8_t> payload);

void dispatch(Instance& inst,
              const MacAddress& source,
              std::uint8_t channel,
              std::span<const std::uint8_t> payload);

} // namespace core

namespace reliable {

void handle_ack(Instance& inst, std::span<const std::uint8_t> payload_span);

} // namespace reliable

namespace segmented {

void handle_segmented_announce(Instance& inst, const message::Header& hdr, std::span<const std::uint8_t> payload);
void handle_segmented_symbol(Instance& inst, const message::Header& hdr, std::span<const std::uint8_t> payload);
void handle_segmented_ack(Instance& inst, const message::Header& hdr, std::span<const std::uint8_t> payload);
void handle_segmented_nack(Instance& inst, const message::Header& hdr, std::span<const std::uint8_t> payload);

} // namespace segmented

} // namespace bricks::disnet::instance
