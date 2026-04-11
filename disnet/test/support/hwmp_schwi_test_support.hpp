#pragma once

#include "bricks/disnet/flood.hpp"
#include "bricks/disnet/hwmp.hpp"
#include "bricks/schwi.hpp"
#include "schwi_transport.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace bricks::disnet::test {

using namespace std::chrono_literals;

struct SendPacket {
    SchwiAddress target{};
    std::vector<std::uint8_t> payload;
};

struct InjectPacket {
    TransportPacket<SchwiAddress> packet;
};

template <typename RouterT>
struct RouterNode {
    using Address = SchwiAddress;
    using Config = typename RouterT::Config;

    Address address{};
    std::unique_ptr<SchwiTransport> transport;
    std::unique_ptr<RouterT> router;
    std::vector<std::vector<std::uint8_t>> delivered_payloads;
    std::vector<TransportPacket<Address>> inbound_packets;

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
        transport->register_callback([this](TransportPacket<Address> packet) {
            inbound_packets.push_back(packet);
            router->handle_packet(packet);
        });
        router->register_callback([this](TransportPacket<Address> packet) {
            delivered_payloads.push_back(std::move(packet.payload));
        });
    }
};

enum class HwmpFrameType : std::uint8_t {
    Data = 0,
    Preq = 1,
    Prep = 2,
    Perr = 3,
};

template <typename T>
void append_bytes(std::vector<std::uint8_t>& out, const T& value) {
    const std::size_t offset = out.size();
    out.resize(offset + sizeof(T));
    std::memcpy(out.data() + offset, &value, sizeof(T));
}

template <typename T>
T read_bytes(const std::vector<std::uint8_t>& in, std::size_t& offset) {
    T value{};
    assert(offset + sizeof(T) <= in.size());
    std::memcpy(&value, in.data() + offset, sizeof(T));
    offset += sizeof(T);
    return value;
}

inline std::vector<std::uint8_t> encode_prep(SchwiAddress originator, SchwiAddress target, std::uint32_t target_seq,
                                             std::uint32_t metric, std::uint8_t ttl = 5) {
    std::vector<std::uint8_t> out;
    append_bytes(out, HwmpFrameType::Prep);
    append_bytes(out, ttl);
    append_bytes(out, originator);
    append_bytes(out, target);
    append_bytes(out, target_seq);
    append_bytes(out, metric);
    return out;
}

inline std::vector<std::uint8_t> encode_preq(SchwiAddress originator, std::uint32_t preq_id, SchwiAddress target,
                                             std::uint32_t originator_seq = 1, std::uint32_t target_seq = 0,
                                             std::uint32_t metric = 0, std::uint8_t ttl = 5, std::uint8_t flags = 0) {
    std::vector<std::uint8_t> out;
    append_bytes(out, HwmpFrameType::Preq);
    append_bytes(out, ttl);
    append_bytes(out, flags);
    append_bytes(out, preq_id);
    append_bytes(out, originator);
    append_bytes(out, originator_seq);
    append_bytes(out, target);
    append_bytes(out, target_seq);
    append_bytes(out, metric);
    return out;
}

inline std::vector<std::uint8_t> encode_perr(SchwiAddress destination, std::uint32_t destination_seq) {
    std::vector<std::uint8_t> out;
    append_bytes(out, HwmpFrameType::Perr);
    append_bytes(out, destination);
    append_bytes(out, destination_seq);
    return out;
}

inline HwmpFrameType frame_type(const TransportPacket<SchwiAddress>& packet) {
    std::size_t offset = 0;
    return read_bytes<HwmpFrameType>(packet.payload, offset);
}

inline std::uint8_t frame_ttl(const TransportPacket<SchwiAddress>& packet) {
    std::size_t offset = 0;
    const HwmpFrameType type = read_bytes<HwmpFrameType>(packet.payload, offset);
    assert(type == HwmpFrameType::Data || type == HwmpFrameType::Preq || type == HwmpFrameType::Prep);
    return read_bytes<std::uint8_t>(packet.payload, offset);
}

inline std::uint8_t preq_flags(const TransportPacket<SchwiAddress>& packet) {
    std::size_t offset = sizeof(HwmpFrameType) + sizeof(std::uint8_t);
    return read_bytes<std::uint8_t>(packet.payload, offset);
}

inline std::vector<std::uint8_t> data_payload(const TransportPacket<SchwiAddress>& packet) {
    std::size_t offset = 0;
    const HwmpFrameType type = read_bytes<HwmpFrameType>(packet.payload, offset);
    assert(type == HwmpFrameType::Data);
    offset += sizeof(std::uint8_t);
    offset += sizeof(SchwiAddress);
    offset += sizeof(SchwiAddress);
    offset += sizeof(std::uint32_t);
    return {packet.payload.begin() + static_cast<std::ptrdiff_t>(offset), packet.payload.end()};
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

inline bricks::schwi::Simulation make_line_simulation(double spacing = 5.0, double threshold = -36.0) {
    (void)spacing;
    return bricks::schwi::Simulation({
        .radio = {
            .rssi_from_distance = [](double distance) { return -30.0 - distance; },
            .reachability_threshold = threshold,
        },
    });
}

template <typename PacketT>
std::size_t count_frames(const std::vector<PacketT>& packets, HwmpFrameType type) {
    return static_cast<std::size_t>(
        std::count_if(packets.begin(), packets.end(), [type](const auto& packet) { return frame_type(packet) == type; }));
}

} // namespace bricks::disnet::test
