#pragma once

#include "bricks/disnet/hwmp.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <ostream>
#include <utility>
#include <vector>

namespace bricks::disnet::test {

using namespace std::chrono_literals;

struct FakeClock {
    using time_point = std::chrono::steady_clock::time_point;
    using duration = std::chrono::steady_clock::duration;

    static time_point now() { return s_now; }
    static void advance(std::chrono::milliseconds by) { s_now += by; }
    static void reset() { s_now = time_point{}; }

    inline static time_point s_now{};
};

struct FakeAddress {
    std::uint8_t value = 0;

    auto operator<=>(const FakeAddress&) const = default;

    friend std::ostream& operator<<(std::ostream& os, const FakeAddress& addr) {
        return os << static_cast<unsigned>(addr.value);
    }
};

struct FakeTransport {
    using Address = FakeAddress;
    static constexpr std::size_t max_payload_size = 256;

    explicit FakeTransport(Address self) : self(self) {}

    static constexpr Address broadcast_address() {
        return Address{0xFF};
    }

    Address my_address() const {
        return self;
    }

    void send(TransportPacket<Address> packet) {
        sent.push_back(std::move(packet));
    }

    void register_callback(TransportReceiveCallback<Address> callback) {
        callback_ = std::move(callback);
    }

    Address self;
    std::vector<TransportPacket<Address>> sent;
    TransportReceiveCallback<Address> callback_;
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

inline std::vector<std::uint8_t> encode_preq(FakeAddress originator, std::uint32_t preq_id, FakeAddress target,
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

inline std::vector<std::uint8_t> encode_prep(FakeAddress originator, FakeAddress target, std::uint32_t target_seq,
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

inline std::vector<std::uint8_t> encode_perr(FakeAddress destination, std::uint32_t destination_seq) {
    std::vector<std::uint8_t> out;
    append_bytes(out, HwmpFrameType::Perr);
    append_bytes(out, destination);
    append_bytes(out, destination_seq);
    return out;
}

inline std::vector<std::uint8_t> encode_data(FakeAddress source, FakeAddress target, std::uint32_t source_seq,
                                             std::vector<std::uint8_t> payload, std::uint8_t ttl = 5) {
    std::vector<std::uint8_t> out;
    append_bytes(out, HwmpFrameType::Data);
    append_bytes(out, ttl);
    append_bytes(out, source);
    append_bytes(out, target);
    append_bytes(out, source_seq);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

inline HwmpFrameType frame_type(const TransportPacket<FakeAddress>& packet) {
    std::size_t offset = 0;
    return read_bytes<HwmpFrameType>(packet.payload, offset);
}

inline std::uint8_t data_ttl(const TransportPacket<FakeAddress>& packet) {
    std::size_t offset = 0;
    const HwmpFrameType type = read_bytes<HwmpFrameType>(packet.payload, offset);
    assert(type == HwmpFrameType::Data);
    return read_bytes<std::uint8_t>(packet.payload, offset);
}

inline FakeAddress data_source(const TransportPacket<FakeAddress>& packet) {
    std::size_t offset = sizeof(HwmpFrameType) + sizeof(std::uint8_t);
    return read_bytes<FakeAddress>(packet.payload, offset);
}

inline FakeAddress data_target(const TransportPacket<FakeAddress>& packet) {
    std::size_t offset = sizeof(HwmpFrameType) + sizeof(std::uint8_t) + sizeof(FakeAddress);
    return read_bytes<FakeAddress>(packet.payload, offset);
}

inline std::vector<std::uint8_t> data_payload(const TransportPacket<FakeAddress>& packet) {
    std::size_t offset = 0;
    const HwmpFrameType type = read_bytes<HwmpFrameType>(packet.payload, offset);
    assert(type == HwmpFrameType::Data);
    offset += sizeof(std::uint8_t);
    offset += sizeof(FakeAddress);
    offset += sizeof(FakeAddress);
    offset += sizeof(std::uint32_t);
    return {packet.payload.begin() + static_cast<std::ptrdiff_t>(offset), packet.payload.end()};
}

inline std::uint8_t preq_ttl(const TransportPacket<FakeAddress>& packet) {
    std::size_t offset = 0;
    const HwmpFrameType type = read_bytes<HwmpFrameType>(packet.payload, offset);
    assert(type == HwmpFrameType::Preq);
    return read_bytes<std::uint8_t>(packet.payload, offset);
}

inline std::uint8_t preq_flags(const TransportPacket<FakeAddress>& packet) {
    std::size_t offset = sizeof(HwmpFrameType) + sizeof(std::uint8_t);
    return read_bytes<std::uint8_t>(packet.payload, offset);
}

inline FakeAddress preq_originator(const TransportPacket<FakeAddress>& packet) {
    std::size_t offset =
        sizeof(HwmpFrameType) + sizeof(std::uint8_t) + sizeof(std::uint8_t) + sizeof(std::uint32_t);
    return read_bytes<FakeAddress>(packet.payload, offset);
}

inline FakeAddress preq_target(const TransportPacket<FakeAddress>& packet) {
    std::size_t offset = sizeof(HwmpFrameType) + sizeof(std::uint8_t) + sizeof(std::uint8_t) + sizeof(std::uint32_t)
                       + sizeof(FakeAddress) + sizeof(std::uint32_t);
    return read_bytes<FakeAddress>(packet.payload, offset);
}

inline std::uint32_t prep_target_seq(const TransportPacket<FakeAddress>& packet) {
    std::size_t offset = sizeof(HwmpFrameType) + sizeof(std::uint8_t) + sizeof(FakeAddress) + sizeof(FakeAddress);
    return read_bytes<std::uint32_t>(packet.payload, offset);
}

inline std::size_t count_frames(const std::vector<TransportPacket<FakeAddress>>& packets, HwmpFrameType type) {
    return static_cast<std::size_t>(
        std::count_if(packets.begin(), packets.end(), [type](const auto& packet) { return frame_type(packet) == type; }));
}

inline const TransportPacket<FakeAddress>& find_nth_frame(const std::vector<TransportPacket<FakeAddress>>& packets,
                                                          HwmpFrameType type, std::size_t index = 0) {
    std::size_t seen = 0;
    for (const auto& packet : packets) {
        if (frame_type(packet) != type)
            continue;
        if (seen == index)
            return packet;
        ++seen;
    }
    assert(false && "requested frame not found");
    return packets.front();
}

template <typename Fn>
void run_test(Fn&& fn) {
    FakeClock::reset();
    std::forward<Fn>(fn)();
}

} // namespace bricks::disnet::test
