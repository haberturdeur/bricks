#include "bricks/disnet/flood.hpp"
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

namespace {

// Manually-advanceable clock for deterministic time-dependent tests.
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

    static Address broadcast_address() {
        return Address{0xFF};
    }

    Address my_address() const {
        return self;
    }

    void send(bricks::disnet::TransportPacket<Address> packet) {
        sent.push_back(std::move(packet));
    }

    void register_callback(bricks::disnet::TransportReceiveCallback<Address> callback) {
        callback_ = std::move(callback);
    }

    Address self;
    std::vector<bricks::disnet::TransportPacket<Address>> sent;
    bricks::disnet::TransportReceiveCallback<Address> callback_;
};

enum class FrameType : std::uint8_t {
    Data = 0,
    Preq = 1,
    Prep = 2,
    Perr = 3,
};

template <typename T>
void append(std::vector<std::uint8_t>& out, const T& value) {
    const std::size_t offset = out.size();
    out.resize(offset + sizeof(T));
    std::memcpy(out.data() + offset, &value, sizeof(T));
}

template <typename T>
T read(const std::vector<std::uint8_t>& in, std::size_t& offset) {
    T value{};
    assert(offset + sizeof(T) <= in.size());
    std::memcpy(&value, in.data() + offset, sizeof(T));
    offset += sizeof(T);
    return value;
}

std::vector<std::uint8_t> encode_prep(FakeAddress originator, FakeAddress target, std::uint32_t target_seq,
                                      std::uint32_t metric, std::uint8_t ttl = 5) {
    std::vector<std::uint8_t> out;
    append(out, FrameType::Prep);
    append(out, ttl);
    append(out, originator);
    append(out, target);
    append(out, target_seq);
    append(out, metric);
    return out;
}

std::vector<std::uint8_t> encode_preq(FakeAddress originator, std::uint32_t preq_id, FakeAddress target,
                                      std::uint32_t originator_seq = 1, std::uint32_t target_seq = 0,
                                      std::uint32_t metric = 0, std::uint8_t ttl = 5, std::uint8_t flags = 0) {
    std::vector<std::uint8_t> out;
    append(out, FrameType::Preq);
    append(out, ttl);
    append(out, flags);
    append(out, preq_id);
    append(out, originator);
    append(out, originator_seq);
    append(out, target);
    append(out, target_seq);
    append(out, metric);
    return out;
}

std::vector<std::uint8_t> encode_perr(FakeAddress destination, std::uint32_t destination_seq) {
    std::vector<std::uint8_t> out;
    append(out, FrameType::Perr);
    append(out, destination);
    append(out, destination_seq);
    return out;
}

FrameType frame_type(const bricks::disnet::TransportPacket<FakeAddress>& packet) {
    std::size_t offset = 0;
    return read<FrameType>(packet.payload, offset);
}

std::vector<std::uint8_t> data_payload(const bricks::disnet::TransportPacket<FakeAddress>& packet) {
    std::size_t offset = 0;
    const FrameType type = read<FrameType>(packet.payload, offset);
    assert(type == FrameType::Data);
    offset += sizeof(std::uint8_t);
    offset += sizeof(FakeAddress);
    offset += sizeof(FakeAddress);
    offset += sizeof(std::uint32_t);
    return {packet.payload.begin() + static_cast<std::ptrdiff_t>(offset), packet.payload.end()};
}

std::uint8_t data_ttl(const bricks::disnet::TransportPacket<FakeAddress>& packet) {
    std::size_t offset = 0;
    const FrameType type = read<FrameType>(packet.payload, offset);
    assert(type == FrameType::Data);
    return read<std::uint8_t>(packet.payload, offset);
}

using namespace std::chrono_literals;

void test_pending_queue_is_bounded_and_preq_is_suppressed() {
    FakeTransport transport(FakeAddress{1});
    bricks::disnet::Hwmp<FakeTransport> router(transport, {
                                                              .ttl = 4,
                                                              .proactive_ttl = 6,
                                                              .root = false,
                                                              .intermediate_replies = true,
                                                              .max_pending_per_destination = 2,
                                                              .max_pending_total = 2,
                                                              .route_lifetime = 32ms,
                                                          });

    router.send({.source = {}, .target = FakeAddress{9}, .source_seq = 0, .payload = {1}});
    router.send({.source = {}, .target = FakeAddress{9}, .source_seq = 0, .payload = {2}});
    router.send({.source = {}, .target = FakeAddress{9}, .source_seq = 0, .payload = {3}});

    const std::size_t preq_count = static_cast<std::size_t>(
        std::count_if(transport.sent.begin(), transport.sent.end(), [](const auto& packet) {
            return frame_type(packet) == FrameType::Preq;
        }));
    assert(preq_count == 1);

    router.handle_packet({
        .source = FakeAddress{2},
        .target = transport.my_address(),
        .source_seq = 77,
        .payload = encode_prep(transport.my_address(), FakeAddress{9}, 10, 0),
    });

    std::vector<std::vector<std::uint8_t>> flushed_payloads;
    for (const auto& packet : transport.sent) {
        if (frame_type(packet) == FrameType::Data) {
            flushed_payloads.push_back(data_payload(packet));
        }
    }

    assert(flushed_payloads.size() == 2);
    assert((flushed_payloads[0] == std::vector<std::uint8_t>{2}));
    assert((flushed_payloads[1] == std::vector<std::uint8_t>{3}));
}

void test_stale_route_does_not_answer_preq() {
    FakeClock::reset();

    FakeTransport transport(FakeAddress{1});
    bricks::disnet::Hwmp<FakeTransport, FakeClock> router(transport, {
                                                                          .ttl = 4,
                                                                          .proactive_ttl = 6,
                                                                          .root = false,
                                                                          .intermediate_replies = true,
                                                                          .max_pending_per_destination = 4,
                                                                          .max_pending_total = 8,
                                                                          .route_lifetime = 2ms,
                                                                      });

    router.handle_packet({
        .source = FakeAddress{2},
        .target = transport.my_address(),
        .source_seq = 10,
        .payload = encode_prep(transport.my_address(), FakeAddress{9}, 5, 0),
    });

    transport.sent.clear();
    FakeClock::advance(3ms);
    transport.sent.clear();

    router.handle_packet({
        .source = FakeAddress{3},
        .target = transport.broadcast_address(),
        .source_seq = 42,
        .payload = encode_preq(FakeAddress{4}, 1, FakeAddress{9}),
    });

    assert(!transport.sent.empty());
    assert(frame_type(transport.sent.back()) == FrameType::Preq);
}

void test_same_destination_retries_after_real_time_backoff() {
    FakeClock::reset();

    FakeTransport transport(FakeAddress{1});
    bricks::disnet::Hwmp<FakeTransport, FakeClock> router(transport, {
                                                                          .ttl = 4,
                                                                          .proactive_ttl = 6,
                                                                          .root = false,
                                                                          .intermediate_replies = true,
                                                                          .max_pending_per_destination = 4,
                                                                          .max_pending_total = 8,
                                                                          .route_lifetime = 16ms,
                                                                          .discovery_retry_interval = 1ms,
                                                                      });

    router.send({.source = {}, .target = FakeAddress{9}, .source_seq = 0, .payload = {1}});
    const std::size_t first_preq_count = static_cast<std::size_t>(
        std::count_if(transport.sent.begin(), transport.sent.end(), [](const auto& packet) {
            return frame_type(packet) == FrameType::Preq;
        }));
    assert(first_preq_count == 1);

    FakeClock::advance(3ms);
    router.send({.source = {}, .target = FakeAddress{9}, .source_seq = 0, .payload = {2}});

    const std::size_t second_preq_count = static_cast<std::size_t>(
        std::count_if(transport.sent.begin(), transport.sent.end(), [](const auto& packet) {
            return frame_type(packet) == FrameType::Preq;
        }));
    assert(second_preq_count == 2);
}

void test_perr_is_rebroadcast_once() {
    FakeTransport transport(FakeAddress{1});
    bricks::disnet::Hwmp<FakeTransport> router(transport, {
                                                              .ttl = 4,
                                                              .proactive_ttl = 6,
                                                              .root = false,
                                                              .intermediate_replies = true,
                                                              .max_pending_per_destination = 4,
                                                              .max_pending_total = 8,
                                                              .route_lifetime = 16ms,
                                                          });

    router.handle_packet({
        .source = FakeAddress{2},
        .target = transport.my_address(),
        .source_seq = 10,
        .payload = encode_prep(transport.my_address(), FakeAddress{9}, 5, 0),
    });

    transport.sent.clear();

    const auto perr_payload = encode_perr(FakeAddress{9}, 5);
    router.handle_packet({
        .source = FakeAddress{2},
        .target = transport.broadcast_address(),
        .source_seq = 22,
        .payload = perr_payload,
    });

    const std::size_t first_count = static_cast<std::size_t>(
        std::count_if(transport.sent.begin(), transport.sent.end(), [](const auto& packet) {
            return frame_type(packet) == FrameType::Perr;
        }));
    assert(first_count == 1);

    router.handle_packet({
        .source = FakeAddress{3},
        .target = transport.broadcast_address(),
        .source_seq = 23,
        .payload = perr_payload,
    });

    const std::size_t second_count = static_cast<std::size_t>(
        std::count_if(transport.sent.begin(), transport.sent.end(), [](const auto& packet) {
            return frame_type(packet) == FrameType::Perr;
        }));
    assert(second_count == 1);
}

void test_global_pending_trim_drops_old_destination_safely() {
    FakeTransport transport(FakeAddress{1});
    bricks::disnet::Hwmp<FakeTransport> router(transport, {
                                                              .ttl = 4,
                                                              .proactive_ttl = 6,
                                                              .root = false,
                                                              .intermediate_replies = true,
                                                              .max_pending_per_destination = 2,
                                                              .max_pending_total = 1,
                                                              .route_lifetime = 16ms,
                                                          });

    router.send({.source = {}, .target = FakeAddress{9}, .source_seq = 0, .payload = {1}});
    router.send({.source = {}, .target = FakeAddress{10}, .source_seq = 0, .payload = {2}});

    transport.sent.clear();

    router.send({.source = {}, .target = FakeAddress{9}, .source_seq = 0, .payload = {3}});

    const std::size_t preq_count = static_cast<std::size_t>(
        std::count_if(transport.sent.begin(), transport.sent.end(), [](const auto& packet) {
            return frame_type(packet) == FrameType::Preq;
        }));
    assert(preq_count == 1);
}

void test_originator_does_not_redeliver_own_broadcast() {
    FakeTransport transport(FakeAddress{1});
    bricks::disnet::Hwmp<FakeTransport> router(transport, {
                                                              .ttl = 4,
                                                              .proactive_ttl = 6,
                                                              .root = false,
                                                              .intermediate_replies = true,
                                                              .max_pending_per_destination = 4,
                                                              .max_pending_total = 8,
                                                              .route_lifetime = 16ms,
                                                          });

    std::vector<std::vector<std::uint8_t>> delivered;
    router.register_callback([&](bricks::disnet::TransportPacket<FakeAddress> packet) {
        delivered.push_back(std::move(packet.payload));
    });

    router.send({.source = {}, .target = transport.broadcast_address(), .source_seq = 0, .payload = {7, 8}});
    assert(transport.sent.size() == 1);

    bricks::disnet::TransportPacket<FakeAddress> rebroadcast = transport.sent.front();
    rebroadcast.source = FakeAddress{2};

    transport.sent.clear();
    router.handle_packet(rebroadcast);

    assert(delivered.empty());
    assert(transport.sent.empty());
}

void test_perr_keeps_pending_packets_for_future_route_resolution() {
    FakeTransport transport(FakeAddress{1});
    bricks::disnet::Hwmp<FakeTransport> router(transport, {
                                                              .ttl = 4,
                                                              .proactive_ttl = 6,
                                                              .root = false,
                                                              .intermediate_replies = true,
                                                              .max_pending_per_destination = 4,
                                                              .max_pending_total = 8,
                                                              .route_lifetime = 16ms,
                                                          });

    router.send({.source = {}, .target = FakeAddress{9}, .source_seq = 0, .payload = {1}});
    transport.sent.clear();

    router.handle_packet({
        .source = FakeAddress{2},
        .target = transport.broadcast_address(),
        .source_seq = 22,
        .payload = encode_perr(FakeAddress{9}, 1),
    });

    router.handle_packet({
        .source = FakeAddress{2},
        .target = transport.my_address(),
        .source_seq = 23,
        .payload = encode_prep(transport.my_address(), FakeAddress{9}, 2, 0),
    });

    const auto data_it = std::find_if(transport.sent.begin(), transport.sent.end(), [](const auto& packet) {
        return frame_type(packet) == FrameType::Data;
    });
    assert(data_it != transport.sent.end());
    assert(data_ttl(*data_it) == 4);
    assert((data_payload(*data_it) == std::vector<std::uint8_t>{1}));
}

} // namespace

int main() {
    test_pending_queue_is_bounded_and_preq_is_suppressed();
    test_stale_route_does_not_answer_preq();
    test_same_destination_retries_after_real_time_backoff();
    test_perr_is_rebroadcast_once();
    test_global_pending_trim_drops_old_destination_safely();
    test_originator_does_not_redeliver_own_broadcast();
    test_perr_keeps_pending_packets_for_future_route_resolution();
}
