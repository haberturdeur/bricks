#include "fake_platform.hpp"

#include "bricks/disnet.hpp"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <future>
#include <iostream>
#include <map>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace disnet = bricks::disnet;
using namespace std::chrono_literals;

namespace {

int g_failures = 0;
int g_custom_send_calls = 0;
std::vector<std::uint8_t> g_custom_last_frame;
std::map<std::pair<std::array<std::uint8_t, 32>, std::uint16_t>, std::vector<std::uint8_t>> g_segment_store;
int g_segment_store_put_calls = 0;
int g_segment_store_get_calls = 0;

void expect_true(bool condition, const char* expr, const char* test) {
    if (!condition) {
        ++g_failures;
        std::cerr << "[FAIL] " << test << ": " << expr << "\n";
    }
}

#define EXPECT_TRUE(expr) expect_true((expr), #expr, __func__)

std::vector<std::uint8_t> build_packet(const disnet::message::Header& hdr,
                                       std::span<const disnet::MacAddress> targets,
                                       std::span<const std::uint8_t> payload) {
    const std::size_t header_bytes = sizeof(disnet::message::Header) + targets.size() * 6u;
    std::vector<std::uint8_t> out(header_bytes + payload.size());
    std::memcpy(out.data(), &hdr, sizeof(disnet::message::Header));
    if (!targets.empty()) {
        std::memcpy(out.data() + sizeof(disnet::message::Header), targets.data(), targets.size() * 6u);
    }
    if (!payload.empty()) {
        std::memcpy(out.data() + header_bytes, payload.data(), payload.size());
    }
    return out;
}

struct [[gnu::packed]] TestAnnouncePayload {
    disnet::detail::SessionId session;
    std::uint32_t total_len;
    std::uint16_t block_size;
    std::uint16_t block_count;
};

struct [[gnu::packed]] TestSymbolPayloadHeader {
    disnet::detail::SessionId session;
    std::uint32_t seed;
};

std::uint32_t xorshift32(std::uint32_t& s) {
    std::uint32_t x = s;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    s = x;
    return x;
}

std::uint16_t choose_degree(std::uint16_t K, std::uint32_t& rng) {
    if (K <= 1) return 1;
    std::uint32_t r = xorshift32(rng) % 100;
    if (r < 50) return 1;
    if (r < 75) return std::min<std::uint16_t>(2, K);
    if (r < 90) return std::min<std::uint16_t>(3, K);
    if (r < 98) return std::min<std::uint16_t>(4, K);
    return std::min<std::uint16_t>(5, K);
}

std::vector<std::uint16_t> select_indices(std::uint16_t K, std::uint32_t seed, const disnet::detail::SessionId& session) {
    std::uint32_t rng = seed;
    for (std::size_t i = 0; i < 8; ++i) {
        std::uint32_t word = 0;
        std::memcpy(&word, session.bytes + i * sizeof(word), sizeof(word));
        rng ^= word;
    }
    const std::uint16_t D = choose_degree(K, rng);
    std::vector<std::uint16_t> out;
    out.reserve(D);
    while (out.size() < D) {
        std::uint16_t idx = static_cast<std::uint16_t>(xorshift32(rng) % K);
        if (std::find(out.begin(), out.end(), idx) == out.end()) out.push_back(idx);
    }
    return out;
}

std::array<std::uint8_t, 32> to_session_key(const disnet::detail::SessionId& sid) {
    std::array<std::uint8_t, 32> out{};
    std::memcpy(out.data(), sid.bytes, out.size());
    return out;
}

void xor_vec(std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b) {
    for (std::size_t i = 0; i < a.size(); ++i) a[i] ^= b[i];
}

void test_send_raw_serializes_frame() {
    fake_platform::reset();

    const disnet::MacAddress my{{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}};
    disnet::Node node(my);
    node.init();
    node.activate_channel(200);

    const disnet::MacAddress t1{{0xAA, 0x00, 0x00, 0x00, 0x00, 0x01}};
    const disnet::MacAddress t2{{0xAA, 0x00, 0x00, 0x00, 0x00, 0x02}};
    const std::set<disnet::MacAddress> targets{t2, t1};
    const std::vector<std::uint8_t> payload{1, 2, 3, 4};

    node.send_raw(200, 9, targets, payload);

    std::vector<fake_platform::TxFrame> frames = fake_platform::take_tx_frames();
    EXPECT_TRUE(frames.size() == 1);
    EXPECT_TRUE(frames[0].payload.size() == sizeof(disnet::message::Header) + 12 + payload.size());

    const disnet::message::Header* hdr = reinterpret_cast<const disnet::message::Header*>(frames[0].payload.data());
    EXPECT_TRUE(hdr->type == disnet::message::Type::Raw);
    EXPECT_TRUE(hdr->ttl == 9);
    EXPECT_TRUE(hdr->channel == 200);
    EXPECT_TRUE(hdr->target_count == 2);

    const std::size_t header_bytes = sizeof(disnet::message::Header) + hdr->target_count * 6u;
    EXPECT_TRUE(std::memcmp(frames[0].payload.data() + header_bytes, payload.data(), payload.size()) == 0);

    node.shutdown();
}

void test_reliable_inject_dispatches_and_acks() {
    fake_platform::reset();

    const disnet::MacAddress my{{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}};
    const disnet::MacAddress src{{0x66, 0x55, 0x44, 0x33, 0x22, 0x11}};

    disnet::Node node(my);
    node.init();
    node.activate_channel(200);

    int called = 0;
    std::vector<std::uint8_t> got;
    node.register_handler(200, [&](const disnet::MacAddress& from, std::span<const std::uint8_t> data) {
        EXPECT_TRUE(from == src);
        ++called;
        got.assign(data.begin(), data.end());
    });

    disnet::message::Header hdr{};
    hdr.id.source = src;
    hdr.id.seq = 77;
    hdr.type = disnet::message::Type::Reliable;
    hdr.ttl = 3;
    hdr.channel = 200;
    hdr.target_count = 1;

    const std::vector<std::uint8_t> payload{9, 8, 7};
    std::array<disnet::MacAddress, 1> targets{my};
    std::vector<std::uint8_t> packet = build_packet(hdr, targets, payload);

    node.inject_received(src, packet);
    EXPECT_TRUE(node.process_one(0ms));

    EXPECT_TRUE(called == 1);
    EXPECT_TRUE(got == payload);

    std::vector<fake_platform::TxFrame> frames = fake_platform::take_tx_frames();
    EXPECT_TRUE(frames.size() == 1);

    const disnet::message::Header* ah = reinterpret_cast<const disnet::message::Header*>(frames[0].payload.data());
    EXPECT_TRUE(ah->type == disnet::message::Type::ReliableAck);

    const std::size_t ack_header_bytes = sizeof(disnet::message::Header) + ah->target_count * 6u;
    EXPECT_TRUE(frames[0].payload.size() >= ack_header_bytes + sizeof(disnet::message::Id));

    const disnet::message::Id* acked = reinterpret_cast<const disnet::message::Id*>(frames[0].payload.data() + ack_header_bytes);
    EXPECT_TRUE(acked->seq == hdr.id.seq);
    EXPECT_TRUE(acked->source == hdr.id.source);

    node.shutdown();
}

void test_dedupe_drops_duplicate_message() {
    fake_platform::reset();

    const disnet::MacAddress my{{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}};
    const disnet::MacAddress src{{0x10, 0x20, 0x30, 0x40, 0x50, 0x61}};

    disnet::Node node(my);
    node.init();
    node.activate_channel(200);

    int called = 0;
    node.register_handler(200, [&](const disnet::MacAddress&, std::span<const std::uint8_t>) { ++called; });

    disnet::message::Header hdr{};
    hdr.id.source = src;
    hdr.id.seq = 1234;
    hdr.type = disnet::message::Type::Raw;
    hdr.ttl = 1;
    hdr.channel = 200;
    hdr.target_count = 1;

    const std::vector<std::uint8_t> payload{0xAB, 0xCD};
    std::array<disnet::MacAddress, 1> targets{my};
    std::vector<std::uint8_t> packet = build_packet(hdr, targets, payload);

    node.inject_received(src, packet);
    node.inject_received(src, packet);

    EXPECT_TRUE(node.process_one(0ms));
    EXPECT_TRUE(!node.process_one(0ms));
    EXPECT_TRUE(called == 1);

    node.shutdown();
}

void test_segmented_send_emits_frames_and_completes() {
    fake_platform::reset();

    const disnet::MacAddress my{{0x21, 0x22, 0x23, 0x24, 0x25, 0x26}};
    disnet::Node node(my);
    node.init();
    node.activate_channel(200);

    std::vector<std::uint8_t> payload(300, 0x5A);
    disnet::AckFuture fut = node.send_segmented(200, 5, {}, payload);

    EXPECT_TRUE(fut.valid());
    EXPECT_TRUE(fut.wait_for(2s) == std::future_status::ready);

    std::vector<fake_platform::TxFrame> frames = fake_platform::take_tx_frames();
    EXPECT_TRUE(!frames.empty());

    bool saw_announce = false;
    bool saw_symbol = false;
    for (const fake_platform::TxFrame& frame : frames) {
        if (frame.payload.size() < sizeof(disnet::message::Header)) {
            continue;
        }
        const disnet::message::Header* hdr = reinterpret_cast<const disnet::message::Header*>(frame.payload.data());
        if (hdr->type == disnet::message::Type::SegmentedAnnounce) {
            saw_announce = true;
        }
        if (hdr->type == disnet::message::Type::Segmented) {
            saw_symbol = true;
        }
    }

    EXPECT_TRUE(saw_announce);
    EXPECT_TRUE(saw_symbol);

    node.shutdown();
}

void test_segmented_receive_reassembles_and_dispatches() {
    fake_platform::reset();

    const disnet::MacAddress my{{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}};
    const disnet::MacAddress src{{0x77, 0x66, 0x55, 0x44, 0x33, 0x22}};

    disnet::Node node(my);
    node.init();
    node.activate_channel(200);

    int called = 0;
    std::vector<std::uint8_t> got;
    node.register_handler(200, [&](const disnet::MacAddress& from, std::span<const std::uint8_t> data) {
        EXPECT_TRUE(from == src);
        ++called;
        got.assign(data.begin(), data.end());
    });

    disnet::detail::SessionId sid{};
    for (std::size_t i = 0; i < sizeof(sid.bytes); ++i) {
        sid.bytes[i] = static_cast<std::uint8_t>(i + 1);
    }

    const std::vector<std::uint8_t> original{9, 1, 2, 3, 4};

    disnet::message::Header announce_hdr{};
    announce_hdr.id.source = src;
    announce_hdr.id.seq = 500;
    announce_hdr.type = disnet::message::Type::SegmentedAnnounce;
    announce_hdr.ttl = 3;
    announce_hdr.channel = 200;
    announce_hdr.target_count = 1;

    TestAnnouncePayload announce_payload{
        .session = sid,
        .total_len = static_cast<std::uint32_t>(original.size()),
        .block_size = static_cast<std::uint16_t>(original.size()),
        .block_count = 1,
    };
    std::array<disnet::MacAddress, 1> targets{my};
    std::span<const std::uint8_t> announce_bytes(reinterpret_cast<const std::uint8_t*>(&announce_payload), sizeof(announce_payload));
    std::vector<std::uint8_t> announce_packet = build_packet(announce_hdr, targets, announce_bytes);

    node.inject_received(src, announce_packet);

    disnet::message::Header symbol_hdr{};
    symbol_hdr.id.source = src;
    symbol_hdr.id.seq = 501;
    symbol_hdr.type = disnet::message::Type::Segmented;
    symbol_hdr.ttl = 3;
    symbol_hdr.channel = 200;
    symbol_hdr.target_count = 1;

    TestSymbolPayloadHeader symbol_payload_hdr{
        .session = sid,
        .seed = 0x12345678u,
    };
    std::vector<std::uint8_t> symbol_payload(sizeof(TestSymbolPayloadHeader) + original.size());
    std::memcpy(symbol_payload.data(), &symbol_payload_hdr, sizeof(symbol_payload_hdr));
    std::memcpy(symbol_payload.data() + sizeof(symbol_payload_hdr), original.data(), original.size());

    std::vector<std::uint8_t> symbol_packet = build_packet(symbol_hdr, targets, symbol_payload);
    node.inject_received(src, symbol_packet);

    EXPECT_TRUE(node.process_one(0ms));
    EXPECT_TRUE(called == 1);
    EXPECT_TRUE(got == original);

    std::vector<fake_platform::TxFrame> frames = fake_platform::take_tx_frames();
    std::size_t ack_count = 0;
    for (const fake_platform::TxFrame& frame : frames) {
        if (frame.payload.size() < sizeof(disnet::message::Header)) {
            continue;
        }
        const disnet::message::Header* hdr = reinterpret_cast<const disnet::message::Header*>(frame.payload.data());
        if (hdr->type == disnet::message::Type::SegmentedAck) {
            ++ack_count;
        }
    }
    EXPECT_TRUE(ack_count >= 2);

    node.shutdown();
}

void test_segmented_rejects_invalid_announce() {
    fake_platform::reset();

    const disnet::MacAddress my{{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}};
    const disnet::MacAddress src{{0x77, 0x66, 0x55, 0x44, 0x33, 0x22}};

    disnet::Node node(my);
    node.init();
    node.activate_channel(200);

    int called = 0;
    node.register_handler(200, [&](const disnet::MacAddress&, std::span<const std::uint8_t>) { ++called; });

    disnet::detail::SessionId sid{};
    disnet::message::Header announce_hdr{};
    announce_hdr.id.source = src;
    announce_hdr.id.seq = 800;
    announce_hdr.type = disnet::message::Type::SegmentedAnnounce;
    announce_hdr.ttl = 3;
    announce_hdr.channel = 200;
    announce_hdr.target_count = 1;

    TestAnnouncePayload invalid_announce{
        .session = sid,
        .total_len = 10,
        .block_size = 0,
        .block_count = 1,
    };
    std::array<disnet::MacAddress, 1> targets{my};
    std::span<const std::uint8_t> bytes(reinterpret_cast<const std::uint8_t*>(&invalid_announce), sizeof(invalid_announce));
    std::vector<std::uint8_t> packet = build_packet(announce_hdr, targets, bytes);
    node.inject_received(src, packet);

    disnet::message::Header symbol_hdr{};
    symbol_hdr.id.source = src;
    symbol_hdr.id.seq = 801;
    symbol_hdr.type = disnet::message::Type::Segmented;
    symbol_hdr.ttl = 3;
    symbol_hdr.channel = 200;
    symbol_hdr.target_count = 1;
    TestSymbolPayloadHeader sph{
        .session = sid,
        .seed = 1,
    };
    std::vector<std::uint8_t> sym(sizeof(TestSymbolPayloadHeader) + 4, 0);
    std::memcpy(sym.data(), &sph, sizeof(sph));
    std::vector<std::uint8_t> symbol_packet = build_packet(symbol_hdr, targets, sym);
    node.inject_received(src, symbol_packet);

    EXPECT_TRUE(!node.process_one(0ms));
    EXPECT_TRUE(called == 0);

    std::vector<fake_platform::TxFrame> frames = fake_platform::take_tx_frames();
    bool saw_nack = false;
    for (const fake_platform::TxFrame& frame : frames) {
        if (frame.payload.size() < sizeof(disnet::message::Header)) continue;
        const disnet::message::Header* hdr = reinterpret_cast<const disnet::message::Header*>(frame.payload.data());
        if (hdr->type == disnet::message::Type::SegmentedNack) {
            saw_nack = true;
        }
    }
    EXPECT_TRUE(saw_nack);

    node.shutdown();
}

void test_segmented_send_rejects_too_large_payload() {
    fake_platform::reset();

    const disnet::MacAddress my{{0x21, 0x22, 0x23, 0x24, 0x25, 0x26}};
    disnet::Node node(my);
    node.init();
    node.activate_channel(200);

    std::vector<std::uint8_t> payload(disnet::detail::Limits::max_segmented_payload_bytes + 1, 0x7F);
    bool threw = false;
    try {
        disnet::AckFuture fut = node.send_segmented(200, 5, {}, payload);
        (void)fut;
    } catch (const std::exception&) {
        threw = true;
    }
    EXPECT_TRUE(threw);

    node.shutdown();
}

esp_err_t custom_transport_init() { return ESP_OK; }
esp_err_t custom_transport_deinit() { return ESP_OK; }
esp_err_t custom_transport_add_peer() { return ESP_OK; }
esp_err_t custom_transport_send(std::span<const std::uint8_t> data) {
    ++g_custom_send_calls;
    g_custom_last_frame.assign(data.begin(), data.end());
    return ESP_OK;
}
std::uint32_t custom_transport_random() { return 0xA5A5A5A5u; }
disnet::TimePoint custom_transport_now() { return disnet::Clock::time_point{std::chrono::milliseconds{12345}}; }
void custom_transport_sleep(std::chrono::milliseconds d) { (void)d; }

void test_custom_transport_hooks_are_used() {
    g_custom_send_calls = 0;
    g_custom_last_frame.clear();

    disnet::Node::Config cfg{};
    cfg.inbound_slots = 4;
    cfg.transport = disnet::Node::Transport{
        .init = custom_transport_init,
        .deinit = custom_transport_deinit,
        .add_broadcast_peer = custom_transport_add_peer,
        .send_broadcast = custom_transport_send,
        .random_u32 = custom_transport_random,
        .now = custom_transport_now,
        .sleep_for = custom_transport_sleep,
    };

    const disnet::MacAddress my{{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}};
    disnet::Node node(cfg, my);
    node.init();
    node.activate_channel(200);
    const std::vector<std::uint8_t> payload{0xDE, 0xAD};
    node.send_raw(200, 5, {}, payload);

    EXPECT_TRUE(g_custom_send_calls == 1);
    EXPECT_TRUE(!g_custom_last_frame.empty());
    const disnet::message::Header* hdr = reinterpret_cast<const disnet::message::Header*>(g_custom_last_frame.data());
    EXPECT_TRUE(hdr->id.seq == 0xA5A5A5A5u);
    EXPECT_TRUE(hdr->type == disnet::message::Type::Raw);

    node.shutdown();
}

bool seg_store_put(const disnet::detail::SessionId& sid, std::uint16_t block_idx, std::span<const std::uint8_t> data) {
    ++g_segment_store_put_calls;
    g_segment_store[{to_session_key(sid), block_idx}] = std::vector<std::uint8_t>(data.begin(), data.end());
    return true;
}

bool seg_store_get(const disnet::detail::SessionId& sid, std::uint16_t block_idx, std::span<std::uint8_t> out) {
    ++g_segment_store_get_calls;
    std::map<std::pair<std::array<std::uint8_t, 32>, std::uint16_t>, std::vector<std::uint8_t>>::const_iterator it =
        g_segment_store.find({to_session_key(sid), block_idx});
    if (it == g_segment_store.end()) return false;
    if (it->second.size() != out.size()) return false;
    std::memcpy(out.data(), it->second.data(), out.size());
    return true;
}

void test_segmented_external_store_reload_with_small_cache() {
    fake_platform::reset();
    g_segment_store.clear();
    g_segment_store_put_calls = 0;
    g_segment_store_get_calls = 0;

    disnet::Node::Config cfg{};
    cfg.inbound_slots = 8;
    cfg.segmented_rx_cache_blocks = 1;
    cfg.segment_store = disnet::Node::Config::SegmentStore{
        .store_block = seg_store_put,
        .load_block = seg_store_get,
    };

    const disnet::MacAddress my{{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}};
    const disnet::MacAddress src{{0x77, 0x66, 0x55, 0x44, 0x33, 0x22}};
    disnet::Node node(cfg, my);
    node.init();
    node.activate_channel(200);

    int called = 0;
    std::vector<std::uint8_t> got;
    node.register_handler(200, [&](const disnet::MacAddress&, std::span<const std::uint8_t> data) {
        ++called;
        got.assign(data.begin(), data.end());
    });

    disnet::detail::SessionId sid{};
    for (std::size_t i = 0; i < sizeof(sid.bytes); ++i) sid.bytes[i] = static_cast<std::uint8_t>(0xA0 + i);

    const std::uint16_t block_size = 4;
    const std::uint16_t K = 2;
    const std::vector<std::uint8_t> b0{1, 2, 3, 4};
    const std::vector<std::uint8_t> b1{10, 20, 30, 40};
    std::vector<std::uint8_t> xor01 = b0;
    xor_vec(xor01, b1);

    disnet::message::Header announce_hdr{};
    announce_hdr.id.source = src;
    announce_hdr.id.seq = 900;
    announce_hdr.type = disnet::message::Type::SegmentedAnnounce;
    announce_hdr.ttl = 3;
    announce_hdr.channel = 200;
    announce_hdr.target_count = 1;
    TestAnnouncePayload announce_payload{
        .session = sid,
        .total_len = 8,
        .block_size = block_size,
        .block_count = K,
    };
    std::array<disnet::MacAddress, 1> targets{my};
    std::span<const std::uint8_t> announce_bytes(reinterpret_cast<const std::uint8_t*>(&announce_payload), sizeof(announce_payload));
    std::vector<std::uint8_t> announce_packet = build_packet(announce_hdr, targets, announce_bytes);
    node.inject_received(src, announce_packet);

    std::uint32_t seed_single_0 = 0;
    std::uint32_t seed_mix_01 = 0;
    bool found_single_0 = false;
    bool found_mix_01 = false;
    for (std::uint32_t seed = 1; seed < 200000 && (!found_single_0 || !found_mix_01); ++seed) {
        const std::vector<std::uint16_t> idx = select_indices(K, seed, sid);
        if (!found_single_0 && idx.size() == 1 && idx[0] == 0) {
            seed_single_0 = seed;
            found_single_0 = true;
        }
        if (!found_mix_01 && idx.size() == 2 && ((idx[0] == 0 && idx[1] == 1) || (idx[0] == 1 && idx[1] == 0))) {
            seed_mix_01 = seed;
            found_mix_01 = true;
        }
    }
    EXPECT_TRUE(found_single_0);
    EXPECT_TRUE(found_mix_01);

    disnet::message::Header s1_hdr{};
    s1_hdr.id.source = src;
    s1_hdr.id.seq = 901;
    s1_hdr.type = disnet::message::Type::Segmented;
    s1_hdr.ttl = 3;
    s1_hdr.channel = 200;
    s1_hdr.target_count = 1;
    TestSymbolPayloadHeader s1p{.session = sid, .seed = seed_single_0};
    std::vector<std::uint8_t> s1_payload(sizeof(TestSymbolPayloadHeader) + block_size);
    std::memcpy(s1_payload.data(), &s1p, sizeof(s1p));
    std::memcpy(s1_payload.data() + sizeof(s1p), b0.data(), block_size);
    std::vector<std::uint8_t> s1_packet = build_packet(s1_hdr, targets, s1_payload);
    node.inject_received(src, s1_packet);

    disnet::message::Header s2_hdr{};
    s2_hdr.id.source = src;
    s2_hdr.id.seq = 902;
    s2_hdr.type = disnet::message::Type::Segmented;
    s2_hdr.ttl = 3;
    s2_hdr.channel = 200;
    s2_hdr.target_count = 1;
    TestSymbolPayloadHeader s2p{.session = sid, .seed = seed_mix_01};
    std::vector<std::uint8_t> s2_payload(sizeof(TestSymbolPayloadHeader) + block_size);
    std::memcpy(s2_payload.data(), &s2p, sizeof(s2p));
    std::memcpy(s2_payload.data() + sizeof(s2p), xor01.data(), block_size);
    std::vector<std::uint8_t> s2_packet = build_packet(s2_hdr, targets, s2_payload);
    node.inject_received(src, s2_packet);

    EXPECT_TRUE(node.process_one(0ms));
    EXPECT_TRUE(called == 1);
    EXPECT_TRUE(got == std::vector<std::uint8_t>({1, 2, 3, 4, 10, 20, 30, 40}));
    EXPECT_TRUE(g_segment_store_put_calls >= 1);
    EXPECT_TRUE(g_segment_store_get_calls >= 1);

    node.shutdown();
}

void test_segmented_limits_cap_rx_sessions() {
    fake_platform::reset();

    disnet::Node::Config cfg{};
    cfg.segmented_limits.max_rx_sessions = 2;

    const disnet::MacAddress my{{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}};
    const disnet::MacAddress src{{0x77, 0x66, 0x55, 0x44, 0x33, 0x22}};
    disnet::Node node(cfg, my);
    node.init();
    node.activate_channel(200);

    std::array<disnet::MacAddress, 1> targets{my};
    for (std::uint32_t i = 0; i < 4; ++i) {
        disnet::detail::SessionId sid{};
        sid.bytes[0] = static_cast<std::uint8_t>(i + 1);

        disnet::message::Header announce_hdr{};
        announce_hdr.id.source = src;
        announce_hdr.id.seq = 1000 + i;
        announce_hdr.type = disnet::message::Type::SegmentedAnnounce;
        announce_hdr.ttl = 3;
        announce_hdr.channel = 200;
        announce_hdr.target_count = 1;

        TestAnnouncePayload announce_payload{
            .session = sid,
            .total_len = 8,
            .block_size = 4,
            .block_count = 2,
        };
        std::span<const std::uint8_t> bytes(reinterpret_cast<const std::uint8_t*>(&announce_payload), sizeof(announce_payload));
        std::vector<std::uint8_t> packet = build_packet(announce_hdr, targets, bytes);
        node.inject_received(src, packet);
    }

    std::vector<fake_platform::TxFrame> frames = fake_platform::take_tx_frames();
    int ack_count = 0;
    int nack_count = 0;
    for (const fake_platform::TxFrame& frame : frames) {
        if (frame.payload.size() < sizeof(disnet::message::Header)) continue;
        const disnet::message::Header* hdr = reinterpret_cast<const disnet::message::Header*>(frame.payload.data());
        if (hdr->type == disnet::message::Type::SegmentedAck) ++ack_count;
        if (hdr->type == disnet::message::Type::SegmentedNack) ++nack_count;
    }

    EXPECT_TRUE(ack_count == 2);
    EXPECT_TRUE(nack_count == 2);

    node.shutdown();
}

void test_segmented_limits_cap_tx_sessions() {
    fake_platform::reset();

    disnet::Node::Config cfg{};
    cfg.segmented_limits.max_tx_sessions = 2;

    const disnet::MacAddress my{{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}};
    disnet::Node node(cfg, my);
    node.init();
    node.activate_channel(200);

    std::set<disnet::MacAddress> one_target{
        disnet::MacAddress{{0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x01}},
    };
    std::vector<std::uint8_t> payload1(1200, 0x2A);
    std::vector<std::uint8_t> payload2(1200, 0x2B);
    std::vector<std::uint8_t> payload3(1200, 0x2C);

    disnet::AckFuture f1 = node.send_segmented(200, 5, one_target, payload1);
    disnet::AckFuture f2 = node.send_segmented(200, 5, one_target, payload2);
    disnet::AckFuture f3 = node.send_segmented(200, 5, one_target, payload3);

    EXPECT_TRUE(f3.valid());
    EXPECT_TRUE(f3.wait_for(0ms) == std::future_status::ready);
    bool threw = false;
    try {
        f3.get();
    } catch (const std::exception&) {
        threw = true;
    }
    EXPECT_TRUE(threw);

    node.shutdown();
    if (f1.valid()) {
        try {
            f1.get();
        } catch (const std::exception&) {
        }
    }
    if (f2.valid()) {
        try {
            f2.get();
        } catch (const std::exception&) {
        }
    }
}

void test_diagnostics_counters_track_limits() {
    fake_platform::reset();

    disnet::Node::Config cfg{};
    cfg.segmented_limits.max_rx_sessions = 1;
    cfg.segmented_limits.max_tx_sessions = 1;

    const disnet::MacAddress my{{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}};
    const disnet::MacAddress src{{0x77, 0x66, 0x55, 0x44, 0x33, 0x22}};
    disnet::Node node(cfg, my);
    node.init();
    node.activate_channel(200);

    std::array<disnet::MacAddress, 1> targets{my};
    for (std::uint32_t i = 0; i < 2; ++i) {
        disnet::detail::SessionId sid{};
        sid.bytes[0] = static_cast<std::uint8_t>(0x80 + i);
        disnet::message::Header announce_hdr{};
        announce_hdr.id.source = src;
        announce_hdr.id.seq = 2000 + i;
        announce_hdr.type = disnet::message::Type::SegmentedAnnounce;
        announce_hdr.ttl = 3;
        announce_hdr.channel = 200;
        announce_hdr.target_count = 1;
        TestAnnouncePayload announce_payload{
            .session = sid,
            .total_len = 8,
            .block_size = 4,
            .block_count = 2,
        };
        std::span<const std::uint8_t> bytes(reinterpret_cast<const std::uint8_t*>(&announce_payload), sizeof(announce_payload));
        std::vector<std::uint8_t> packet = build_packet(announce_hdr, targets, bytes);
        node.inject_received(src, packet);
    }

    std::set<disnet::MacAddress> one_target{
        disnet::MacAddress{{0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x01}},
    };
    std::vector<std::uint8_t> p1(1200, 0x31);
    std::vector<std::uint8_t> p2(1200, 0x32);
    disnet::AckFuture f1 = node.send_segmented(200, 5, one_target, p1);
    disnet::AckFuture f2 = node.send_segmented(200, 5, one_target, p2);
    EXPECT_TRUE(f2.wait_for(0ms) == std::future_status::ready);
    try {
        (void)f2.get();
    } catch (const std::exception&) {
    }

    const disnet::Node::Diagnostics d = node.diagnostics();
    EXPECT_TRUE(d.rx_session_rejected_limit >= 1);
    EXPECT_TRUE(d.tx_session_rejected_limit >= 1);

    node.shutdown();
    if (f1.valid()) {
        try {
            (void)f1.get();
        } catch (const std::exception&) {
        }
    }
}

} // namespace

int main() {
    try {
        test_send_raw_serializes_frame();
        test_reliable_inject_dispatches_and_acks();
        test_dedupe_drops_duplicate_message();
        test_segmented_send_emits_frames_and_completes();
        test_segmented_receive_reassembles_and_dispatches();
        test_segmented_rejects_invalid_announce();
        test_segmented_send_rejects_too_large_payload();
        test_custom_transport_hooks_are_used();
        test_segmented_external_store_reload_with_small_cache();
        test_segmented_limits_cap_rx_sessions();
        test_segmented_limits_cap_tx_sessions();
        test_diagnostics_counters_track_limits();
    } catch (const std::exception& e) {
        ++g_failures;
        std::cerr << "[FAIL] unhandled exception: " << e.what() << "\n";
    }

    if (g_failures == 0) {
        std::cout << "All disnet host tests passed\n";
        return 0;
    }

    std::cerr << g_failures << " test assertions failed\n";
    return 1;
}
