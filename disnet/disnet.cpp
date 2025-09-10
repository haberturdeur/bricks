#include "esp_log.h"

#include "include/bricks/disnet.hpp"
#include <cstdlib>
#include <memory>
#include <thread>
;
#include "bricks/disnet.hpp"

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include "bricks/exceptions.hpp"

#include <any>
#include <atomic>
#include <cassert>
#include <chrono>
#include <compare>
#include <cstdint>
#include <cstring>
#include <future>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>
#include <mutex>
#include <algorithm>

// crypto for session id
#include "mbedtls/version.h"
#include "mbedtls/sha256.h"

using namespace std::chrono_literals;

static const char* g_tag = "bricks/disnet";

namespace bricks::disnet {

using message::Header;
using message::Id;
using message::Type;

enum class InitState { NotInitialized, Initializing, Initialized };

using AckPromise = std::promise<std::tuple<>>;

struct AckCookie {
    TimePoint timeout;
    AckPromise promise;
};

namespace segmented {

static constexpr std::uint8_t ACK_FLAG_INIT   = 0x01;  // Receiver saw announce and will participate
static constexpr std::uint8_t ACK_FLAG_FINISH = 0x02;  // Receiver finished decode

static constexpr std::uint8_t NACK_REPEAT     = 0x01;  // Receiver is repeatedly getting duplicate seeds
static constexpr std::uint8_t NACK_NEED_MORE  = 0x02;  // Receiver needs more innovative symbols

struct [[gnu::packed]] SessionId {
    std::uint8_t bytes[32];

    bool operator==(const SessionId& o) const {
        return std::memcmp(bytes, o.bytes, 32) == 0;
    }
    bool operator<(const SessionId& o) const {
        return std::memcmp(bytes, o.bytes, 32) < 0;
    }
};

struct [[gnu::packed]] AnnouncePayload {
    SessionId session;
    std::uint32_t total_len;  // original payload length
    std::uint16_t block_size; // bytes per source block (padded for last)
    std::uint16_t block_count;// number of source blocks (K)
};

struct [[gnu::packed]] SymbolPayloadHeader {
    SessionId session;
    std::uint32_t seed; // RNG seed that determines degree + block indices
    // followed by coded data: block_size bytes
};

struct [[gnu::packed]] AckPayload {
    SessionId session;
    std::uint8_t flags; // ACK_FLAG_INIT or ACK_FLAG_FINISH
};

struct [[gnu::packed]] NackPayload {
    SessionId session;
    std::uint8_t reason; // NACK_* constants
};

} // namespace segmented

// -----------------------------------------------------------------------------------

struct State {
    const MacAddress my_address = MacAddress::my_address_sta();

    std::atomic<InitState> init_state = InitState::NotInitialized;

    std::mutex active_channels_mutex;
    std::vector<bool> active_channels = std::vector<bool>(static_cast<std::vector<bool>::size_type>(256));
    std::uint8_t active_kiddy_count = 0;

    std::atomic<bool> custom_filters_enabled = false;
    std::mutex filter_mutex;
    Predicate input_filter;      // true -> keep
    Predicate processing_filter; // true -> process
    Predicate forwarding_filter; // true -> forward

    std::mutex channel_handlers_mutex;
    std::map<std::uint8_t, Callback> channel_handlers;

    std::atomic<std::uint8_t> initial_ttl = 15;

    utils::DeduplicationTable<Id> dedupe;
    std::atomic<std::uint32_t> msg_seq = esp_random();

    QueueHandle_t packet_queue = nullptr;

    std::mutex heartbeats_mutex;
    std::map<std::pair<std::uint8_t, MacAddress>, TimePoint> heartbeats;
    TimePoint last_message;

    std::mutex ack_promises_mutex;
    std::map<Id, AckCookie> ack_promises;

    struct SenderSession;
    struct ReceiverSessionKey {
        std::uint8_t channel;
        MacAddress   sender;
        segmented::SessionId session;
        bool operator<(const ReceiverSessionKey& o) const {
            if (channel != o.channel) return channel < o.channel;
            if (!(sender == o.sender)) return sender < o.sender;
            return session < o.session;
        }
    };

    struct ReceiverSession {
        segmented::SessionId session;
        std::uint8_t channel;
        MacAddress   sender;
        std::uint32_t total_len = 0;
        std::uint16_t block_size = 0;
        std::uint16_t K = 0; // blocks

        std::vector<std::vector<std::uint8_t>> blocks;
        std::vector<bool> known;

        struct Equation {
            std::vector<std::uint16_t> idx;
            std::vector<std::uint8_t>   data;
        };
        std::vector<Equation> equations;

        std::set<std::uint32_t> seen_seeds;
        std::size_t innovative_count = 0;
        Clock::time_point last_progress = Clock::now();
    };

    std::mutex rx_sessions_mutex;
    std::map<ReceiverSessionKey, std::shared_ptr<ReceiverSession>> rx_sessions;

    struct SenderSessionKey {
        segmented::SessionId session;
        bool operator<(const SenderSessionKey& o) const {
            return session < o.session;
        }
    };

    struct SenderSession {
        segmented::SessionId session;
        std::uint8_t channel;
        std::uint8_t ttl;
        std::vector<MacAddress> targets;
        std::uint32_t total_len;
        std::uint16_t block_size;
        std::uint16_t K;
        std::vector<std::vector<std::uint8_t>> blocks;

        std::set<MacAddress> init_acked;
        std::set<MacAddress> finished;
        std::atomic<bool> stop{false};
        TaskHandle_t task = nullptr;

        AckPromise promise;
    };

    std::mutex tx_sessions_mutex;
    std::map<SenderSessionKey, std::shared_ptr<SenderSession>> tx_sessions;

};

struct QueueItem {
    std::size_t size;
    MacAddress source;
    std::uint16_t channel;
    uint8_t payload[];
};

namespace {

segmented::SessionId sha256_of(std::span<const std::uint8_t> data) {
    segmented::SessionId sid{};
    // mbedTLS v2 one-shot function without *_ret
    (void) mbedtls_sha256(reinterpret_cast<const unsigned char*>(data.data()),
    static_cast<size_t>(data.size()),
    reinterpret_cast<unsigned char*>(sid.bytes),
    /*is224=*/0);
    return sid;
}

inline std::size_t header_size_bytes(const Header& h) {
    return sizeof(Header) + static_cast<std::size_t>(h.target_count) * 6u;
}

inline bool targets_contains(const Header& h, const MacAddress& addr) {
    const auto* t = reinterpret_cast<const MacAddress*>(h.targets);
    for (std::uint8_t i = 0; i < h.target_count; ++i) {
        if (t[i] == addr) return true;
    }
    return false;
}

inline std::vector<MacAddress> targets_vector(const std::set<MacAddress>& targets) {
    return std::vector<MacAddress>(targets.begin(), targets.end());
}

static State g_state{};

inline bool is_kiddy_device_locked() {
    return g_state.active_kiddy_count > 0;
}

void send_buffer(std::span<const std::uint8_t> data) {
    using namespace std::chrono_literals;
    static MacAddress bcast = MacAddress::broadcast();
    esp_err_t err = ESP_OK;
    while ((err = esp_now_send(bcast.data(), data.data(), static_cast<int>(data.size()))) == ESP_ERR_ESPNOW_NO_MEM)
        std::this_thread::sleep_for(100ms);
    CHECK_IDF_ERROR(err);
}

Id build_and_send(std::uint8_t channel,
                    std::uint8_t ttl,
                    Type type,
                    std::span<const MacAddress> targets,
                    std::span<const std::uint8_t> payload) {

    Header header;
    header.id.source    = g_state.my_address;
    header.id.seq       = g_state.msg_seq++;
    header.type         = type;
    header.ttl          = ttl;
    header.channel      = channel;
    header.target_count = static_cast<std::uint8_t>(std::min<std::size_t>(targets.size(), UINT8_MAX));

    const std::size_t hdr_bytes = sizeof(Header) + static_cast<std::size_t>(header.target_count) * 6u;
    const std::size_t total     = hdr_bytes + payload.size();
    if (total > ESP_NOW_MAX_DATA_LEN_V2) {
        throw exceptions::Exception(std::runtime_error("disnet: packet too large for ESP-NOW"));
    }

    std::vector<std::uint8_t> buf(total);
    std::memcpy(buf.data(), &header, sizeof(Header));
    if (header.target_count) {
        std::memcpy(buf.data() + sizeof(Header), targets.data(), header.target_count * 6u);
    }

    if (!payload.empty()) {
        std::memcpy(buf.data() + hdr_bytes, payload.data(), payload.size());
    }

    std::scoped_lock l(g_state.heartbeats_mutex);
    g_state.last_message = Clock::now();

    send_buffer(buf);

    return header.id;
}

void forward_packet(std::span<std::uint8_t> packet) {
    if (packet.size() < sizeof(Header))
        return;

    auto* hdr = reinterpret_cast<Header*>(packet.data());
    if (hdr->ttl == 0)
        return;

    hdr->ttl--;
    send_buffer(packet);
    hdr->ttl++;
}

void dispatch(const MacAddress& source, std::uint8_t channel, std::span<const std::uint8_t> payload) {
    std::scoped_lock l(g_state.channel_handlers_mutex);
    auto it = g_state.channel_handlers.find(channel);
    if (it != g_state.channel_handlers.end() && it->second) {
        it->second(source, payload);
    }
}

void enqueue_packet(MacAddress source, std::uint8_t channel, std::span<const std::uint8_t> payload) {
    QueueItem* item = static_cast<QueueItem*>(std::malloc(sizeof(QueueItem) + payload.size()));
    item->source = source;
    item->channel = channel;
    item->size = payload.size();
    std::memcpy(&item->payload, payload.data(), payload.size());

    if (xQueueSend(g_state.packet_queue, &item, 0) != pdPASS) {
        free(item);
    }
}

void handle_ack(std::span<const std::uint8_t> payload_span) {
    const Id* acked = reinterpret_cast<const Id*>(payload_span.data());

    std::scoped_lock l(g_state.ack_promises_mutex);

    auto it = g_state.ack_promises.find(*acked);
    if (it != g_state.ack_promises.end()) {
        try {
            it->second.promise.set_value({});
        } catch (...) {
        }
        g_state.ack_promises.erase(it);
    } else {
        ESP_LOGD(g_tag, "ACK for unknown Id (maybe timed out or already handled)");
    }
}

static void send_reliable_ack(const Header& hdr) {
    const uint8_t* id_bytes = reinterpret_cast<const uint8_t*>(&hdr.id);
    std::span<const uint8_t> ack_payload(id_bytes, sizeof(Id));

    MacAddress target = hdr.id.source;
    std::span<const MacAddress> targets(&target, 1);

    build_and_send(hdr.channel, g_state.initial_ttl, Type::ReliableAck, targets, ack_payload);
}

// ------------------------- Utilities: hashing & PRNG ---------------------------------

static inline std::uint32_t xorshift32(std::uint32_t& s) {
    std::uint32_t x = s;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    s = x;
    return x;
}

static std::uint16_t choose_degree(std::uint16_t K, std::uint32_t& rng) {
    if (K <= 1) return 1;
    // Simple distribution favoring degree-1 for peel decoding
    // P(1)=0.5, P(2)=0.25, P(3)=0.15, P(4)=0.08, P(>=5)=0.02
    std::uint32_t r = xorshift32(rng) % 100;
    if (r < 50) return 1;
    if (r < 75) return std::min<std::uint16_t>(2, K);
    if (r < 90) return std::min<std::uint16_t>(3, K);
    if (r < 98) return std::min<std::uint16_t>(4, K);
    return std::min<std::uint16_t>(5, K);
}

static void select_unique_indices(std::uint16_t K, std::uint16_t D, std::uint32_t& rng, std::vector<std::uint16_t>& out) {
    out.clear();
    out.reserve(D);
    // small D (<=5), rejection sampling
    while (out.size() < D) {
        std::uint16_t idx = static_cast<std::uint16_t>(xorshift32(rng) % K);
        if (std::find(out.begin(), out.end(), idx) == out.end()) out.push_back(idx);
    }
}

static void xor_into(std::vector<std::uint8_t>& dst, std::span<const std::uint8_t> src) {
    for (std::size_t i = 0; i < dst.size(); ++i) dst[i] ^= src[i];
}

static void rx_try_peel_decode(State::ReceiverSession& rs) {
    bool progress = true;
    while (progress) {
        progress = false;
        for (auto& eq : rs.equations) {
            if (eq.idx.empty()) continue;
            std::size_t w = 0;
            for (std::size_t i = 0; i < eq.idx.size(); ++i) {
                std::uint16_t b = eq.idx[i];
                if (b < rs.known.size() && rs.known[b]) {
                    xor_into(eq.data, rs.blocks[b]);
                } else {
                    eq.idx[w++] = b;
                }
            }
            eq.idx.resize(w);
        }

        for (std::size_t e = 0; e < rs.equations.size(); ) {
            auto& eq = rs.equations[e];
            if (eq.idx.size() == 1) {
                std::uint16_t b = eq.idx[0];
                if (!rs.known[b]) {
                    rs.blocks[b] = eq.data; // move
                    rs.known[b] = true;
                    rs.innovative_count++;
                    rs.last_progress = Clock::now();
                    progress = true;
                }
                // remove equation
                rs.equations.erase(rs.equations.begin() + e);
                continue;
            }
            ++e;
        }

    }
}

static void handle_segmented_announce(const Header& hdr, std::span<const std::uint8_t> payload) {
    using namespace segmented;
    if (payload.size() < sizeof(AnnouncePayload)) return;
    const auto* ann = reinterpret_cast<const AnnouncePayload*>(payload.data());

    ESP_LOGD(g_tag, "SegmentedAnnounce: channel: %u, session: %u, length: %u", hdr.channel, ann->session, ann->total_len);

    std::shared_ptr<State::ReceiverSession> rs; 
    {
        std::scoped_lock l(g_state.rx_sessions_mutex);
        auto [it, _] = g_state.rx_sessions.emplace(
            State::ReceiverSessionKey{ hdr.channel, hdr.id.source, ann->session },
            std::make_shared<State::ReceiverSession>());
        rs = it->second;
    }
    rs->session = ann->session;
    rs->channel = hdr.channel;
    rs->sender  = hdr.id.source;
    rs->total_len = ann->total_len;
    rs->block_size = ann->block_size;
    rs->K = ann->block_count;
    rs->blocks.assign(rs->K, std::vector<std::uint8_t>(rs->block_size));
    rs->known.assign(rs->K, false);

    // Send INIT ACK back to sender
    AckPayload ap{};
    ap.session = ann->session;
    ap.flags = ACK_FLAG_INIT;
    std::span<const MacAddress> t(&rs->sender, 1);
    std::span<const std::uint8_t> p(reinterpret_cast<const std::uint8_t*>(&ap), sizeof(ap));
    build_and_send(hdr.channel, g_state.initial_ttl, Type::SegmentedAck, t, p);
}

static void handle_segmented_symbol(const Header& hdr, std::span<const std::uint8_t> payload) {
    using namespace segmented;
    if (payload.size() < sizeof(SymbolPayloadHeader)) return;
    const auto* sph = reinterpret_cast<const SymbolPayloadHeader*>(payload.data());

    ESP_LOGD(g_tag, "Segmented: channel: %u, session: %u", hdr.channel, sph->session);

    State::ReceiverSessionKey key{ hdr.channel, hdr.id.source, sph->session };

    std::shared_ptr<State::ReceiverSession> rs;
    {
        std::scoped_lock l(g_state.rx_sessions_mutex);
        auto it = g_state.rx_sessions.find(key);
        if (it == g_state.rx_sessions.end()) {
            ESP_LOGD(g_tag, "No session with key: channel: %u, source: %u, session: %u", hdr.channel, hdr.id.source, sph->session.bytes[31]);
            return;
        }
        rs = it->second;
    }

    const std::size_t header_bytes = sizeof(SymbolPayloadHeader);
    if (payload.size() < header_bytes + rs->block_size)
        return;

    const std::uint32_t seed = sph->seed;
    if (!rs->seen_seeds.insert(seed).second) {
        if ((rs->seen_seeds.size() % 16) == 0) {
            NackPayload np{ sph->session, NACK_REPEAT };
            std::span<const MacAddress> t(&rs->sender, 1);
            std::span<const std::uint8_t> p(reinterpret_cast<const std::uint8_t*>(&np), sizeof(np));
            build_and_send(hdr.channel, g_state.initial_ttl, Type::SegmentedNack, t, p);
        }
        return;
    }

    std::uint32_t rng = seed;
    for (int i = 0; i < 8; ++i) rng ^= (reinterpret_cast<const std::uint32_t*>(sph->session.bytes))[i];
    const std::uint16_t D = choose_degree(rs->K, rng);
    std::vector<std::uint16_t> idx;
    select_unique_indices(rs->K, D, rng, idx);

    State::ReceiverSession::Equation eq;
    eq.data.assign(rs->block_size, 0);
    std::memcpy(eq.data.data(), payload.data() + header_bytes, rs->block_size);

    for (std::uint16_t b : idx) {
        if (rs->known[b]) {
            xor_into(eq.data, rs->blocks[b]);
        } else {
            eq.idx.push_back(b);
        }
    }

    if (eq.idx.empty()) {
    } else if (eq.idx.size() == 1) {
        std::uint16_t b = eq.idx[0];
        if (!rs->known[b]) {
            rs->blocks[b] = std::move(eq.data);
            rs->known[b] = true;
            rs->innovative_count++;
            rs->last_progress = Clock::now();
            rx_try_peel_decode(*rs);
        }
    } else {
        rs->equations.emplace_back(std::move(eq));
        rx_try_peel_decode(*rs);
    }

    bool complete = std::all_of(rs->known.begin(), rs->known.end(), [](bool v){return v;});
    if (complete) {
        std::vector<std::uint8_t> full;
        full.reserve(rs->block_size * rs->K);
        for (std::size_t i = 0; i < rs->K; ++i) {
            full.insert(full.end(), rs->blocks[i].begin(), rs->blocks[i].end());
        }
        if (full.size() > rs->total_len) full.resize(rs->total_len);

        enqueue_packet(hdr.id.source, hdr.channel, full);

        AckPayload ap{}; ap.session = sph->session; ap.flags = ACK_FLAG_FINISH;
        std::span<const MacAddress> t(&rs->sender, 1);
        std::span<const std::uint8_t> p(reinterpret_cast<const std::uint8_t*>(&ap), sizeof(ap));
        build_and_send(hdr.channel, g_state.initial_ttl, Type::SegmentedAck, t, p);

        {
            std::scoped_lock l(g_state.rx_sessions_mutex);
            g_state.rx_sessions.erase(key);
        }
    } else {
        const auto now = Clock::now();
        if (now - rs->last_progress > std::chrono::milliseconds(500)) {
            NackPayload np{ sph->session, NACK_NEED_MORE };
            std::span<const MacAddress> t(&rs->sender, 1);
            std::span<const std::uint8_t> p(reinterpret_cast<const std::uint8_t*>(&np), sizeof(np));
            build_and_send(hdr.channel, g_state.initial_ttl, Type::SegmentedNack, t, p);
            rs->last_progress = now; // avoid spamming
        }
    }

}

static void handle_segmented_ack(const Header& hdr, std::span<const std::uint8_t> payload) {
    using namespace segmented;
    if (payload.size() < sizeof(AckPayload)) return;
    const auto* ap = reinterpret_cast<const AckPayload*>(payload.data());

    // Find sender session
    State::SenderSessionKey key{ ap->session };
    std::shared_ptr<State::SenderSession> ss;
    {
        std::scoped_lock l(g_state.tx_sessions_mutex);
        auto it = g_state.tx_sessions.find(key);
        if (it == g_state.tx_sessions.end()) return;
        ss = it->second;
    }

    ESP_LOGD(g_tag, "SegmentedAck: channel: %u, session: %u, flags: %u", hdr.channel, ap->session, (std::uint8_t)ap->flags);

    if (ap->flags & ACK_FLAG_INIT) {
        ss->init_acked.insert(hdr.id.source);
    }
    if (ap->flags & ACK_FLAG_FINISH) {
        ss->finished.insert(hdr.id.source);
        if (!ss->targets.empty() && ss->finished.size() >= ss->targets.size()) {
            // done
            try { ss->promise.set_value({}); } catch(...) {}
            ss->stop.store(true);
        }
    }
}

static void handle_segmented_nack(const Header& hdr, std::span<const std::uint8_t> payload) {
    using namespace segmented;
    if (payload.size() < sizeof(NackPayload)) return;
    const auto* np = reinterpret_cast<const NackPayload*>(payload.data());

    ESP_LOGD(g_tag, "SegmentedNack: channel: %u, session: %u", hdr.channel, np->session);

    // Find sender session
    State::SenderSessionKey key{ np->session };
    std::shared_ptr<State::SenderSession> ss;
    {
        std::scoped_lock l(g_state.tx_sessions_mutex);
        auto it = g_state.tx_sessions.find(key);
        if (it == g_state.tx_sessions.end()) return;
        ss = it->second;
    }
    (void)hdr;
}

void handle_incoming(const esp_now_recv_info_t* info, const std::uint8_t* data, int len) {
    if (!info || !data || len <= 0) {
        ESP_LOGW(g_tag, "Incorrect message received. info: %p, data: %p, len: %d", info, data, len);
        return;
    }

    MacAddress source;
    std::memcpy(source._data, info->src_addr, 6);

    ESP_LOGD(g_tag, "Packet from: %x:%x:%x:%x:%x:%x", source[0], source[1], source[2], source[3], source[4], source[5]);
    
    std::span<const std::uint8_t> packet_ro(data, static_cast<std::size_t>(len));
    if (packet_ro.size() < sizeof(Header)) {
        ESP_LOGW(g_tag, "Incorrect message");
        
        return;
    }

    const auto* hdr = reinterpret_cast<const Header*>(packet_ro.data());
    const std::size_t hdr_bytes = sizeof(Header) + static_cast<std::size_t>(hdr->target_count) * 6u;
    if (hdr_bytes > packet_ro.size()) {
        ESP_LOGW(g_tag, "Incorrect message");
        return;
    }

    if (g_state.custom_filters_enabled) {
        std::scoped_lock l(g_state.filter_mutex);

        const bool keep_input =
            g_state.input_filter
                ? g_state.input_filter(*hdr)
                : default_input_filter(*hdr);
        if (!keep_input)
            return;
    } else {
        if (!default_input_filter(*hdr)) {
            ESP_LOGD(g_tag, "input filter rejects");
            return;
        }
    }

    if (g_state.dedupe.check_seen_and_mark(hdr->id)) {
        ESP_LOGD(g_tag, "Message is duplicate");
        return;
    }

    if (g_state.custom_filters_enabled) {
        std::scoped_lock l(g_state.filter_mutex);

        bool allow_by_device_policy = false;
        {
            std::scoped_lock l(g_state.active_channels_mutex);
            const bool kiddy = is_kiddy_device_locked();
            allow_by_device_policy = kiddy ? true : g_state.active_channels[hdr->channel];
        }

        const bool allow_by_filter =
            g_state.forwarding_filter
                ? g_state.forwarding_filter(*hdr)
                : default_forwarding_filter(*hdr);

        if (hdr->ttl > 0 && allow_by_device_policy && allow_by_filter) {
            auto* mut = const_cast<std::uint8_t*>(packet_ro.data());
            std::span<std::uint8_t> packet_rw(mut, packet_ro.size());
            forward_packet(packet_rw);
        }

        const bool allow_processing =
            g_state.processing_filter
                ? g_state.processing_filter(*hdr)
                : default_processing_filter(*hdr);

        if (!allow_processing)
            return;

    } else {
        bool allow_by_device_policy = false;
        {
            std::scoped_lock l(g_state.active_channels_mutex);
            const bool kiddy = (g_state.active_kiddy_count > 0);
            allow_by_device_policy = kiddy ? true : g_state.active_channels[hdr->channel];
        }

        const bool allow_by_filter = default_forwarding_filter(*hdr);

        if (hdr->ttl > 0 && allow_by_device_policy && allow_by_filter) {
            auto* mut = const_cast<std::uint8_t*>(packet_ro.data());
            std::span<std::uint8_t> packet_rw(mut, packet_ro.size());
            forward_packet(packet_rw);
        }

        if (!default_processing_filter(*hdr)) {
            ESP_LOGD(g_tag, "processing filter rejects");
            return;
        }

    }

    {
        std::scoped_lock l(g_state.heartbeats_mutex);
        g_state.heartbeats.emplace(std::pair<std::uint8_t, MacAddress>{ hdr->channel, hdr->id.source }, Clock::now());
    }

    switch (hdr->type) {
        case Type::Raw:
            enqueue_packet(hdr->id.source, hdr->channel, packet_ro.subspan(header_size_bytes(*hdr)));
            break;

        case Type::Reliable:
            send_reliable_ack(*hdr);
            enqueue_packet(hdr->id.source, hdr->channel, packet_ro.subspan(header_size_bytes(*hdr)));
            break;

        case Type::ReliableAck:
            handle_ack(packet_ro.subspan(header_size_bytes(*hdr)));
            break;

        case Type::Segmented: {
            auto pl = packet_ro.subspan(header_size_bytes(*hdr));
            handle_segmented_symbol(*hdr, pl);
            break;
        }

        case Type::SegmentedAnnounce: {
            auto pl = packet_ro.subspan(header_size_bytes(*hdr));
            handle_segmented_announce(*hdr, pl);
            break;
        }

        case Type::SegmentedAck: {
            auto pl = packet_ro.subspan(header_size_bytes(*hdr));
            handle_segmented_ack(*hdr, pl);
            break;
        }

        case Type::SegmentedNack: {
            auto pl = packet_ro.subspan(header_size_bytes(*hdr));
            handle_segmented_nack(*hdr, pl);
            break;
        }

        case Type::Heartbeat:
            break;
    }

}

} // namespace

bool default_input_filter(const message::Header& header) {
    return header.id.source != g_state.my_address;
}

bool default_processing_filter(const message::Header& header) {
    if (header.target_count == 0)
        return true;

    return targets_contains(header, g_state.my_address);
}

bool default_forwarding_filter(const message::Header& header) {
    const bool for_me = (header.target_count != 0) && targets_contains(header, g_state.my_address);
    return (!for_me) && (header.ttl > 0);
}

void init() {
    InitState expected = InitState::NotInitialized;
    if (!g_state.init_state.compare_exchange_strong(expected, InitState::Initializing)) {
        throw exceptions::Exception(std::runtime_error("disnet already initialized"));
    }

    g_state.msg_seq.store(esp_random(), std::memory_order_relaxed);

    g_state.packet_queue = xQueueCreate(32, sizeof(QueueItem*));
    if (!g_state.packet_queue) {
        g_state.init_state.store(InitState::NotInitialized, std::memory_order_release);
        throw exceptions::Exception(std::runtime_error("disnet: failed to create inbound packet queue"));
    }

    CHECK_IDF_ERROR(esp_now_init());
    CHECK_IDF_ERROR(esp_now_register_recv_cb(handle_incoming));

    esp_now_peer_info_t peer_info = {
        .peer_addr = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
        .lmk = {0},
        .channel = 0,
        .ifidx   = WIFI_IF_STA,
        .encrypt = false,
        .priv = nullptr
    };

    CHECK_IDF_ERROR(esp_now_add_peer(&peer_info));
    {
        std::scoped_lock l(g_state.active_channels_mutex);
        g_state.initial_ttl.store(15, std::memory_order_relaxed);
        g_state.active_channels.assign(256, false);
        g_state.active_kiddy_count = 0;
    }

    {
        std::scoped_lock l(g_state.heartbeats_mutex);
        g_state.heartbeats.clear();
    }

    g_state.init_state.store(InitState::Initialized, std::memory_order_release);

}

bool is_initialized() {
    return g_state.init_state.load(std::memory_order_acquire) == InitState::Initialized;
}

void shutdown() {
    InitState expected = InitState::Initialized;
    if (!g_state.init_state.compare_exchange_strong(expected, InitState::Initializing)) {
        return;

    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wterminate"

    CHECK_IDF_ERROR(esp_now_unregister_recv_cb());
    CHECK_IDF_ERROR(esp_now_deinit());

    if (g_state.packet_queue) {
        QueueItem* pkt = nullptr;
        while (xQueueReceive(g_state.packet_queue, &pkt, 0) == pdPASS) {
            std::free(pkt);
        }
        vQueueDelete(g_state.packet_queue);
        g_state.packet_queue = nullptr;
    }

#pragma GCC diagnostic pop

    {
        std::scoped_lock l(g_state.channel_handlers_mutex);
        g_state.channel_handlers.clear();
    }
    {
        std::scoped_lock l(g_state.heartbeats_mutex);
        g_state.heartbeats.clear();
    }
    {
        std::scoped_lock l(g_state.active_channels_mutex);
        g_state.active_channels.assign(256, false);
        g_state.active_kiddy_count = 0;
    }

    g_state.init_state.store(InitState::NotInitialized, std::memory_order_release);
}

void activate_channel(std::uint8_t channel) {
    std::scoped_lock l(g_state.active_channels_mutex);
    std::vector<bool>::reference slot = g_state.active_channels[channel];
    if (!slot) {
        slot = true;
        if (channel < 128) {
            ++g_state.active_kiddy_count;
        }
    }
}

bool is_channel_active(std::uint8_t channel) {
    std::scoped_lock l(g_state.active_channels_mutex);
    return g_state.active_channels[channel];
}

void register_handler(std::uint8_t channel, Callback cb) {
    std::scoped_lock l(g_state.channel_handlers_mutex);
    g_state.channel_handlers[channel] = std::move(cb);
}

static inline void recompute_custom_filters_flag_unlocked() {
    const bool enabled =
        static_cast<bool>(g_state.input_filter) ||
        static_cast<bool>(g_state.processing_filter) ||
        static_cast<bool>(g_state.forwarding_filter);
    g_state.custom_filters_enabled.store(enabled, std::memory_order_relaxed);
}

void set_input_filter(Predicate predicate) {
    std::scoped_lock l(g_state.filter_mutex);
    g_state.input_filter = std::move(predicate);
    recompute_custom_filters_flag_unlocked();
}

void set_processing_filter(Predicate predicate) {
    std::scoped_lock l(g_state.filter_mutex);
    g_state.processing_filter = std::move(predicate);
    recompute_custom_filters_flag_unlocked();
}

void set_forwarding_filter(Predicate predicate) {
    std::scoped_lock l(g_state.filter_mutex);
    g_state.forwarding_filter = std::move(predicate);
    recompute_custom_filters_flag_unlocked();
}

bool process_one(std::chrono::milliseconds time_to_wait) {
    if (!g_state.packet_queue) return false;

    QueueItem* item = nullptr;
    if (xQueueReceive(g_state.packet_queue, &item, pdMS_TO_TICKS(time_to_wait.count())) != pdPASS) {
        return false;
    }

    dispatch(item->source, item->channel, std::span<std::uint8_t>(item->payload, item->size));

    std::free(item);
    return true;
}

void send_raw(std::uint8_t channel,
              std::uint8_t ttl,
              const std::set<MacAddress>& targets,
              std::span<const std::uint8_t> payload) {
    if (!is_channel_active(channel)) {
        ESP_LOGW(g_tag, "send_raw: Channel not active: %x", channel);
        return;
    }

    const auto tvec = targets_vector(targets);
    build_and_send(channel, ttl, Type::Raw, tvec, payload);
}

AckFuture send_reliable(std::uint8_t channel,
                        std::uint8_t ttl,
                        const std::set<MacAddress>& targets,
                        std::span<const std::uint8_t> payload) {
    if (!is_channel_active(channel)) {
        ESP_LOGW(g_tag, "send_reliable: Channel not active: %x", channel);
        return {};
    }

    const auto tvec = targets_vector(targets);
    Id id = build_and_send(channel, ttl, Type::Reliable, tvec, payload);

    std::scoped_lock l(g_state.ack_promises_mutex);
    auto [it, inserted] = g_state.ack_promises.emplace(id, AckCookie{ Clock::now(), {} });

    return it->second.promise.get_future();
}

static void tx_send_announce(const State::SenderSession& ss) {
    using namespace segmented;
    AnnouncePayload ap{ ss.session, ss.total_len, ss.block_size, ss.K };

    Header h{};
    h.target_count = static_cast<std::uint8_t>(std::min<std::size_t>(ss.targets.size(), UINT8_MAX));
    const std::size_t maxpl = (sizeof(Header) + h.target_count * 6u <= ESP_NOW_MAX_DATA_LEN_V2)
        ? (ESP_NOW_MAX_DATA_LEN_V2 - (sizeof(Header) + h.target_count * 6u)) : 0;
    if (sizeof(ap) > maxpl) {
        ESP_LOGW(g_tag, "SegmentedAnnounce payload too large");
    }

    std::span<const MacAddress> t(ss.targets.data(), ss.targets.size());
    std::span<const std::uint8_t> p(reinterpret_cast<const std::uint8_t*>(&ap), sizeof(ap));
    (void)build_and_send(ss.channel, ss.ttl, Type::SegmentedAnnounce, t, p);
}

static void tx_send_symbol(const State::SenderSession& ss, std::uint32_t seed) {
    using namespace segmented;

    Header h{};
    h.target_count = static_cast<std::uint8_t>(std::min<std::size_t>(ss.targets.size(), UINT8_MAX));
    const std::size_t maxpl = h.max_payload_size(); // uses header's helper

    const std::size_t overhead = sizeof(SymbolPayloadHeader);
    if (overhead + ss.block_size > maxpl) {
        ESP_LOGW(g_tag, "Symbol too large for ESP-NOW frame");
        return;
    }

    std::vector<std::uint8_t> buf(overhead + ss.block_size);
    auto* sh = reinterpret_cast<SymbolPayloadHeader*>(buf.data());
    sh->session = ss.session;
    sh->seed = seed;

    std::uint32_t rng = seed;
    for (int i = 0; i < 8; ++i)
        rng ^= (reinterpret_cast<const std::uint32_t*>(ss.session.bytes))[i];

    const std::uint16_t D = choose_degree(ss.K, rng);
    std::vector<std::uint16_t> idx;
    select_unique_indices(ss.K, D, rng, idx);

    std::uint8_t* out = buf.data() + sizeof(SymbolPayloadHeader);
    std::memset(out, 0, ss.block_size);
    for (std::uint16_t b : idx) {
        const auto& src = ss.blocks[b];
        for (std::size_t i = 0; i < ss.block_size; ++i)
            out[i] ^= src[i];
    }

    std::span<const MacAddress> t(ss.targets.data(), ss.targets.size());
    std::span<const std::uint8_t> p(buf.data(), buf.size());
    (void)build_and_send(ss.channel, ss.ttl, Type::Segmented, t, p);
}

static void sender_task(void* pv) {
    using namespace segmented;
    auto ss = static_cast<State::SenderSession*>(pv);

    for (int i = 0; i < 3 && !ss->stop.load(); ++i) {
        tx_send_announce(*ss);
        std::this_thread::sleep_for(10ms);
    }

    const bool is_broadcast = ss->targets.empty();

    std::uint32_t seed = esp_random();
    const std::size_t max_symbols = is_broadcast ? (ss->K * 2u) : (ss->K * 10u); // cap

    std::size_t sent = 0;
    while (!ss->stop.load()) {
        tx_send_symbol(*ss, seed);
        seed = xorshift32(seed);
        ++sent;

        if (!is_broadcast && ss->finished.size() >= ss->targets.size()) break;
        if (sent >= max_symbols) break;
        std::this_thread::sleep_for(100ms);
    }

    if (is_broadcast) {
        try { ss->promise.set_value({}); } catch(...) {}
    } else if (ss->finished.size() >= ss->targets.size()) {
        try { ss->promise.set_value({}); } catch(...) {}
    } else {
        ESP_LOGW(g_tag, "Segmented sender stopping without all FINISH ACKs (%u/%u)", (unsigned)ss->finished.size(), (unsigned)ss->targets.size());
        try { ss->promise.set_value({}); } catch(...) {}
    }

    ss->stop.store(true);
    vTaskDelete(nullptr);
}

static std::shared_ptr<State::SenderSession> create_sender_session(std::uint8_t channel,
                                                                   std::uint8_t ttl,
                                                                   const std::vector<MacAddress>& targets,
                                                                   std::span<const std::uint8_t> payload) {
    using namespace segmented;

    Header h{}; h.target_count = static_cast<std::uint8_t>(std::min<std::size_t>(targets.size(), UINT8_MAX));
    const std::size_t maxpl = (sizeof(Header) + h.target_count * 6u <= ESP_NOW_MAX_DATA_LEN_V2)
        ? (ESP_NOW_MAX_DATA_LEN_V2 - (sizeof(Header) + h.target_count * 6u)) : 0;

    const std::size_t symbol_overhead = sizeof(SymbolPayloadHeader);
    if (maxpl <= symbol_overhead + 1) {
        throw exceptions::Exception(std::runtime_error("disnet: not enough space for segmented symbol"));
    }
    std::uint16_t block_size = static_cast<std::uint16_t>(std::min<std::size_t>(maxpl - symbol_overhead, 1024));

    const std::uint32_t total_len = static_cast<std::uint32_t>(payload.size());
    const std::uint16_t K = static_cast<std::uint16_t>((total_len + block_size - 1) / block_size);

    auto ss = std::make_shared<State::SenderSession>();
    ss->session    = sha256_of(payload);
    ss->channel    = channel;
    ss->ttl        = ttl;
    ss->targets    = targets;
    ss->total_len  = total_len;
    ss->block_size = block_size;
    ss->K          = K;
    ss->blocks.resize(K);

    for (std::uint16_t i = 0; i < K; ++i) {
        ss->blocks[i].assign(block_size, 0);
        const std::size_t off = static_cast<std::size_t>(i) * block_size;
        const std::size_t n   = std::min<std::size_t>(block_size, payload.size() - std::min<std::size_t>(off, payload.size()));
        if (n > 0) std::memcpy(ss->blocks[i].data(), payload.data() + off, n);
    }

    return ss;
}

AckFuture send_segmented(std::uint8_t channel,
                         std::uint8_t ttl,
                         const std::set<MacAddress>& targets,
                         std::span<const std::uint8_t> payload) {
    if (!is_channel_active(channel)) {
        ESP_LOGW(g_tag, "send_segmented: Channel not active: %x", channel);
        std::promise<std::tuple<>> p; p.set_exception(std::make_exception_ptr(std::runtime_error("channel inactive"))); return p.get_future();
    }

    const auto tvec = targets_vector(targets);

    auto ss = create_sender_session(channel, ttl, tvec, payload);

    State::SenderSessionKey key{ ss->session };
    {
        std::scoped_lock l(g_state.tx_sessions_mutex);
        g_state.tx_sessions[key] = ss;
    }

    // launch task
    BaseType_t ok = xTaskCreate(sender_task, "disnet_seg_tx", 4096, ss.get(), tskIDLE_PRIORITY + 1, &ss->task);
    if (ok != pdPASS) {
        std::promise<std::tuple<>> p; p.set_exception(std::make_exception_ptr(std::runtime_error("failed to start sender task"))); return p.get_future();
    }

    return ss->promise.get_future();
}

void send_heartbeat(std::uint8_t channel, std::uint8_t ttl) {
    if (!is_channel_active(channel))
        return;

    build_and_send(channel, ttl, Type::Heartbeat, {}, {});
    std::scoped_lock l(g_state.heartbeats_mutex);
}

void ensure_heartbeat(std::uint8_t channel, std::uint8_t ttl, TimePoint cutoff) {
    const auto key = std::make_pair(channel, g_state.my_address);
    bool need = false;
    {
        std::scoped_lock l(g_state.heartbeats_mutex);
        need = g_state.last_message < cutoff;
    }
    if (need)
        send_heartbeat(channel, ttl);
}

TimePoint last_heartbeat(std::uint8_t channel, const MacAddress& address) {
    const auto key = std::make_pair(channel, address);
    std::scoped_lock l(g_state.heartbeats_mutex);
    auto it = g_state.heartbeats.find(key);
    if (it == g_state.heartbeats.end()) return TimePoint{};
    return it->second;
}

std::vector<std::pair<MacAddress, TimePoint>> neighbours(std::uint8_t channel, std::optional<TimePoint> cutoff) {
    std::vector<std::pair<MacAddress, TimePoint>> out;
    std::scoped_lock l(g_state.heartbeats_mutex);
    for (const auto& [key, ts] : g_state.heartbeats) {
        const auto& [ch, mac] = key;
        if (ch != channel) continue;
        if (cutoff.has_value() && ts < *cutoff) continue;
        out.emplace_back(mac, ts);
    }
    return out;
}

} // namespace bricks::disnet

