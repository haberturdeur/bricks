#include "bricks/disnet.hpp"

#include "freertos/task.h"

#include "mbedtls/sha256.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <thread>

using namespace std::chrono_literals;

namespace {

static constexpr std::uint8_t ACK_FLAG_INIT = 0x01;
static constexpr std::uint8_t ACK_FLAG_FINISH = 0x02;

static constexpr std::uint8_t NACK_REPEAT = 0x01;
static constexpr std::uint8_t NACK_NEED_MORE = 0x02;
static constexpr std::uint8_t NACK_INVALID = 0x04;

struct [[gnu::packed]] AnnouncePayload {
    bricks::disnet::detail::SessionId session;
    std::uint32_t total_len;
    std::uint16_t block_size;
    std::uint16_t block_count;
};

struct [[gnu::packed]] SymbolPayloadHeader {
    bricks::disnet::detail::SessionId session;
    std::uint32_t seed;
};

struct [[gnu::packed]] AckPayload {
    bricks::disnet::detail::SessionId session;
    std::uint8_t flags;
};

struct [[gnu::packed]] NackPayload {
    bricks::disnet::detail::SessionId session;
    std::uint8_t reason;
};

static bricks::disnet::detail::SessionId sha256_of(std::span<const std::uint8_t> data) {
    bricks::disnet::detail::SessionId sid{};
    (void)mbedtls_sha256(reinterpret_cast<const unsigned char*>(data.data()),
                         static_cast<size_t>(data.size()),
                         reinterpret_cast<unsigned char*>(sid.bytes),
                         0);
    return sid;
}

static std::uint32_t xorshift32(std::uint32_t& s) {
    std::uint32_t x = s;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    s = x;
    return x;
}

static std::uint16_t choose_degree(std::uint16_t K, std::uint32_t& rng) {
    if (K <= 1) return 1;
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
    while (out.size() < D) {
        std::uint16_t idx = static_cast<std::uint16_t>(xorshift32(rng) % K);
        if (std::find(out.begin(), out.end(), idx) == out.end()) out.push_back(idx);
    }
}

static void xor_into(std::vector<std::uint8_t>& dst, std::span<const std::uint8_t> src) {
    for (std::size_t i = 0; i < dst.size(); ++i) dst[i] ^= src[i];
}

static std::uint32_t mix_seed_with_session(std::uint32_t seed, const bricks::disnet::detail::SessionId& session) {
    std::uint32_t mixed = seed;
    for (std::size_t i = 0; i < 8; ++i) {
        std::uint32_t word = 0;
        std::memcpy(&word, session.bytes + (i * sizeof(word)), sizeof(word));
        mixed ^= word;
    }
    return mixed;
}

static bool rx_try_peel_decode(bricks::disnet::detail::ReceiverSession& rs,
                               bricks::disnet::TimePoint now,
                               const std::function<bool(std::uint16_t)>& ensure_block_cached) {
    bool progress = true;
    while (progress) {
        progress = false;

        for (bricks::disnet::detail::ReceiverSession::Equation& eq : rs.equations) {
            if (eq.idx.empty()) continue;
            std::size_t w = 0;
            for (std::size_t i = 0; i < eq.idx.size(); ++i) {
                std::uint16_t b = eq.idx[i];
                if (b < rs.known.size() && rs.known[b]) {
                    if (!ensure_block_cached(b)) return false;
                    xor_into(eq.data, rs.blocks[b]);
                } else {
                    eq.idx[w++] = b;
                }
            }
            eq.idx.resize(w);
        }

        for (std::size_t e = 0; e < rs.equations.size();) {
            bricks::disnet::detail::ReceiverSession::Equation& eq = rs.equations[e];
            if (eq.idx.size() == 1) {
                std::uint16_t b = eq.idx[0];
                if (!rs.known[b]) {
                    rs.blocks[b] = eq.data;
                    rs.known[b] = true;
                    rs.innovative_count++;
                    rs.last_progress = now;
                    progress = true;
                }
                rs.equations.erase(rs.equations.begin() + static_cast<std::ptrdiff_t>(e));
                continue;
            }
            ++e;
        }
    }
    return true;
}

struct SenderTaskArg {
    bricks::disnet::Node* node;
    std::shared_ptr<bricks::disnet::detail::SenderSession> session;
};

static bool is_valid_announce(const AnnouncePayload& ann, const bricks::disnet::Node::Config::SegmentedLimits& limits) {
    if (ann.block_size == 0 || ann.block_size > limits.max_block_size) return false;
    if (ann.block_count == 0 || ann.block_count > limits.max_block_count) return false;

    const std::size_t total = static_cast<std::size_t>(ann.block_size) * ann.block_count;
    if (total == 0 || total > limits.max_payload_bytes) return false;
    if (ann.total_len == 0 || ann.total_len > total) return false;
    return true;
}

} // namespace

namespace bricks::disnet {

void Node::_segmented_send_ack(std::uint8_t channel,
                               const MacAddress& target,
                               const detail::SessionId& session,
                               std::uint8_t flags) {
    AckPayload payload{
        .session = session,
        .flags = flags,
    };
    std::span<const MacAddress> targets(&target, 1);
    std::span<const std::uint8_t> bytes(reinterpret_cast<const std::uint8_t*>(&payload), sizeof(payload));
    (void)_build_and_send(channel, m_runtime.initial_ttl, message::Type::SegmentedAck, targets, bytes);
}

void Node::_segmented_send_nack(std::uint8_t channel,
                                const MacAddress& target,
                                const detail::SessionId& session,
                                std::uint8_t reason) {
    NackPayload payload{
        .session = session,
        .reason = reason,
    };
    std::span<const MacAddress> targets(&target, 1);
    std::span<const std::uint8_t> bytes(reinterpret_cast<const std::uint8_t*>(&payload), sizeof(payload));
    (void)_build_and_send(channel, m_runtime.initial_ttl, message::Type::SegmentedNack, targets, bytes);
}

void Node::_segmented_handle_announce(const message::Header& hdr, std::span<const std::uint8_t> payload) {
    if (payload.size() < sizeof(AnnouncePayload)) return;

    const AnnouncePayload* ann = reinterpret_cast<const AnnouncePayload*>(payload.data());
    if (!is_valid_announce(*ann, m_config.segmented_limits)) {
        _segmented_send_nack(hdr.channel, hdr.id.source, ann->session, NACK_INVALID);
        return;
    }

    std::shared_ptr<detail::ReceiverSession> rs;
    bool rx_overloaded = false;
    {
        std::scoped_lock l(m_segmented.rx_mutex);
        if (m_segmented.rx_sessions.size() >= m_config.segmented_limits.max_rx_sessions) {
            rx_overloaded = true;
        } else {
            std::pair<std::map<detail::ReceiverSessionKey, std::shared_ptr<detail::ReceiverSession>>::iterator, bool> insert_res =
                m_segmented.rx_sessions.emplace(
                detail::ReceiverSessionKey{hdr.channel, hdr.id.source, ann->session},
                std::make_shared<detail::ReceiverSession>());
            rs = insert_res.first->second;
        }
    }
    if (rx_overloaded) {
#if BRICKS_DISNET_DIAGNOSTICS
        m_diag.rx_session_rejected_limit.fetch_add(1, std::memory_order_relaxed);
#endif
        _segmented_send_nack(hdr.channel, hdr.id.source, ann->session, NACK_NEED_MORE);
        return;
    }

    MacAddress sender_for_reply{};
    {
        std::scoped_lock l(rs->mutex);
        rs->session = ann->session;
        rs->channel = hdr.channel;
        rs->sender = hdr.id.source;
        rs->total_len = ann->total_len;
        rs->block_size = ann->block_size;
        rs->K = ann->block_count;
        rs->blocks.assign(rs->K, {});
        rs->known.assign(rs->K, false);
        rs->cached.assign(rs->K, false);
        rs->cache_order.clear();
        rs->equations.clear();
        rs->seen_seeds.clear();
        rs->innovative_count = 0;
        rs->last_progress = _now();
        sender_for_reply = rs->sender;
    }

    _segmented_send_ack(hdr.channel, sender_for_reply, ann->session, ACK_FLAG_INIT);
}

void Node::_segmented_handle_symbol(const message::Header& hdr, std::span<const std::uint8_t> payload) {
    if (payload.size() < sizeof(SymbolPayloadHeader)) return;

    const SymbolPayloadHeader* sph = reinterpret_cast<const SymbolPayloadHeader*>(payload.data());
    detail::ReceiverSessionKey key{
        .channel = hdr.channel,
        .sender = hdr.id.source,
        .session = sph->session,
    };

    std::shared_ptr<detail::ReceiverSession> rs;
    {
        std::scoped_lock l(m_segmented.rx_mutex);
        std::map<detail::ReceiverSessionKey, std::shared_ptr<detail::ReceiverSession>>::iterator it = m_segmented.rx_sessions.find(key);
        if (it == m_segmented.rx_sessions.end()) return;
        rs = it->second;
    }

    const std::size_t header_bytes = sizeof(SymbolPayloadHeader);
    bool send_repeat_nack = false;
    bool send_need_more_nack = false;
    bool send_finish_ack = false;
    bool erase_session = false;
    std::vector<std::uint8_t> full_payload;
    MacAddress sender_for_reply{};
    const TimePoint now = _now();

    {
        std::scoped_lock l(rs->mutex);
        sender_for_reply = rs->sender;
        _segmented_process_symbol_locked(
            *rs,
            sph->session,
            sph->seed,
            payload.subspan(header_bytes),
            now,
            send_repeat_nack,
            send_need_more_nack,
            send_finish_ack,
            erase_session,
            full_payload);
    }

    if (send_repeat_nack) {
        _segmented_send_nack(hdr.channel, sender_for_reply, sph->session, NACK_REPEAT);
        return;
    }
    if (send_need_more_nack) {
        _segmented_send_nack(hdr.channel, sender_for_reply, sph->session, NACK_NEED_MORE);
    }
    if (send_finish_ack) {
        _enqueue_packet(hdr.id.source, hdr.channel, full_payload);
        _segmented_send_ack(hdr.channel, sender_for_reply, sph->session, ACK_FLAG_FINISH);

        if (erase_session) {
            std::scoped_lock l(m_segmented.rx_mutex);
            m_segmented.rx_sessions.erase(key);
        }
    }
}

void Node::_segmented_process_symbol_locked(detail::ReceiverSession& session,
                                            const detail::SessionId& session_id,
                                            std::uint32_t seed,
                                            std::span<const std::uint8_t> symbol_payload,
                                            TimePoint now,
                                            bool& send_repeat_nack,
                                            bool& send_need_more_nack,
                                            bool& send_finish_ack,
                                            bool& erase_session,
                                            std::vector<std::uint8_t>& full_payload) {
    const bool use_external_segment_store =
        static_cast<bool>(m_config.segment_store.store_block) && static_cast<bool>(m_config.segment_store.load_block);

    auto cache_touch = [&](std::uint16_t idx) {
        for (std::size_t i = 0; i < session.cache_order.size(); ++i) {
            if (session.cache_order[i] == idx) {
                session.cache_order.erase(session.cache_order.begin() + static_cast<std::ptrdiff_t>(i));
                break;
            }
        }
        session.cache_order.push_back(idx);
    };

    auto cache_evict = [&]() {
        if (!use_external_segment_store) return;
        const std::size_t limit = m_config.segmented_rx_cache_blocks;
        while (session.cache_order.size() > limit) {
            const std::uint16_t evict_idx = session.cache_order.front();
            session.cache_order.erase(session.cache_order.begin());
            if (evict_idx < session.cached.size() && session.cached[evict_idx]) {
                session.cached[evict_idx] = false;
                session.blocks[evict_idx].clear();
#if BRICKS_DISNET_DIAGNOSTICS
                m_diag.segment_cache_evictions.fetch_add(1, std::memory_order_relaxed);
#endif
            }
        }
    };

    auto ensure_block_cached = [&](std::uint16_t idx) -> bool {
        if (idx >= session.known.size() || !session.known[idx]) return false;
        if (!session.cached[idx]) {
            if (!use_external_segment_store) return false;
            session.blocks[idx].assign(session.block_size, 0);
            if (!m_config.segment_store.load_block(session.session, idx, std::span<std::uint8_t>(session.blocks[idx]))) {
#if BRICKS_DISNET_DIAGNOSTICS
                m_diag.segment_store_load_failures.fetch_add(1, std::memory_order_relaxed);
#endif
                session.blocks[idx].clear();
                return false;
            }
            session.cached[idx] = true;
        }
        cache_touch(idx);
        cache_evict();
        return true;
    };

    auto set_solved_block = [&](std::uint16_t idx, std::vector<std::uint8_t>&& data) {
        session.blocks[idx] = std::move(data);
        session.known[idx] = true;
        session.cached[idx] = true;
        cache_touch(idx);
        if (use_external_segment_store) {
            if (!m_config.segment_store.store_block(session.session, idx, std::span<const std::uint8_t>(session.blocks[idx]))) {
#if BRICKS_DISNET_DIAGNOSTICS
                m_diag.segment_store_store_failures.fetch_add(1, std::memory_order_relaxed);
#endif
            }
        }
        cache_evict();
    };

    if (symbol_payload.size() < session.block_size) return;

    if (!session.seen_seeds.insert(seed).second) {
        if ((session.seen_seeds.size() % 16) == 0) {
            send_repeat_nack = true;
        }
        return;
    }
    if (session.seen_seeds.size() > m_config.segmented_limits.max_seen_seeds_per_session) {
        session.seen_seeds.erase(session.seen_seeds.begin());
    }

    std::uint32_t rng = mix_seed_with_session(seed, session_id);
    const std::uint16_t degree = choose_degree(session.K, rng);

    std::vector<std::uint16_t> idx;
    select_unique_indices(session.K, degree, rng, idx);

    detail::ReceiverSession::Equation eq;
    eq.data.assign(session.block_size, 0);
    std::memcpy(eq.data.data(), symbol_payload.data(), session.block_size);

    for (std::uint16_t block : idx) {
        if (session.known[block]) {
            if (!ensure_block_cached(block)) {
                send_need_more_nack = true;
                eq.idx.clear();
                break;
            }
            xor_into(eq.data, session.blocks[block]);
        } else {
            eq.idx.push_back(block);
        }
    }

    if (eq.idx.size() == 1) {
        std::uint16_t block = eq.idx[0];
        if (!session.known[block]) {
            set_solved_block(block, std::move(eq.data));
            session.innovative_count++;
            session.last_progress = now;
            if (!rx_try_peel_decode(session, now, ensure_block_cached)) {
                send_need_more_nack = true;
            }
        }
    } else if (!eq.idx.empty()) {
        if (session.equations.size() >= m_config.segmented_limits.max_equations_per_session) {
            send_need_more_nack = true;
        } else {
            session.equations.emplace_back(std::move(eq));
            if (!rx_try_peel_decode(session, now, ensure_block_cached)) {
                send_need_more_nack = true;
            }
        }
    }

    const bool complete = std::all_of(session.known.begin(), session.known.end(), [](bool value) { return value; });
    if (complete) {
        bool can_build_full = true;
        full_payload.reserve(session.block_size * session.K);
        for (std::size_t i = 0; i < session.K; ++i) {
            if (!ensure_block_cached(static_cast<std::uint16_t>(i))) {
                can_build_full = false;
                break;
            }
            full_payload.insert(full_payload.end(), session.blocks[i].begin(), session.blocks[i].end());
        }
        if (can_build_full) {
            if (full_payload.size() > session.total_len) full_payload.resize(session.total_len);
            send_finish_ack = true;
            erase_session = true;
        } else {
            send_need_more_nack = true;
            full_payload.clear();
        }
    } else if (now - session.last_progress > 500ms) {
        send_need_more_nack = true;
        session.last_progress = now;
    }
}

void Node::_segmented_handle_ack(const message::Header& hdr, std::span<const std::uint8_t> payload) {
    if (payload.size() < sizeof(AckPayload)) return;

    const AckPayload* ap = reinterpret_cast<const AckPayload*>(payload.data());

    detail::SenderSessionKey key{
        .session = ap->session,
    };
    std::shared_ptr<detail::SenderSession> ss;
    {
        std::scoped_lock l(m_segmented.tx_mutex);
        std::map<detail::SenderSessionKey, std::shared_ptr<detail::SenderSession>>::iterator it = m_segmented.tx_sessions.find(key);
        if (it == m_segmented.tx_sessions.end()) return;
        ss = it->second;
    }

    std::scoped_lock l(ss->ack_mutex);
    if (ap->flags & ACK_FLAG_INIT) {
        ss->init_acked.insert(hdr.id.source);
    }
    if (ap->flags & ACK_FLAG_FINISH) {
        ss->finished.insert(hdr.id.source);
        if (!ss->targets.empty() && ss->finished.size() >= ss->targets.size()) {
            try {
                ss->promise.set_value({});
            } catch (...) {
            }
            ss->stop.store(true);
        }
    }
}

void Node::_segmented_handle_nack(std::span<const std::uint8_t> payload) {
    if (payload.size() < sizeof(NackPayload)) return;

    const NackPayload* np = reinterpret_cast<const NackPayload*>(payload.data());
    detail::SenderSessionKey key{
        .session = np->session,
    };

    std::scoped_lock l(m_segmented.tx_mutex);
    (void)m_segmented.tx_sessions.find(key);
}

void Node::_segmented_send_announce(const detail::SenderSession& ss) {
    AnnouncePayload ap{
        .session = ss.session,
        .total_len = ss.total_len,
        .block_size = ss.block_size,
        .block_count = ss.K,
    };

    std::span<const MacAddress> t(ss.targets.data(), ss.targets.size());
    std::span<const std::uint8_t> p(reinterpret_cast<const std::uint8_t*>(&ap), sizeof(ap));
    (void)_build_and_send(ss.channel, ss.ttl, message::Type::SegmentedAnnounce, t, p);
}

void Node::_segmented_send_symbol(const detail::SenderSession& ss, std::uint32_t seed) {
    message::Header h{
        .id = {.source = {}, .seq = 0},
        .type = message::Type::Raw,
        .ttl = 0,
        .channel = 0,
        .target_count = static_cast<std::uint8_t>(std::min<std::size_t>(ss.targets.size(), UINT8_MAX)),
    };
    const std::size_t maxpl = h.max_payload_size();

    const std::size_t overhead = sizeof(SymbolPayloadHeader);
    if (overhead + ss.block_size > maxpl) return;

    std::vector<std::uint8_t> buf(overhead + ss.block_size);
    SymbolPayloadHeader* sh = reinterpret_cast<SymbolPayloadHeader*>(buf.data());
    sh->session = ss.session;
    sh->seed = seed;

    std::uint32_t rng = mix_seed_with_session(seed, ss.session);

    const std::uint16_t D = choose_degree(ss.K, rng);
    std::vector<std::uint16_t> idx;
    select_unique_indices(ss.K, D, rng, idx);

    std::uint8_t* out = buf.data() + sizeof(SymbolPayloadHeader);
    std::memset(out, 0, ss.block_size);
    for (std::uint16_t b : idx) {
        const std::vector<std::uint8_t>& src = ss.blocks[b];
        for (std::size_t i = 0; i < ss.block_size; ++i) out[i] ^= src[i];
    }

    std::span<const MacAddress> t(ss.targets.data(), ss.targets.size());
    std::span<const std::uint8_t> p(buf.data(), buf.size());
    (void)_build_and_send(ss.channel, ss.ttl, message::Type::Segmented, t, p);
}

void Node::_segmented_sender_task_entry(void* pv) {
    std::unique_ptr<SenderTaskArg> arg(static_cast<SenderTaskArg*>(pv));
    arg->node->_segmented_sender_task(*arg->session);
}

void Node::_segmented_sender_task(detail::SenderSession& ss) {
    struct WorkerDone {
        detail::SegmentedSlice* seg;
        ~WorkerDone() {
            seg->active_tx_workers.fetch_sub(1, std::memory_order_relaxed);
        }
    } done{&m_segmented};

    for (int i = 0; i < 3 && !ss.stop.load(); ++i) {
        _segmented_send_announce(ss);
        _sleep_for(10ms);
    }

    const bool is_broadcast = ss.targets.empty();

    std::uint32_t seed = _random_u32();
    const std::size_t max_symbols = is_broadcast ? (ss.K * 2u) : (ss.K * 10u);

    std::size_t sent = 0;
    while (!ss.stop.load()) {
        _segmented_send_symbol(ss, seed);
        seed = xorshift32(seed);
        ++sent;

        if (!is_broadcast) {
            std::scoped_lock l(ss.ack_mutex);
            if (ss.finished.size() >= ss.targets.size()) break;
        }
        if (sent >= max_symbols) break;
        _sleep_for(100ms);
    }

    try {
        ss.promise.set_value({});
    } catch (...) {
    }

    {
        std::scoped_lock l(m_segmented.tx_mutex);
        m_segmented.tx_sessions.erase(detail::SenderSessionKey{ss.session});
    }

    ss.stop.store(true);
    vTaskDelete(nullptr);
}

std::shared_ptr<detail::SenderSession> Node::_segmented_create_sender_session(std::uint8_t channel,
                                                                               std::uint8_t ttl,
                                                                               const std::vector<MacAddress>& targets,
                                                                               std::span<const std::uint8_t> payload) {
    message::Header h{};
    h.target_count = static_cast<std::uint8_t>(std::min<std::size_t>(targets.size(), UINT8_MAX));
    const std::size_t maxpl = (sizeof(message::Header) + h.target_count * 6u <= ESP_NOW_MAX_DATA_LEN_V2)
                                  ? (ESP_NOW_MAX_DATA_LEN_V2 - (sizeof(message::Header) + h.target_count * 6u))
                                  : 0;

    const std::size_t symbol_overhead = sizeof(SymbolPayloadHeader);
    if (maxpl <= symbol_overhead + 1) {
        throw exceptions::Exception(std::runtime_error("disnet: not enough space for segmented symbol"));
    }

    std::uint16_t block_size =
        static_cast<std::uint16_t>(std::min<std::size_t>(maxpl - symbol_overhead, m_config.segmented_limits.max_block_size));
    const std::uint32_t total_len = static_cast<std::uint32_t>(payload.size());
    if (total_len > m_config.segmented_limits.max_payload_bytes) {
        throw exceptions::Exception(std::runtime_error("disnet: segmented payload exceeds configured limit"));
    }
    const std::uint16_t K = std::max<std::uint16_t>(1, static_cast<std::uint16_t>((total_len + block_size - 1) / block_size));
    if (K > m_config.segmented_limits.max_block_count) {
        throw exceptions::Exception(std::runtime_error("disnet: segmented block count exceeds configured limit"));
    }

    std::shared_ptr<detail::SenderSession> ss = std::make_shared<detail::SenderSession>();
    ss->session = sha256_of(payload);
    ss->channel = channel;
    ss->ttl = ttl;
    ss->targets = targets;
    ss->total_len = total_len;
    ss->block_size = block_size;
    ss->K = K;
    ss->blocks.resize(K);

    for (std::uint16_t i = 0; i < K; ++i) {
        ss->blocks[i].assign(block_size, 0);
        const std::size_t off = static_cast<std::size_t>(i) * block_size;
        const std::size_t remaining = payload.size() > off ? payload.size() - off : 0;
        const std::size_t n = std::min<std::size_t>(block_size, remaining);
        if (n > 0) std::memcpy(ss->blocks[i].data(), payload.data() + off, n);
    }

    return ss;
}

AckFuture Node::send_segmented(std::uint8_t channel,
                               std::uint8_t ttl,
                               const std::set<MacAddress>& targets,
                               std::span<const std::uint8_t> payload) {
    if (!is_channel_active(channel)) {
        std::promise<std::tuple<>> p;
        p.set_exception(std::make_exception_ptr(std::runtime_error("channel inactive")));
        return p.get_future();
    }

    const std::vector<MacAddress> tvec = _targets_vector(targets);
    std::shared_ptr<detail::SenderSession> ss = _segmented_create_sender_session(channel, ttl, tvec, payload);

    detail::SenderSessionKey key{
        .session = ss->session,
    };
    {
        std::scoped_lock l(m_segmented.tx_mutex);
        if (m_segmented.tx_sessions.size() >= m_config.segmented_limits.max_tx_sessions) {
#if BRICKS_DISNET_DIAGNOSTICS
            m_diag.tx_session_rejected_limit.fetch_add(1, std::memory_order_relaxed);
#endif
            std::promise<std::tuple<>> p;
            p.set_exception(std::make_exception_ptr(std::runtime_error("too many segmented tx sessions")));
            return p.get_future();
        }
        m_segmented.tx_sessions[key] = ss;
    }

    m_segmented.active_tx_workers.fetch_add(1, std::memory_order_relaxed);
    SenderTaskArg* arg = new SenderTaskArg{
        .node = this,
        .session = ss,
    };
    BaseType_t ok = xTaskCreate(_segmented_sender_task_entry, "disnet_seg_tx", 4096, arg, tskIDLE_PRIORITY + 1, &ss->task);
    if (ok != pdPASS) {
        delete arg;
        std::scoped_lock l(m_segmented.tx_mutex);
        m_segmented.tx_sessions.erase(key);
        m_segmented.active_tx_workers.fetch_sub(1, std::memory_order_relaxed);
        std::promise<std::tuple<>> p;
        p.set_exception(std::make_exception_ptr(std::runtime_error("failed to start sender task")));
        return p.get_future();
    }

    return ss->promise.get_future();
}

} // namespace bricks::disnet
