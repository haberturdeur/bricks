#include "bricks/disnet.hpp"

#include "esp_log.h"

#include <chrono>
#include <future>
#include <stdexcept>

using namespace std::chrono_literals;

static const char* g_tag = "bricks/disnet";

namespace bricks::disnet {

static constexpr std::chrono::seconds ACK_TIMEOUT = std::chrono::seconds(5);

void Node::_reliable_cleanup_expired_acks(TimePoint now) {
    std::map<message::Id, detail::AckCookie>::iterator it = m_acks.promises.begin();
    while (it != m_acks.promises.end()) {
        if (now - it->second.timeout > ACK_TIMEOUT) {
            try {
                it->second.promise.set_exception(std::make_exception_ptr(std::runtime_error("ack timeout")));
            } catch (...) {
            }
            it = m_acks.promises.erase(it);
            continue;
        }
        ++it;
    }
}

void Node::_reliable_sweep_timeouts() {
    std::scoped_lock l(m_acks.mutex);
    _reliable_cleanup_expired_acks(_now());
}

void Node::_reliable_handle_ack(std::span<const std::uint8_t> payload_span) {
    if (payload_span.size() < sizeof(message::Id)) return;
    const message::Id* acked = reinterpret_cast<const message::Id*>(payload_span.data());

    std::scoped_lock l(m_acks.mutex);
    _reliable_cleanup_expired_acks(_now());
    std::map<message::Id, detail::AckCookie>::iterator it = m_acks.promises.find(*acked);
    if (it != m_acks.promises.end()) {
        try {
            it->second.promise.set_value({});
        } catch (...) {
        }
        m_acks.promises.erase(it);
    }
}

void Node::_reliable_send_ack(const message::Header& hdr) {
    const std::uint8_t* id_bytes = reinterpret_cast<const std::uint8_t*>(&hdr.id);
    std::span<const std::uint8_t> ack_payload(id_bytes, sizeof(message::Id));

    MacAddress target = hdr.id.source;
    std::span<const MacAddress> targets(&target, 1);

    (void)_build_and_send(hdr.channel, m_runtime.initial_ttl, message::Type::ReliableAck, targets, ack_payload);
}

AckFuture Node::send_reliable(std::uint8_t channel,
                              std::uint8_t ttl,
                              const std::set<MacAddress>& targets,
                              std::span<const std::uint8_t> payload) {
    if (!is_channel_active(channel)) {
        ESP_LOGW(g_tag, "send_reliable: Channel not active: %x", channel);
        std::promise<std::tuple<>> promise;
        promise.set_exception(std::make_exception_ptr(std::runtime_error("channel inactive")));
        return promise.get_future();
    }

    const std::vector<MacAddress> tvec = _targets_vector(targets);
    const message::Id id = _build_and_send(channel, ttl, message::Type::Reliable, tvec, payload);

    std::scoped_lock l(m_acks.mutex);
    _reliable_cleanup_expired_acks(_now());
    std::pair<std::map<message::Id, detail::AckCookie>::iterator, bool> insert_res =
        m_acks.promises.emplace(id, detail::AckCookie{_now(), {}});
    (void)insert_res.second;

    return insert_res.first->second.promise.get_future();
}

} // namespace bricks::disnet
