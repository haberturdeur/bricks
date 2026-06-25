#pragma once

#include "bricks/disnet/transport.hpp"
#include "bricks/disnet/mac_address.hpp"

#include <cstring>
#include <mutex>

#include "esp_log.h"
#include "esp_mac.h"
#include "esp_now.h"

namespace bricks::disnet::esp_now {

class EspNow {
public:
    using Address = bricks::disnet::MacAddress;
    static constexpr std::size_t max_payload_size = ESP_NOW_MAX_DATA_LEN_V2 - (2 * 6) - sizeof(std::uint32_t);

    static EspNow& singleton() {
        static EspNow s_instance;
        return s_instance;
    }

    EspNow(const EspNow&) = delete;
    EspNow& operator=(const EspNow&) = delete;

    EspNow(EspNow&&) = delete;
    EspNow& operator=(EspNow&&) = delete;

    Address my_address() const {
        Address address{};
        esp_read_mac(address.data(), ESP_MAC_WIFI_STA);
        return address;
    }

    static Address broadcast_address() {
        Address address{};
        std::memcpy(address.data(), s_broadcast_address, s_address_size);
        return address;
    }

    void send(TransportPacket<Address> packet) {
        std::vector<std::uint8_t> frame(_encoded_packet_size(packet.payload.size()));
        _encode_address(frame.data(), packet.source);
        _encode_address(frame.data() + s_address_size, packet.target);
        std::memcpy(frame.data() + 2 * s_address_size, &packet.source_seq, sizeof(packet.source_seq));
        if (!packet.payload.empty()) {
            std::memcpy(frame.data() + s_header_size, packet.payload.data(), packet.payload.size());
        }

        const int err = esp_now_send(packet.target.data(), frame.data(), static_cast<int>(frame.size()));
        if (err != 0) {
            ESP_LOGW("EspNow", "esp_now_send failed: %d", err);
        }
    }

    void register_callback(TransportReceiveCallback<Address> callback) {
        std::lock_guard lock(m_mutex);
        m_callback = std::move(callback);
    }

    // Called by the ESP-NOW receive trampoline; may also be invoked directly in tests.
    void handle_receive(const esp_now_recv_info_t* info, const std::uint8_t* data, int len) {
        TransportReceiveCallback<Address> cb;
        {
            std::lock_guard lock(m_mutex);
            cb = m_callback;
        }

        if (!cb || data == nullptr || len < static_cast<int>(s_header_size))
            return;

        TransportPacket<Address> packet{
            .source = (info != nullptr && info->src_addr != nullptr) ? _decode_address(info->src_addr)
                                                                      : _decode_address(data),
            .target = _decode_address(data + s_address_size),
            .source_seq = 0,
            .payload = {},
        };
        std::memcpy(&packet.source_seq, data + 2 * s_address_size, sizeof(packet.source_seq));
        packet.payload.assign(data + s_header_size, data + len);

        cb(std::move(packet));
    }

private:
    static constexpr std::uint8_t s_broadcast_address[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    EspNow() {
        esp_now_register_recv_cb(&EspNow::_receive_trampoline);
    }

    ~EspNow() = default;

    static constexpr std::size_t s_address_size = 6;
    static constexpr std::size_t s_header_size = 2 * s_address_size + sizeof(std::uint32_t);

    TransportReceiveCallback<Address> m_callback;
    mutable std::mutex m_mutex;

    static constexpr std::size_t _encoded_packet_size(std::size_t payload_size) {
        return s_header_size + payload_size;
    }

    static void _encode_address(std::uint8_t* out, const Address& address) {
        std::memcpy(out, address.data(), s_address_size);
    }

    static Address _decode_address(const std::uint8_t* data) {
        Address address{};
        std::memcpy(address.data(), data, s_address_size);
        return address;
    }

    static void _receive_trampoline(const esp_now_recv_info_t* info, const std::uint8_t* data, int len) {
        singleton().handle_receive(info, data, len);
    }
};

static_assert(Transport<EspNow>);

} // namespace bricks::disnet::esp_now
