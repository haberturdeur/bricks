#pragma once

#include <cstddef>
#include <cstdint>

inline constexpr std::size_t ESP_NOW_MAX_DATA_LEN_V2 = 1470;

struct esp_now_recv_info_t {
    const std::uint8_t* src_addr;
};

using esp_now_recv_cb_t = void (*)(const esp_now_recv_info_t*, const std::uint8_t*, int);

inline esp_now_recv_cb_t g_esp_now_recv_cb = nullptr;
inline const std::uint8_t* g_last_send_peer = nullptr;
inline const std::uint8_t* g_last_send_data = nullptr;
inline int g_last_send_len = 0;

inline int esp_now_register_recv_cb(esp_now_recv_cb_t cb) {
    g_esp_now_recv_cb = cb;
    return 0;
}

inline int esp_now_send(const std::uint8_t* peer_addr, const std::uint8_t* data, int len) {
    g_last_send_peer = peer_addr;
    g_last_send_data = data;
    g_last_send_len = len;
    return 0;
}
