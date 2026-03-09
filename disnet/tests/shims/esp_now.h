#pragma once

#include "esp_err.h"
#include "esp_wifi.h"

#include <cstdint>

static constexpr int ESP_NOW_MAX_DATA_LEN_V2 = 1470;

typedef struct esp_now_recv_info {
    std::uint8_t src_addr[6];
} esp_now_recv_info_t;

typedef struct esp_now_peer_info {
    std::uint8_t peer_addr[6];
    std::uint8_t lmk[16];
    std::uint8_t channel;
    wifi_interface_t ifidx;
    bool encrypt;
    void* priv;
} esp_now_peer_info_t;

extern "C" esp_err_t esp_now_init(void);
extern "C" esp_err_t esp_now_deinit(void);
extern "C" esp_err_t esp_now_add_peer(const esp_now_peer_info_t* peer);
extern "C" esp_err_t esp_now_send(const std::uint8_t* peer_addr, const std::uint8_t* data, int len);
