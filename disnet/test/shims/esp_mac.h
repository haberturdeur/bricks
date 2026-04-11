#pragma once

#include <cstdint>

inline constexpr int ESP_MAC_WIFI_STA = 0;

inline int esp_read_mac(std::uint8_t* out, int) {
    for (int i = 0; i < 6; ++i)
        out[i] = static_cast<std::uint8_t>(0xA0 + i);
    return 0;
}
