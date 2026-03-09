#pragma once

#include <cstdint>

#define ESP_MAC_WIFI_STA 0

extern "C" void esp_read_mac(std::uint8_t* mac, int type);
