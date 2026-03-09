#pragma once

#include <cstdint>

using esp_err_t = int;

static constexpr esp_err_t ESP_OK = 0;
static constexpr esp_err_t ESP_FAIL = -1;
static constexpr esp_err_t ESP_ERR_ESPNOW_NO_MEM = 0x3069;

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

extern "C" const char* esp_err_to_name(esp_err_t err);
