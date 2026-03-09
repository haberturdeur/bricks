#pragma once

#include <cstdio>

#define LOG_ANSI_COLOR(x) ""
#define LOG_ANSI_COLOR_RED ""
#define LOG_ANSI_COLOR_RESET ""

#define ESP_LOGI(tag, fmt, ...) do { (void)(tag); std::fprintf(stderr, "[I] " fmt "\n", ##__VA_ARGS__); } while (0)
#define ESP_LOGW(tag, fmt, ...) do { (void)(tag); std::fprintf(stderr, "[W] " fmt "\n", ##__VA_ARGS__); } while (0)
#define ESP_LOGE(tag, fmt, ...) do { (void)(tag); std::fprintf(stderr, "[E] " fmt "\n", ##__VA_ARGS__); } while (0)
