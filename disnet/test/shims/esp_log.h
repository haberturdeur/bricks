#pragma once
#include <cstdio>

// NOLINTBEGIN
#define ESP_LOGW(tag, fmt, ...) ((void)(tag), fprintf(stderr, "WARN: " fmt "\n", ##__VA_ARGS__))
// NOLINTEND
