#pragma once

#include <cstdint>

using BaseType_t = int;
using UBaseType_t = unsigned;
using TickType_t = std::uint32_t;

static constexpr BaseType_t pdPASS = 1;
static constexpr BaseType_t pdFAIL = 0;
static constexpr UBaseType_t tskIDLE_PRIORITY = 0;

#define pdMS_TO_TICKS(ms) static_cast<TickType_t>(ms)
