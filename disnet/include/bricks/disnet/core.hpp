#pragma once

#include "bricks/disnet.hpp"

#include "bricks/exceptions.hpp"

#include <esp_random.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include <esp_netif.h>
#include <esp_mac.h>

#include <span>
#include <vector>
#include <cstdint>

namespace bricks::disnet::core {

message::Id build_and_send(std::uint8_t channel,
                           std::uint8_t ttl,
                           message::Type type,
                           std::span<const MacAddress> targets,
                           std::span<const std::uint8_t> payload);

void dispatch(const MacAddress& source, std::uint8_t channel, std::span<const std::uint8_t> payload);

} // namespace bricks::disnet::core
