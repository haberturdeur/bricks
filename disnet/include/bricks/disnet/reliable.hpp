#pragma once

#include <span>
#include <cstdint>

namespace bricks::disnet::reliable {

void handle_ack(std::span<const std::uint8_t> payload_span);
 
} // namespace bricks::disnet::reliable
