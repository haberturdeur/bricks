#pragma once

#include "bricks/disnet.hpp"
#include "bricks/disnet/core.hpp"

#include <cstdint>
#include <algorithm>
#include <span>
#include <vector>
#include <mutex>
#include <memory>
#include <cstring>

namespace bricks::disnet::segmented {

void handle_segmented_announce(const message::Header& hdr, std::span<const std::uint8_t> payload);
void handle_segmented_symbol(const message::Header& hdr, std::span<const std::uint8_t> payload);
void handle_segmented_ack(const message::Header& hdr, std::span<const std::uint8_t> payload);
void handle_segmented_nack(const message::Header& hdr, std::span<const std::uint8_t> payload);

} // namespace bricks::disnet::segmented
