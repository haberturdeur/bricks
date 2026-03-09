#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace fake_platform {

struct TxFrame {
    std::array<std::uint8_t, 6> peer{};
    std::vector<std::uint8_t> payload;
};

void reset();
std::vector<TxFrame> take_tx_frames();

} // namespace fake_platform
