#pragma once

#include <cstdint>

namespace MFRC522Constants {

enum StatusCode : std::uint8_t {
    STATUS_OK = 0,
};

enum PCD_Register : std::uint8_t {
    VersionReg = 0x37,
};

struct Uid {
    std::uint8_t uidByte[10]{};
};

} // namespace MFRC522Constants
