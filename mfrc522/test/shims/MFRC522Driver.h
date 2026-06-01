#pragma once

#include <cstdint>

class MFRC522Driver {
public:
    using PCD_Register = std::uint8_t;
    virtual ~MFRC522Driver() = default;
    virtual bool init() = 0;
    virtual void PCD_WriteRegister(PCD_Register reg, std::uint8_t value) = 0;
    virtual void PCD_WriteRegister(PCD_Register reg, std::uint8_t count, std::uint8_t* values) = 0;
    virtual std::uint8_t PCD_ReadRegister(PCD_Register reg) = 0;
    virtual void PCD_ReadRegister(PCD_Register reg, std::uint8_t count, std::uint8_t* values, std::uint8_t rxAlign) = 0;
};
