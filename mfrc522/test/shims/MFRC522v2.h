#pragma once

#include "MFRC522Driver.h"
#include "MFRC522Constants.h"

class MFRC522 {
public:
    explicit MFRC522(MFRC522Driver&) {}

    void PCD_Reset() {}
    void PCD_Init() {}
    void PCD_AntennaOn() {}
    bool PICC_IsNewCardPresent() { return false; }
    bool PICC_ReadCardSerial() { return false; }
    void PICC_HaltA() {}

    std::uint8_t MIFARE_Read(std::uint8_t, std::uint8_t* buffer, std::uint8_t* size) {
        if (size != nullptr && *size >= 4) {
            buffer[0] = buffer[1] = buffer[2] = buffer[3] = 0;
        }
        return MFRC522Constants::STATUS_OK;
    }

    std::uint8_t MIFARE_Ultralight_Write(std::uint8_t, std::uint8_t*, std::uint8_t) {
        return MFRC522Constants::STATUS_OK;
    }

    MFRC522Constants::Uid uid{};
};
