#include <bricks/mfrc522.hpp>

#include <MFRC522Constants.h>

#include <driver/gpio.h>
#include <esp_rom_sys.h>

#include <algorithm>
#include <cstdio>

namespace bricks::mfrc522 {

SoftwareSPI::SoftwareSPI(SpiPinout pinout) : pinout_(pinout) {}

void SoftwareSPI::begin() {
    const gpio_config_t config = {
        .pin_bit_mask = (1ULL << pinout_.mosi) | (1ULL << pinout_.sck) | (1ULL << pinout_.ss),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };

    gpio_reset_pin(pinout_.mosi);
    gpio_reset_pin(pinout_.sck);
    gpio_reset_pin(pinout_.ss);
    gpio_config(&config);

    gpio_reset_pin(pinout_.miso);
    gpio_set_direction(pinout_.miso, GPIO_MODE_INPUT);

    gpio_set_level(pinout_.ss, 1);
    gpio_set_level(pinout_.sck, 0);
}

std::uint8_t SoftwareSPI::transfer(std::uint8_t data) {
    std::uint8_t result = 0;
    for (int i = 0; i < 8; ++i) {
        gpio_set_level(pinout_.sck, 0);
        gpio_set_level(pinout_.mosi, (data & (1 << (7 - i))) ? 1 : 0);
        esp_rom_delay_us(1);
        gpio_set_level(pinout_.sck, 1);
        result |= (gpio_get_level(pinout_.miso) == 1) << (7 - i);
        esp_rom_delay_us(1);
    }
    return result;
}

void SoftwareSPI::select() {
    gpio_set_level(pinout_.sck, 0);
    gpio_set_level(pinout_.ss, 0);
}

void SoftwareSPI::deselect() {
    gpio_set_level(pinout_.ss, 1);
    gpio_set_level(pinout_.sck, 0);
}

DriverSPISoftware::DriverSPISoftware(SpiPinout pinout) : spi_(pinout) {}

bool DriverSPISoftware::init() {
    spi_.begin();
    return true;
}

void DriverSPISoftware::PCD_WriteRegister(PCD_Register reg, std::uint8_t value) {
    spi_.select();
    spi_.transfer(reg << 1);
    spi_.transfer(value);
    spi_.deselect();
}

void DriverSPISoftware::PCD_WriteRegister(PCD_Register reg, std::uint8_t count, std::uint8_t* values) {
    spi_.select();
    spi_.transfer(reg << 1);
    for (std::uint8_t i = 0; i < count; ++i) {
        spi_.transfer(values[i]);
    }
    spi_.deselect();
}

std::uint8_t DriverSPISoftware::PCD_ReadRegister(PCD_Register reg) {
    spi_.select();
    spi_.transfer(std::uint8_t(0x80) | (reg << 1));
    const std::uint8_t value = spi_.transfer(0);
    spi_.deselect();
    return value;
}

void DriverSPISoftware::PCD_ReadRegister(PCD_Register reg, std::uint8_t count, std::uint8_t* values, std::uint8_t rxAlign) {
    if (count == 0) {
        return;
    }

    const std::uint8_t address = std::uint8_t(0x80) | (reg << 1);
    std::uint8_t index = 0;

    spi_.select();
    spi_.transfer(address);

    if (rxAlign > 0) {
        const std::uint8_t mask = std::uint8_t(0xFF << rxAlign) & 0xFF;
        const std::uint8_t value = spi_.transfer(address);
        values[0] = (values[0] & ~mask) | (value & mask);
        ++index;
    }

    while (index < count - 1) {
        values[index++] = spi_.transfer(address);
    }

    values[index] = spi_.transfer(0);
    spi_.deselect();
}

Session::Session(MFRC522& pcd) : pcd_(&pcd) {}

Session::~Session() {
    abort();
}

bool Session::read_page(std::size_t page, std::array<std::uint8_t, 4>& out) {
    std::uint8_t buffer[18]{};
    std::uint8_t size = sizeof(buffer);

    if (pcd_->MIFARE_Read(static_cast<std::uint8_t>(page), buffer, &size) != MFRC522Constants::STATUS_OK) {
        return false;
    }

    out = {buffer[0], buffer[1], buffer[2], buffer[3]};
    return true;
}

bool Session::write_page(std::size_t page, const std::array<std::uint8_t, 4>& in) {
    std::uint8_t data[4] = {in[0], in[1], in[2], in[3]};
    if (pcd_->MIFARE_Ultralight_Write(static_cast<std::uint8_t>(page), data, 4) != MFRC522Constants::STATUS_OK) {
        return false;
    }

    std::array<std::uint8_t, 4> verify{};
    if (!read_page(page, verify)) {
        return false;
    }

    return verify == in;
}

bool Session::read_word(std::size_t page, std::uint32_t& out) {
    std::array<std::uint8_t, 4> bytes{};
    if (!read_page(page, bytes)) {
        return false;
    }

    out = static_cast<std::uint32_t>(bytes[0]) |
          (static_cast<std::uint32_t>(bytes[1]) << 8) |
          (static_cast<std::uint32_t>(bytes[2]) << 16) |
          (static_cast<std::uint32_t>(bytes[3]) << 24);
    return true;
}

bool Session::write_word(std::size_t page, std::uint32_t value) {
    std::array<std::uint8_t, 4> bytes{
        static_cast<std::uint8_t>(value & 0xFF),
        static_cast<std::uint8_t>((value >> 8) & 0xFF),
        static_cast<std::uint8_t>((value >> 16) & 0xFF),
        static_cast<std::uint8_t>((value >> 24) & 0xFF),
    };
    return write_page(page, bytes);
}

void Session::abort() {
    if (pcd_ != nullptr) {
        pcd_->PICC_HaltA();
    }
}

Reader::Reader(SpiPinout pinout, std::size_t card_page_count)
    : driver_(pinout), pcd_(driver_), card_page_count_(card_page_count) {}

void Reader::init() {
    pcd_.PCD_Reset();
    pcd_.PCD_Init();
    pcd_.PCD_AntennaOn();
}

bool Reader::is_alive() {
    const std::uint8_t version = driver_.PCD_ReadRegister(MFRC522Constants::PCD_Register::VersionReg);
    return version != 0x00 && version != 0xFF;
}

bool Reader::new_card_present() {
    using namespace std::chrono_literals;

    if (!pcd_.PICC_IsNewCardPresent()) {
        return false;
    }

    if (!pcd_.PICC_ReadCardSerial()) {
        return false;
    }

    constexpr std::size_t uid_compare_size = 7;
    const bool same_uid = std::equal(
        pcd_.uid.uidByte,
        pcd_.uid.uidByte + uid_compare_size,
        last_uid_.uidByte
    );

    if (same_uid && (Clock::now() - last_seen_time_ < 500ms)) {
        return false;
    }

    last_uid_ = pcd_.uid;
    last_seen_time_ = Clock::now();
    return true;
}

std::string Reader::uid_hex() const {
    char buffer[15] = {0};
    std::snprintf(
        buffer,
        sizeof(buffer),
        "%02X%02X%02X%02X%02X%02X%02X",
        pcd_.uid.uidByte[0],
        pcd_.uid.uidByte[1],
        pcd_.uid.uidByte[2],
        pcd_.uid.uidByte[3],
        pcd_.uid.uidByte[4],
        pcd_.uid.uidByte[5],
        pcd_.uid.uidByte[6]
    );

    return {buffer};
}

}  // namespace bricks::mfrc522
