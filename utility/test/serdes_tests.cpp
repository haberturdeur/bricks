#include "bricks/utility/serdes.hpp"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <optional>
#include <span>
#include <vector>

namespace member_model {

struct Packet {
    std::uint8_t value = 0;

    std::vector<std::uint8_t> serialize() const {
        return {value};
    }

    static std::optional<Packet> deserialize(std::span<const std::uint8_t> bytes) {
        if (bytes.size() != 1)
            return std::nullopt;
        return Packet{.value = bytes[0]};
    }
};

} // namespace member_model

namespace adl_model {

struct Packet {
    std::uint16_t value = 0;
};

std::vector<std::uint8_t> serialize(const Packet& packet) {
    std::vector<std::uint8_t> out(sizeof(packet.value));
    std::memcpy(out.data(), &packet.value, sizeof(packet.value));
    return out;
}

std::optional<Packet> deserialize(std::type_identity<Packet>, std::span<const std::uint8_t> bytes) {
    if (bytes.size() != sizeof(std::uint16_t))
        return std::nullopt;
    Packet packet;
    std::memcpy(&packet.value, bytes.data(), sizeof(packet.value));
    return packet;
}

} // namespace adl_model

struct NotSerializable {
    std::uint8_t value = 0;
};

static_assert(bricks::utility::Serializable<member_model::Packet>);
static_assert(bricks::utility::Serializable<adl_model::Packet>);
static_assert(!bricks::utility::Serializable<NotSerializable>);

int main() {
    {
        auto bytes = bricks::utility::serialize(member_model::Packet{.value = 42});
        auto packet = bricks::utility::deserialize<member_model::Packet>(bytes);
        assert(packet.has_value());
        assert(packet->value == 42);
    }

    {
        auto bytes = bricks::utility::serialize(adl_model::Packet{.value = 1234});
        auto packet = bricks::utility::deserialize<adl_model::Packet>(bytes);
        assert(packet.has_value());
        assert(packet->value == 1234);
    }

    std::cout << "All serdes tests passed.\n";
    return 0;
}
