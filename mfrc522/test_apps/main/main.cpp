#include <bricks/mfrc522.hpp>

#include <cstdint>
#include <optional>

struct RecordA {
    std::uint32_t raw;
};

struct RecordB {
    std::uint32_t raw;
};

struct RecordC {
    std::uint32_t raw;
};

using State = bricks::StateBuilder<bricks::eager<RecordA>, RecordB, bricks::vector<RecordC>>;

extern "C" void app_main(void) {
    constexpr std::size_t fixed_count = State::fixed_record_count;
    constexpr std::size_t pages = State::page_count;

    (void)fixed_count;
    (void)pages;

    std::optional<RecordA> maybe_a = std::nullopt;
    (void)maybe_a;
}
