#include <bricks/chronicler.hpp>

#include <esp_log.h>
#include <esp_partition.h>
#include <esp_timer.h>

#include <array>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <span>

using namespace bricks::chronicler;

namespace {
constexpr char TAG[] = "chronicler_example";
constexpr char partition_label[] = "storage";

struct [[gnu::packed]] LogEntry {
    std::uint32_t sequence;
    std::int32_t temperature_c;  // milli-degrees Celsius
    std::uint64_t timestamp_us;
    char note[12];
};

constexpr std::size_t entry_size = sizeof(LogEntry);
static_assert(entry_size <= 64, "example entry should stay compact");

PartitionHandle find_data_partition() {
    const esp_partition_t* part = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA,
        ESP_PARTITION_SUBTYPE_ANY,
        partition_label);

    if (!part) {
        part = esp_partition_find_first(
            ESP_PARTITION_TYPE_DATA,
            ESP_PARTITION_SUBTYPE_ANY,
            nullptr);
    }

    if (!part) {
        ESP_LOGE(TAG, "no writable data partition found");
        std::abort();
    }

    ESP_LOGI(TAG,
             "using partition '%s' @0x%08" PRIx32 " (%" PRIu32 " bytes)",
             part->label,
             part->address,
             part->size);
    return PartitionHandle(part);
}

void sync_callback(Chronicler&, std::span<std::uint8_t> entry, void*) {
    LogEntry decoded{};
    std::memcpy(&decoded, entry.data(), sizeof(decoded));
    ESP_LOGI(TAG,
             "sync requested for seq=%" PRIu32 ", temp=%" PRId32 "C, note=%.*s",
             decoded.sequence,
             decoded.temperature_c,
             static_cast<int>(sizeof(decoded.note)),
             decoded.note);
}

} // namespace

extern "C" void app_main(void) {
    PartitionHandle partition = find_data_partition();

    auto loaded = Chronicler::load(partition, entry_size);
    Chronicler chronicler = loaded
                          ? std::move(*loaded)
                          : Chronicler::create(partition, entry_size);

    chronicler.set_sync_callback(sync_callback, nullptr);

    const std::uint32_t base_seq = static_cast<std::uint32_t>(chronicler.size());
    const std::uint64_t now = static_cast<std::uint64_t>(esp_timer_get_time());

    const LogEntry first{
        .sequence = base_seq + 1,
        .temperature_c = 2150,
        .timestamp_us = now,
        .note = "boot",
    };
    const LogEntry second{
        .sequence = base_seq + 2,
        .temperature_c = 2230,
        .timestamp_us = now + 60'000,
        .note = "fan on",
    };

    auto to_u8_span = [](auto& buf) {
        return std::span<std::uint8_t>(
            reinterpret_cast<std::uint8_t*>(buf.data()),
            buf.size());
    };

    LogEntry first_mut = first;
    LogEntry second_mut = second;
    std::array<std::byte, entry_size> first_bytes{};
    std::array<std::byte, entry_size> second_bytes{};
    std::memcpy(first_bytes.data(), &first_mut, entry_size);
    std::memcpy(second_bytes.data(), &second_mut, entry_size);

    chronicler.push(to_u8_span(first_bytes), true);
    chronicler.push(to_u8_span(second_bytes), false);

    ESP_LOGI(TAG, "log now holds %zu entries", chronicler.size());

    std::array<std::byte, entry_size> read_buf{};
    for (std::size_t i = 0; i < chronicler.size(); ++i) {
        LogEntry entry{};
        chronicler.read(i, to_u8_span(read_buf));
        std::memcpy(&entry, read_buf.data(), entry_size);
        ESP_LOGI(TAG,
                 "entry[%zu]: seq=%" PRIu32 " temp=%" PRId32 "C ts=%" PRIu64 " note=%.*s",
                 i,
                 entry.sequence,
                 entry.temperature_c,
                 entry.timestamp_us,
                 static_cast<int>(sizeof(entry.note)),
                 entry.note);
        ESP_LOGI(TAG, "  synced=%s", chronicler.is_synced(i) ? "yes" : "no");
    }

    if (auto unsynced = chronicler.get_unsynced()) {
        chronicler.mark_synced(*unsynced);
        ESP_LOGI(TAG, "marked entry %zu synced", *unsynced);
    }

    if (chronicler.sweep_synced_sector())
        ESP_LOGI(TAG, "marked a fully synced sector");

    auto reopened = Chronicler::load_or_create(partition, entry_size);
    ESP_LOGI(TAG, "load_or_create sees %zu entries", reopened.size());

    ESP_LOGI(TAG, "example complete");
}
