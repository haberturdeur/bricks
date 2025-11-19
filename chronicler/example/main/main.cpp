#include <bricks/chronicler.hpp>
#include <bricks/chronicler/geometry.hpp>
#include <bricks/chronicler/data_sector.hpp>
#include <bricks/chronicler/metadata.hpp>

#include <esp_partition.h>
#include <unity.h>

#include <algorithm>
#include <cstdint>
#include <span>
#include <vector>

using namespace bricks::chronicler;

namespace {

constexpr char kPartitionLabel[] = "storage";
constexpr std::size_t kEntrySize = 32;

struct SyncCallbackContext {
    std::size_t invocations{};
    std::vector<std::uint8_t> last_entry;
};

void sync_test_callback(Chronicler& chronicler, std::span<std::uint8_t> entry, void* ctx) {
    (void)chronicler;
    auto* info = static_cast<SyncCallbackContext*>(ctx);
    info->invocations++;
    info->last_entry.assign(entry.begin(), entry.end());
}

const esp_partition_t* find_partition() {
    const esp_partition_t* part = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA,
        ESP_PARTITION_SUBTYPE_ANY,
        kPartitionLabel);
    if (!part)
        part = esp_partition_find_first(
            ESP_PARTITION_TYPE_DATA,
            ESP_PARTITION_SUBTYPE_ANY,
            nullptr);
    TEST_ASSERT_NOT_NULL(part);
    return part;
}

PartitionHandle make_partition_handle() {
    return PartitionHandle(find_partition());
}

void wipe_partition(PartitionHandle partition) {
    partition.erase_range(0, partition.size());
}

void fill_entry(std::vector<std::uint8_t>& buf, std::uint32_t seed) {
    for (std::size_t i = 0; i < buf.size(); ++i) {
        const auto val = static_cast<std::uint8_t>((seed + i * 17U) & 0xFFU);
        buf[i] = val;
    }
}

std::size_t theoretical_capacity(std::size_t sector_bytes, std::size_t entry_bytes) {
    const std::size_t numerator = 8U * sector_bytes;
    const std::size_t denominator = 8U * entry_bytes + 4U;
    return denominator == 0 ? 0 : numerator / denominator;
}

} // namespace

TEST_CASE("geometry matches README formulas", "[geometry]") {
    constexpr std::size_t kSectorBytes = 4096;
    constexpr std::size_t kSectorCount = 64;

    esp_partition_t fake_partition{};
    fake_partition.address = 0;
    fake_partition.size = kSectorBytes * kSectorCount;
    fake_partition.erase_size = kSectorBytes;

    PartitionHandle handle(&fake_partition);

    detail::Geometry geom(kEntrySize, handle);

    const std::size_t expected_capacity = theoretical_capacity(kSectorBytes, kEntrySize);
    TEST_ASSERT_EQUAL_UINT32(expected_capacity, geom.sector_capacity);
    const std::size_t expected_meta_bytes = ((expected_capacity + 1) / 2 + 3) & ~std::size_t(3);
    TEST_ASSERT_EQUAL_UINT32(expected_meta_bytes, geom.data_offset);

    const std::size_t available_words = (kSectorBytes - detail::layout::g_bitmap) / 4U;
    const std::size_t metadata_limit = available_words * 16U;
    const std::size_t partition_limit = kSectorCount - geom.metadata_sector_count;
    const std::size_t rounded_partition_limit = (partition_limit / 16U) * 16U;
    const std::size_t expected_data_sectors = std::min(metadata_limit, rounded_partition_limit);

    TEST_ASSERT_EQUAL_UINT32(expected_data_sectors, geom.data_sector_count);
}

TEST_CASE("metadata advances head and rotates slots", "[metadata]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(kEntrySize, partition);
    TEST_ASSERT_GREATER_THAN_UINT32(0, geom.data_sector_count);

    detail::Metadata metadata = detail::Metadata::create(geom, partition);
    TEST_ASSERT_EQUAL_UINT32(0, metadata.head());

    for (std::size_t i = 1; i < geom.data_sector_count; ++i) {
        metadata.advance_head();
        TEST_ASSERT_EQUAL_UINT32(i, metadata.head());
    }

    metadata.advance_head();
    TEST_ASSERT_EQUAL_UINT32(0, metadata.head());

    auto reloaded = detail::Metadata::load(geom, partition);
    TEST_ASSERT_TRUE(reloaded.has_value());
    TEST_ASSERT_EQUAL_UINT32(0, reloaded->head());

    SectorHandle slot0(partition, 0);
    SectorHandle slot1(partition, 1);
    TEST_ASSERT_EQUAL_UINT32(0U, slot0.read(detail::layout::g_old));
    TEST_ASSERT(slot1.read(detail::layout::g_old) != 0U);
}

TEST_CASE("data sectors persist appended entries", "[data_sector]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(kEntrySize, partition);
    TEST_ASSERT_GREATER_THAN_UINT32(0, geom.sector_capacity);

    auto sector = detail::DataSector::create(geom, partition, 0);

    std::vector<std::uint8_t> payload(kEntrySize);
    for (std::size_t i = 0; i < sector.capacity(); ++i) {
        fill_entry(payload, static_cast<std::uint32_t>(i));
        sector.push(std::span<std::uint8_t>(payload.data(), payload.size()), (i % 2) == 0);
    }
    TEST_ASSERT_EQUAL_UINT32(sector.capacity(), sector.size());

    auto reloaded = detail::DataSector::load(geom, partition, 0);
    TEST_ASSERT_EQUAL_UINT32(sector.size(), reloaded.size());

    std::vector<std::uint8_t> read_buf(kEntrySize);
    std::vector<std::uint8_t> expected(kEntrySize);
    for (std::size_t i = 0; i < reloaded.size(); ++i) {
        reloaded.read(i, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
        fill_entry(expected, static_cast<std::uint32_t>(i));
        TEST_ASSERT_EQUAL_UINT8_ARRAY(expected.data(), read_buf.data(), read_buf.size());
    }
}

TEST_CASE("chronicler push/read round trip on active sector", "[chronicler]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(kEntrySize, partition);
    TEST_ASSERT_GREATER_THAN_UINT32(0, geom.sector_capacity);

    auto chron = Chronicler::create(partition, kEntrySize);

    const std::size_t push_count = std::min<std::size_t>(geom.sector_capacity, 8);

    std::vector<std::uint8_t> payload(kEntrySize);
    std::vector<std::uint8_t> read_buf(kEntrySize);

    for (std::size_t i = 0; i < push_count; ++i) {
        fill_entry(payload, static_cast<std::uint32_t>(i));
        chron.push(std::span<std::uint8_t>(payload.data(), payload.size()), false);
    }

    for (std::size_t i = 0; i < push_count; ++i) {
        chron.read(i, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
        fill_entry(payload, static_cast<std::uint32_t>(i));
        TEST_ASSERT_EQUAL_UINT8_ARRAY(payload.data(), read_buf.data(), payload.size());
    }
}

TEST_CASE("load fails on blank partition", "[chronicler][load]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    auto loaded = Chronicler::load(partition, kEntrySize);
    TEST_ASSERT_FALSE(loaded.has_value());
}

TEST_CASE("entries survive power cycle and reload", "[chronicler][load]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    constexpr std::size_t entry_count = 10;
    std::vector<std::uint8_t> payload(kEntrySize);
    std::vector<std::uint8_t> read_buf(kEntrySize);

    {
        auto chron = Chronicler::create(partition, kEntrySize);
        for (std::size_t i = 0; i < entry_count; ++i) {
            fill_entry(payload, static_cast<std::uint32_t>(i));
            chron.push(std::span<std::uint8_t>(payload.data(), payload.size()), (i % 2) == 0);
        }
    }

    auto loaded = Chronicler::load(partition, kEntrySize);
    TEST_ASSERT_TRUE(loaded.has_value());
    auto chron = std::move(*loaded);
    TEST_ASSERT_EQUAL_UINT32(entry_count, chron.size());

    for (std::size_t i = 0; i < entry_count; ++i) {
        chron.read(i, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
        fill_entry(payload, static_cast<std::uint32_t>(i));
        TEST_ASSERT_EQUAL_UINT8_ARRAY(payload.data(), read_buf.data(), payload.size());
    }

    fill_entry(payload, static_cast<std::uint32_t>(entry_count));
    chron.push(std::span<std::uint8_t>(payload.data(), payload.size()), true);
    chron.read(entry_count, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(payload.data(), read_buf.data(), payload.size());
}

TEST_CASE("sync callback fires for should_sync entries", "[chronicler][callback]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    auto chron = Chronicler::create(partition, kEntrySize);

    SyncCallbackContext ctx;
    ctx.last_entry.resize(kEntrySize);
    chron.set_sync_callback(sync_test_callback, &ctx);

    std::vector<std::uint8_t> payload(kEntrySize);

    fill_entry(payload, 0);
    chron.push(std::span<std::uint8_t>(payload.data(), payload.size()), false);
    TEST_ASSERT_EQUAL_UINT32(0, ctx.invocations);

    fill_entry(payload, 1);
    chron.push(std::span<std::uint8_t>(payload.data(), payload.size()), true);
    TEST_ASSERT_EQUAL_UINT32(1, ctx.invocations);
    std::vector<std::uint8_t> expected(kEntrySize);
    fill_entry(expected, 1);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected.data(), ctx.last_entry.data(), expected.size());

    fill_entry(payload, 2);
    chron.push(std::span<std::uint8_t>(payload.data(), payload.size()), true);
    TEST_ASSERT_EQUAL_UINT32(2, ctx.invocations);
    fill_entry(expected, 2);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected.data(), ctx.last_entry.data(), expected.size());
}

TEST_CASE("sync bookkeeping APIs reflect entry state", "[chronicler][sync]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    auto chron = Chronicler::create(partition, kEntrySize);

    std::vector<std::uint8_t> payload(kEntrySize);

    fill_entry(payload, 0);
    chron.push(std::span<std::uint8_t>(payload.data(), payload.size()), false);

    fill_entry(payload, 1);
    chron.push(std::span<std::uint8_t>(payload.data(), payload.size()), true);

    fill_entry(payload, 2);
    chron.push(std::span<std::uint8_t>(payload.data(), payload.size()), true);

    TEST_ASSERT_TRUE(chron.is_synced(0));      // entries without should_sync are considered synced
    TEST_ASSERT_FALSE(chron.is_synced(1));

    auto unsynced = chron.get_unsynced();
    TEST_ASSERT_TRUE(unsynced.has_value());
    TEST_ASSERT_EQUAL_UINT32(1, *unsynced);

    chron.mark_synced(1);
    TEST_ASSERT_TRUE(chron.is_synced(1));

    unsynced = chron.get_unsynced();
    TEST_ASSERT_TRUE(unsynced.has_value());
    TEST_ASSERT_EQUAL_UINT32(2, *unsynced);

    chron.mark_synced(2);
    TEST_ASSERT_FALSE(chron.get_unsynced().has_value());
}

TEST_CASE("sweep marks fully synced sectors lazily", "[chronicler][sync][gc]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    constexpr std::size_t large_entry = 512;
    auto chron = Chronicler::create(partition, large_entry);

    const std::size_t sector_capacity = theoretical_capacity(partition.sector_size(), large_entry);

    std::vector<std::uint8_t> payload(large_entry);
    for (std::size_t i = 0; i < sector_capacity; ++i) {
        fill_entry(payload, static_cast<std::uint32_t>(i));
        chron.push(std::span<std::uint8_t>(payload.data(), payload.size()), true);
        chron.mark_synced(i);
    }

    TEST_ASSERT_TRUE(chron.sweep_synced_sector());
    TEST_ASSERT_FALSE(chron.sweep_synced_sector());

    fill_entry(payload, sector_capacity);
    chron.push(std::span<std::uint8_t>(payload.data(), payload.size()), true);
    TEST_ASSERT_FALSE(chron.sweep_synced_sector());

    chron.mark_synced(sector_capacity);
    TEST_ASSERT_TRUE(chron.sweep_synced_sector());
}

TEST_CASE("read indexes span multiple sectors", "[chronicler][sectors]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    constexpr std::size_t large_entry = 512;
    auto chron = Chronicler::create(partition, large_entry);

    const std::size_t sector_capacity = theoretical_capacity(partition.sector_size(), large_entry);

    std::vector<std::uint8_t> payload(large_entry);
    std::vector<std::uint8_t> read_buf(large_entry);

    const std::size_t total = sector_capacity + 2;
    for (std::size_t i = 0; i < total; ++i) {
        fill_entry(payload, static_cast<std::uint32_t>(i));
        chron.push(std::span<std::uint8_t>(payload.data(), payload.size()), false);
    }

    TEST_ASSERT_EQUAL_UINT32(total, chron.size());

    fill_entry(payload, 0);
    chron.read(0, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(payload.data(), read_buf.data(), payload.size());

    fill_entry(payload, static_cast<std::uint32_t>(sector_capacity - 1));
    chron.read(sector_capacity - 1, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(payload.data(), read_buf.data(), payload.size());

    fill_entry(payload, static_cast<std::uint32_t>(sector_capacity));
    chron.read(sector_capacity, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(payload.data(), read_buf.data(), payload.size());

    fill_entry(payload, static_cast<std::uint32_t>(total - 1));
    chron.read(total - 1, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(payload.data(), read_buf.data(), payload.size());
}

extern "C" void app_main(void) {
    unity_run_menu();
}
