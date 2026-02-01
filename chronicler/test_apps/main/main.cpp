#include <bricks/chronicler.hpp>
#include <bricks/chronicler/geometry.hpp>
#include <bricks/chronicler/data_sector.hpp>
#include <bricks/chronicler/bitmap.hpp>
#include <bricks/chronicler/metadata.hpp>

#include <esp_system.h>
#include <esp_partition.h>
#include <unity.h>

#include <algorithm>
#include <cstdint>
#include <deque>
#include <optional>
#include <span>
#include <vector>

using namespace bricks::chronicler;

namespace {

constexpr char partition_label[] = "storage";
constexpr std::size_t entry_size = 32;
constexpr std::uint32_t power_cycle_seed_base = 9000;
constexpr std::uint8_t session_id = 0x01;
constexpr bool dispose_other_sessions = false;

struct SyncCallbackContext {
    std::size_t invocations{};
    std::vector<std::uint8_t> last_entry;
};

void sync_test_callback(Chronicler& chronicler, std::span<const std::uint8_t> entry, void* ctx) {
    (void)chronicler;
    auto* info = static_cast<SyncCallbackContext*>(ctx);
    info->invocations++;
    info->last_entry.assign(entry.begin(), entry.end());
}

const esp_partition_t* find_partition() {
    const esp_partition_t* part = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA,
        ESP_PARTITION_SUBTYPE_ANY,
        partition_label);
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

void require_data_sectors_or_skip(const detail::Geometry& geom, std::size_t min) {
    if (geom.data_sector_count >= min)
        return;
    switch (min) {
    case 1:
        TEST_IGNORE_MESSAGE("requires at least 1 data sector");
        break;
    case 2:
        TEST_IGNORE_MESSAGE("requires at least 2 data sectors");
        break;
    case 3:
        TEST_IGNORE_MESSAGE("requires at least 3 data sectors");
        break;
    case 4:
        TEST_IGNORE_MESSAGE("requires at least 4 data sectors");
        break;
    default:
        TEST_IGNORE_MESSAGE("requires more data sectors");
        break;
    }
}

void fill_entry(std::vector<std::uint8_t>& buf, std::uint32_t seed) {
    for (std::size_t i = 0; i < buf.size(); ++i) {
        const auto val = static_cast<std::uint8_t>((seed + i * 17U) & 0xFFU);
        buf[i] = val;
    }
}

std::vector<std::uint8_t> make_bitmap_used(const detail::Geometry& geom, std::size_t used_count) {
    const std::size_t size = (geom.data_sector_count + 1U) / 2U;
    std::vector<std::uint8_t> bytes(size, 0xFF);
    const std::uint8_t used_nibble =
        static_cast<std::uint8_t>(~static_cast<std::uint8_t>(detail::Bitmap::Used)) & 0x0F;
    for (std::size_t idx = 0; idx < used_count && idx < geom.data_sector_count; ++idx) {
        const std::size_t byte_idx = idx / 2U;
        if ((idx % 2U) == 0U)
            bytes[byte_idx] = static_cast<std::uint8_t>((bytes[byte_idx] & 0xF0U) | used_nibble);
        else
            bytes[byte_idx] = static_cast<std::uint8_t>((bytes[byte_idx] & 0x0FU) | (used_nibble << 4U));
    }
    return bytes;
}

void write_metadata_slot(SectorHandle& slot,
                         const std::vector<std::uint8_t>& bitmap_bytes,
                         bool old_flag) {
    slot.erase();
    slot.write(detail::layout::g_magic, detail::g_magic);
    slot.write(detail::layout::g_version, detail::g_version);
    slot.write_byte(detail::layout::g_initialized, 0x00);
    if (old_flag)
        slot.write_byte(detail::layout::g_old, 0x00);
    if (!bitmap_bytes.empty())
        slot.write(detail::layout::g_bitmap,
                   std::span<const std::uint8_t>(bitmap_bytes.data(), bitmap_bytes.size()));
}

std::size_t theoretical_capacity(std::size_t sector_bytes, std::size_t entry_bytes);

std::uint8_t crc8_update(std::uint8_t crc, std::uint8_t data) {
    crc ^= data;
    for (int i = 0; i < 8; ++i) {
        crc = (crc & 0x80U) ? static_cast<std::uint8_t>((crc << 1U) ^ 0x07U)
                           : static_cast<std::uint8_t>(crc << 1U);
    }
    return crc;
}

std::uint8_t crc8_seed_for_length(std::uint16_t length) {
    std::uint8_t crc = 0;
    crc = crc8_update(crc, static_cast<std::uint8_t>(length & 0xFFU));
    crc = crc8_update(crc, static_cast<std::uint8_t>((length >> 8) & 0x0FU));
    return crc;
}

std::uint8_t crc8_compute(std::uint16_t length, std::span<const std::uint8_t> payload) {
    std::uint8_t crc = crc8_seed_for_length(length);
    for (auto byte : payload)
        crc = crc8_update(crc, byte);
    return crc;
}

std::optional<std::vector<std::uint8_t>> find_crc_escape_payload(std::uint16_t length) {
    if (length == 0)
        return std::nullopt;
    std::vector<std::uint8_t> payload(length);
    if (length == 1) {
        for (int b0 = 0; b0 <= 0xFF; ++b0) {
            payload[0] = static_cast<std::uint8_t>(b0);
            if (crc8_compute(length, payload) == 0xFFU)
                return payload;
        }
        return std::nullopt;
    }
    if (length == 2) {
        for (int b0 = 0; b0 <= 0xFF; ++b0) {
            payload[0] = static_cast<std::uint8_t>(b0);
            for (int b1 = 0; b1 <= 0xFF; ++b1) {
                payload[1] = static_cast<std::uint8_t>(b1);
                if (crc8_compute(length, payload) == 0xFFU)
                    return payload;
            }
        }
    }
    return std::nullopt;
}

struct MixedEntry {
    std::uint32_t seed = 0;
    std::size_t size = 0;
};

struct MixedSimState {
    std::size_t head = 0;
    std::vector<std::size_t> used_bytes;
    std::vector<std::size_t> entry_counts;
    std::deque<MixedEntry> entries;
};

bool sim_push(MixedSimState& state,
              const detail::Geometry& geom,
              std::size_t payload_size,
              std::uint32_t seed) {
    const std::size_t capacity = geom.sector_size - detail::Geometry::sector_header_size;
    const std::size_t record_size = payload_size + detail::Geometry::record_overhead;
    TEST_ASSERT_LESS_OR_EQUAL_UINT32(capacity, record_size);
    bool advanced = false;

    auto advance = [&]() {
        state.head = (state.head + 1U) % geom.data_sector_count;
        if (state.entry_counts[state.head] > 0U) {
            for (std::size_t i = 0; i < state.entry_counts[state.head]; ++i)
                state.entries.pop_front();
        }
        state.entry_counts[state.head] = 0;
        state.used_bytes[state.head] = 0;
        advanced = true;
    };

    if (state.used_bytes[state.head] + record_size > capacity)
        advance();

    state.entries.push_back(MixedEntry{seed, payload_size});
    state.entry_counts[state.head]++;
    state.used_bytes[state.head] += record_size;
    return advanced;
}

void stage_prepare_power_cycle() {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 2);

    const std::size_t sector_capacity = theoretical_capacity(geom.sector_size, entry_size);
    const std::size_t extra = std::max<std::size_t>(1, std::min<std::size_t>(sector_capacity / 4U, 32U));
    const std::size_t entries_to_write = sector_capacity + extra;

    auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);

    std::vector<std::uint8_t> payload(entry_size);
    for (std::size_t i = 0; i < entries_to_write; ++i) {
        fill_entry(payload, power_cycle_seed_base + static_cast<std::uint32_t>(i));
        const bool should_sync = (i == 1) || (i == 3);
        chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), should_sync);
        if (i == 1)
            chron.mark_synced(i);
    }

    TEST_ASSERT_EQUAL_UINT32(entries_to_write, chron.size());
    esp_restart();
}

void stage_verify_after_power_cycle() {
    auto partition = make_partition_handle();
    auto loaded = Chronicler::load(partition, session_id, dispose_other_sessions);
    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 2);
    const std::size_t sector_capacity = theoretical_capacity(geom.sector_size, entry_size);
    const std::size_t extra = std::max<std::size_t>(1, std::min<std::size_t>(sector_capacity / 4U, 32U));
    const std::size_t expected_entries = sector_capacity + extra;

    TEST_ASSERT_TRUE(loaded.has_value());
    auto chron = std::move(*loaded);

    TEST_ASSERT_EQUAL_UINT32(expected_entries, chron.size());

    std::vector<std::uint8_t> payload(entry_size);
    std::vector<std::uint8_t> read_buf(entry_size);

    for (std::size_t i = 0; i < expected_entries; ++i) {
        fill_entry(payload, power_cycle_seed_base + static_cast<std::uint32_t>(i));
        const std::size_t bytes = chron.read(i, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
        TEST_ASSERT_EQUAL_UINT32(payload.size(), bytes);
        TEST_ASSERT_EQUAL_UINT8_ARRAY(payload.data(), read_buf.data(), payload.size());
    }

    auto unsynced = chron.get_unsynced();
    TEST_ASSERT_TRUE(unsynced.has_value());
    TEST_ASSERT_EQUAL_UINT32(3, *unsynced);

    chron.mark_synced(*unsynced);
    TEST_ASSERT_FALSE(chron.get_unsynced().has_value());
}

std::size_t theoretical_capacity(std::size_t sector_bytes, std::size_t entry_bytes) {
    if (entry_bytes == 0 || sector_bytes <= detail::Geometry::sector_header_size)
        return 0;
    const std::size_t available = sector_bytes - detail::Geometry::sector_header_size;
    const std::size_t record_bytes = detail::Geometry::record_overhead + entry_bytes;
    return record_bytes == 0 ? 0 : (available / record_bytes);
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

    detail::Geometry geom(handle);

    TEST_ASSERT_EQUAL_UINT32(kSectorBytes, geom.sector_size);
    TEST_ASSERT_EQUAL_UINT32(detail::Geometry::sector_header_size, geom.data_offset);

    const std::size_t available_bytes = kSectorBytes - detail::layout::g_bitmap;
    const std::size_t metadata_limit = available_bytes * 2U;
    const std::size_t partition_limit = kSectorCount - geom.metadata_sector_count;
    const std::size_t expected_data_sectors = (std::min(metadata_limit, partition_limit) / 2U) * 2U;

    TEST_ASSERT_EQUAL_UINT32(expected_data_sectors, geom.data_sector_count);
}

TEST_CASE("metadata advances head and rotates slots", "[metadata]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 1);

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
    TEST_ASSERT_EQUAL_UINT32(0U, slot0.read_byte(detail::layout::g_old));
    TEST_ASSERT(slot1.read_byte(detail::layout::g_old) != 0U);
}

TEST_CASE("metadata selects partial slot over all-ones", "[metadata]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 2);

    const std::size_t bitmap_size = (geom.data_sector_count + 1U) / 2U;
    std::vector<std::uint8_t> all_ones(bitmap_size, 0xFF);
    auto partial = make_bitmap_used(geom, 2);

    SectorHandle slot0(partition, 0);
    SectorHandle slot1(partition, 1);
    write_metadata_slot(slot0, all_ones, false);
    write_metadata_slot(slot1, partial, false);

    auto loaded = detail::Metadata::load(geom, partition);
    TEST_ASSERT_TRUE(loaded.has_value());
    TEST_ASSERT_EQUAL_UINT32(1, loaded->head());
    TEST_ASSERT_TRUE(loaded->is_sector_used(0));
}

TEST_CASE("metadata chooses slot0 when only slot0 valid", "[metadata]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 2);

    auto partial = make_bitmap_used(geom, 1);

    SectorHandle slot0(partition, 0);
    SectorHandle slot1(partition, 1);
    write_metadata_slot(slot0, partial, false);
    slot1.erase();

    auto loaded = detail::Metadata::load(geom, partition);
    TEST_ASSERT_TRUE(loaded.has_value());
    TEST_ASSERT_EQUAL_UINT32(0, loaded->head());
}

TEST_CASE("metadata chooses slot1 when only slot1 valid", "[metadata]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 2);

    auto partial = make_bitmap_used(geom, 2);

    SectorHandle slot0(partition, 0);
    SectorHandle slot1(partition, 1);
    slot0.erase();
    write_metadata_slot(slot1, partial, false);

    auto loaded = detail::Metadata::load(geom, partition);
    TEST_ASSERT_TRUE(loaded.has_value());
    TEST_ASSERT_EQUAL_UINT32(1, loaded->head());
}

TEST_CASE("metadata selects partial slot over all-zeros", "[metadata]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 2);

    const std::size_t bitmap_size = (geom.data_sector_count + 1U) / 2U;
    std::vector<std::uint8_t> all_zeros(bitmap_size, 0x00);
    auto partial = make_bitmap_used(geom, 1);

    SectorHandle slot0(partition, 0);
    SectorHandle slot1(partition, 1);
    write_metadata_slot(slot0, all_zeros, false);
    write_metadata_slot(slot1, partial, false);

    auto loaded = detail::Metadata::load(geom, partition);
    TEST_ASSERT_TRUE(loaded.has_value());
    TEST_ASSERT_EQUAL_UINT32(0, loaded->head());
    TEST_ASSERT_TRUE(loaded->is_sector_used(0));
}

TEST_CASE("metadata prefers non-old slot", "[metadata]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 3);

    auto partial_more = make_bitmap_used(geom, 3);
    auto partial_less = make_bitmap_used(geom, 1);

    SectorHandle slot0(partition, 0);
    SectorHandle slot1(partition, 1);
    write_metadata_slot(slot0, partial_more, true);
    write_metadata_slot(slot1, partial_less, false);

    auto loaded = detail::Metadata::load(geom, partition);
    TEST_ASSERT_TRUE(loaded.has_value());
    TEST_ASSERT_EQUAL_UINT32(0, loaded->head());
    TEST_ASSERT_TRUE(loaded->is_sector_used(0));
    TEST_ASSERT_FALSE(loaded->is_sector_used(2));
}

TEST_CASE("metadata prefers slot with more used sectors", "[metadata]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 3);

    auto partial_more = make_bitmap_used(geom, 3);
    auto partial_less = make_bitmap_used(geom, 1);

    SectorHandle slot0(partition, 0);
    SectorHandle slot1(partition, 1);
    write_metadata_slot(slot0, partial_more, false);
    write_metadata_slot(slot1, partial_less, false);

    auto loaded = detail::Metadata::load(geom, partition);
    TEST_ASSERT_TRUE(loaded.has_value());
    TEST_ASSERT_EQUAL_UINT32(2, loaded->head());
    TEST_ASSERT_TRUE(loaded->is_sector_used(2));
}

TEST_CASE("metadata defaults to slot0 on tie", "[metadata]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 2);

    auto partial = make_bitmap_used(geom, 2);

    SectorHandle slot0(partition, 0);
    SectorHandle slot1(partition, 1);
    write_metadata_slot(slot0, partial, false);
    write_metadata_slot(slot1, partial, false);

    auto loaded = detail::Metadata::load(geom, partition);
    TEST_ASSERT_TRUE(loaded.has_value());
    TEST_ASSERT_EQUAL_UINT32(1, loaded->head());
}

TEST_CASE("metadata chooses slot0 when both all ones", "[metadata]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    const std::size_t bitmap_size = (geom.data_sector_count + 1U) / 2U;
    std::vector<std::uint8_t> all_ones(bitmap_size, 0xFF);

    SectorHandle slot0(partition, 0);
    SectorHandle slot1(partition, 1);
    write_metadata_slot(slot0, all_ones, false);
    write_metadata_slot(slot1, all_ones, false);

    auto loaded = detail::Metadata::load(geom, partition);
    TEST_ASSERT_TRUE(loaded.has_value());
    TEST_ASSERT_EQUAL_UINT32(0, loaded->head());
}

TEST_CASE("metadata chooses slot0 when both all zeros", "[metadata]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    const std::size_t bitmap_size = (geom.data_sector_count + 1U) / 2U;
    std::vector<std::uint8_t> all_zeros(bitmap_size, 0x00);

    SectorHandle slot0(partition, 0);
    SectorHandle slot1(partition, 1);
    write_metadata_slot(slot0, all_zeros, false);
    write_metadata_slot(slot1, all_zeros, false);

    auto loaded = detail::Metadata::load(geom, partition);
    TEST_ASSERT_TRUE(loaded.has_value());
    TEST_ASSERT_EQUAL_UINT32(geom.data_sector_count - 1U, loaded->head());
}

TEST_CASE("bitmap updates do not bleed across nibbles", "[bitmap]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 2);

    SectorHandle slot0(partition, 0);
    slot0.write(detail::layout::g_magic, detail::g_magic);
    slot0.write(detail::layout::g_version, detail::g_version);
    slot0.write_byte(detail::layout::g_initialized, 0x00);

    detail::Bitmap bitmap(geom, slot0);
    bitmap.load_erased();
    bitmap.mark_disposable(0);

    const std::uint8_t byte_after_first = slot0.read_byte(detail::layout::g_bitmap);
    TEST_ASSERT_EQUAL_UINT32(0xFBU, byte_after_first);

    bitmap.mark_full_and_synced(1);
    const std::uint8_t byte_after_second = slot0.read_byte(detail::layout::g_bitmap);
    TEST_ASSERT_EQUAL_UINT32(0xDBU, byte_after_second);
}

TEST_CASE("bitmap reserved bit is isolated per nibble", "[bitmap]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 2);

    SectorHandle slot0(partition, 0);
    slot0.write(detail::layout::g_magic, detail::g_magic);
    slot0.write(detail::layout::g_version, detail::g_version);
    slot0.write_byte(detail::layout::g_initialized, 0x00);

    slot0.write_byte(detail::layout::g_bitmap, 0xF7);

    detail::Bitmap bitmap(geom, slot0);
    bitmap.load();
    bitmap.mark_full_and_synced(1);

    const std::uint8_t byte_after = slot0.read_byte(detail::layout::g_bitmap);
    TEST_ASSERT_EQUAL_UINT32(0xD7U, byte_after);
}

TEST_CASE("data sectors persist appended entries", "[data_sector]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    const std::size_t capacity = theoretical_capacity(geom.sector_size, entry_size);
    TEST_ASSERT_GREATER_THAN_UINT32(0, capacity);

    auto sector = detail::DataSector::create(geom, partition, 0);

    std::vector<std::uint8_t> payload(entry_size);
    for (std::size_t i = 0; i < capacity; ++i) {
        fill_entry(payload, static_cast<std::uint32_t>(i));
        sector.push(std::span<const std::uint8_t>(payload.data(), payload.size()), (i % 2) == 0);
    }
    TEST_ASSERT_EQUAL_UINT32(capacity, sector.size());

    auto reloaded = detail::DataSector::load(geom, partition, 0);
    TEST_ASSERT_EQUAL_UINT32(sector.size(), reloaded.size());

    std::vector<std::uint8_t> read_buf(entry_size);
    std::vector<std::uint8_t> expected(entry_size);
    for (std::size_t i = 0; i < reloaded.size(); ++i) {
        const std::size_t bytes = reloaded.read(i, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
        TEST_ASSERT_EQUAL_UINT32(expected.size(), bytes);
        fill_entry(expected, static_cast<std::uint32_t>(i));
        TEST_ASSERT_EQUAL_UINT8_ARRAY(expected.data(), read_buf.data(), read_buf.size());
    }
}

TEST_CASE("length header zero seals sector", "[data_sector]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    SectorHandle sector(partition, geom.metadata_sector_count);

    std::uint8_t header[detail::Geometry::length_header_size]{};
    const std::uint16_t length_flags = static_cast<std::uint16_t>(detail::Geometry::flag_mask);
    header[0] = static_cast<std::uint8_t>(length_flags & 0xFFU);
    header[1] = static_cast<std::uint8_t>((length_flags >> 8) & 0xFFU);
    sector.write(geom.data_offset, { header, sizeof(header) });

    auto loaded = detail::DataSector::load(geom, partition, 0);
    TEST_ASSERT_EQUAL_UINT32(0, loaded.size());
    TEST_ASSERT_TRUE(loaded.sealed());
}

TEST_CASE("length header overflow seals sector", "[data_sector]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    SectorHandle sector(partition, geom.metadata_sector_count);

    const std::uint16_t length_flags =
        static_cast<std::uint16_t>((detail::Geometry::flag_mask & ~detail::Geometry::flag_should_sync)
                                   | detail::Geometry::length_mask);
    std::uint8_t header[detail::Geometry::length_header_size]{};
    header[0] = static_cast<std::uint8_t>(length_flags & 0xFFU);
    header[1] = static_cast<std::uint8_t>((length_flags >> 8) & 0xFFU);
    sector.write(geom.data_offset, { header, sizeof(header) });

    auto loaded = detail::DataSector::load(geom, partition, 0);
    TEST_ASSERT_EQUAL_UINT32(0, loaded.size());
    TEST_ASSERT_TRUE(loaded.sealed());
}

TEST_CASE("missing crc seals sector", "[data_sector]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    SectorHandle sector(partition, geom.metadata_sector_count);

    const std::uint16_t length_flags = static_cast<std::uint16_t>(detail::Geometry::flag_mask | 16U);
    std::uint8_t header[detail::Geometry::length_header_size]{};
    header[0] = static_cast<std::uint8_t>(length_flags & 0xFFU);
    header[1] = static_cast<std::uint8_t>((length_flags >> 8) & 0xFFU);
    sector.write(geom.data_offset, { header, sizeof(header) });

    std::vector<std::uint8_t> payload(16, 0x5A);
    sector.write(geom.data_offset + detail::Geometry::length_header_size,
                 std::span<const std::uint8_t>(payload.data(), payload.size()));

    auto loaded = detail::DataSector::load(geom, partition, 0);
    TEST_ASSERT_EQUAL_UINT32(0, loaded.size());
    TEST_ASSERT_TRUE(loaded.sealed());
}

TEST_CASE("crc escape flag mismatch seals sector", "[data_sector]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    SectorHandle sector(partition, geom.metadata_sector_count);

    const std::uint16_t length_flags =
        static_cast<std::uint16_t>((detail::Geometry::flag_mask & ~detail::Geometry::flag_crc_escaped) | 1U);
    std::uint8_t header[detail::Geometry::length_header_size]{};
    header[0] = static_cast<std::uint8_t>(length_flags & 0xFFU);
    header[1] = static_cast<std::uint8_t>((length_flags >> 8) & 0xFFU);
    sector.write(geom.data_offset, { header, sizeof(header) });

    const std::uint8_t payload = 0xAA;
    sector.write(geom.data_offset + detail::Geometry::length_header_size,
                 std::span<const std::uint8_t>(&payload, 1));
    sector.write_byte(geom.data_offset + detail::Geometry::length_header_size + 1, 0x00);

    auto loaded = detail::DataSector::load(geom, partition, 0);
    TEST_ASSERT_EQUAL_UINT32(0, loaded.size());
    TEST_ASSERT_TRUE(loaded.sealed());
}

TEST_CASE("crc escape byte without flag seals sector", "[data_sector]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    SectorHandle sector(partition, geom.metadata_sector_count);

    const std::uint16_t length_flags = static_cast<std::uint16_t>(detail::Geometry::flag_mask | 1U);
    std::uint8_t header[detail::Geometry::length_header_size]{};
    header[0] = static_cast<std::uint8_t>(length_flags & 0xFFU);
    header[1] = static_cast<std::uint8_t>((length_flags >> 8) & 0xFFU);
    sector.write(geom.data_offset, { header, sizeof(header) });

    const std::uint8_t payload = 0x55;
    sector.write(geom.data_offset + detail::Geometry::length_header_size,
                 std::span<const std::uint8_t>(&payload, 1));
    sector.write_byte(geom.data_offset + detail::Geometry::length_header_size + 1, 0xFE);

    auto loaded = detail::DataSector::load(geom, partition, 0);
    TEST_ASSERT_EQUAL_UINT32(0, loaded.size());
    TEST_ASSERT_TRUE(loaded.sealed());
}

TEST_CASE("erased header leaves sector appendable", "[data_sector]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    auto loaded = detail::DataSector::load(geom, partition, 0);

    TEST_ASSERT_EQUAL_UINT32(0, loaded.size());
    TEST_ASSERT_FALSE(loaded.sealed());
    TEST_ASSERT_TRUE(loaded.can_append(1));
}

TEST_CASE("record overflow seals sector", "[data_sector]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    SectorHandle sector(partition, geom.metadata_sector_count);

    const std::size_t capacity = geom.sector_size - detail::Geometry::sector_header_size;
    const std::size_t needed = capacity - detail::Geometry::record_overhead + 1U;
    TEST_ASSERT_LESS_OR_EQUAL_UINT32(detail::Geometry::max_entry_size, needed);
    const std::uint16_t length_flags =
        static_cast<std::uint16_t>(detail::Geometry::flag_mask | static_cast<std::uint16_t>(needed));
    std::uint8_t header[detail::Geometry::length_header_size]{};
    header[0] = static_cast<std::uint8_t>(length_flags & 0xFFU);
    header[1] = static_cast<std::uint8_t>((length_flags >> 8) & 0xFFU);
    sector.write(geom.data_offset, { header, sizeof(header) });

    auto loaded = detail::DataSector::load(geom, partition, 0);
    TEST_ASSERT_EQUAL_UINT32(0, loaded.size());
    TEST_ASSERT_TRUE(loaded.sealed());
}

TEST_CASE("data sector size limits reject zero and oversized entries", "[data_sector]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    std::size_t max_payload =
        geom.sector_size - detail::Geometry::sector_header_size - detail::Geometry::record_overhead;
    if (max_payload > detail::Geometry::max_entry_size)
        max_payload = detail::Geometry::max_entry_size;
    TEST_ASSERT_GREATER_THAN_UINT32(0, max_payload);

    auto sector = detail::DataSector::create(geom, partition, 0);
    TEST_ASSERT_FALSE(sector.can_append(0));
    TEST_ASSERT_TRUE(sector.can_append(max_payload));
    TEST_ASSERT_FALSE(sector.can_append(max_payload + 1));
}

TEST_CASE("entry disposable flag toggles", "[data_sector]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    auto sector = detail::DataSector::create(geom, partition, 0);
    std::vector<std::uint8_t> payload(entry_size);
    fill_entry(payload, 42);
    sector.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);

    TEST_ASSERT_FALSE(sector.is_entry_disposable(0));
    sector.mark_entry_disposable(0);
    TEST_ASSERT_TRUE(sector.is_entry_disposable(0));
}

TEST_CASE("crc escape stores 0xFE and marks escaped flag", "[data_sector]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    auto sector = detail::DataSector::create(geom, partition, 0);

    auto payload_opt = find_crc_escape_payload(1);
    if (!payload_opt)
        payload_opt = find_crc_escape_payload(2);
    TEST_ASSERT_TRUE(payload_opt.has_value());

    auto payload = *payload_opt;
    const std::uint16_t length = static_cast<std::uint16_t>(payload.size());
    TEST_ASSERT_EQUAL_UINT32(0xFFU, crc8_compute(length, payload));

    sector.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);

    SectorHandle raw(partition, geom.metadata_sector_count);
    std::uint8_t header[detail::Geometry::length_header_size]{};
    raw.read(geom.data_offset, { header, sizeof(header) });
    const std::uint16_t length_flags = static_cast<std::uint16_t>(header[0] | (header[1] << 8));
    TEST_ASSERT_EQUAL_UINT32(0U, length_flags & detail::Geometry::flag_crc_escaped);

    const std::uint8_t crc_byte =
        raw.read_byte(geom.data_offset + detail::Geometry::length_header_size + payload.size());
    TEST_ASSERT_EQUAL_UINT32(0xFEU, crc_byte);

    auto reloaded = detail::DataSector::load(geom, partition, 0);
    std::vector<std::uint8_t> read_buf(payload.size());
    const std::size_t bytes = reloaded.read(0, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
    TEST_ASSERT_EQUAL_UINT32(payload.size(), bytes);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(payload.data(), read_buf.data(), payload.size());
}

TEST_CASE("corrupting crc seals the sector", "[data_sector]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    auto sector = detail::DataSector::create(geom, partition, 0);

    std::vector<std::uint8_t> payload(8);
    std::uint32_t seed = 1234;
    while (true) {
        fill_entry(payload, seed++);
        const std::uint8_t crc = crc8_compute(static_cast<std::uint16_t>(payload.size()), payload);
        if (crc != 0x00U && crc != 0xFFU)
            break;
    }
    sector.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);

    SectorHandle raw(partition, geom.metadata_sector_count);
    const std::size_t crc_addr =
        geom.data_offset + detail::Geometry::length_header_size + payload.size();
    raw.write_byte(crc_addr, 0x00);

    auto reloaded = detail::DataSector::load(geom, partition, 0);
    TEST_ASSERT_EQUAL_UINT32(0, reloaded.size());
    TEST_ASSERT_TRUE(reloaded.sealed());
    TEST_ASSERT_FALSE(reloaded.can_append(payload.size()));
}

TEST_CASE("variable length entries round trip", "[chronicler]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    std::size_t max_payload =
        geom.sector_size - detail::Geometry::sector_header_size - detail::Geometry::record_overhead;
    if (max_payload > detail::Geometry::max_entry_size)
        max_payload = detail::Geometry::max_entry_size;
    TEST_ASSERT_GREATER_THAN_UINT32(0, max_payload);

    std::vector<std::size_t> sizes = {1, 3, 7, 31, 128, 256, 511, 1024};
    for (auto& sz : sizes)
        if (sz > max_payload)
            sz = max_payload;

    auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);
    std::vector<std::vector<std::uint8_t>> expected;
    expected.reserve(sizes.size());

    for (std::size_t i = 0; i < sizes.size(); ++i) {
        std::vector<std::uint8_t> payload(sizes[i]);
        fill_entry(payload, static_cast<std::uint32_t>(100 + i));
        chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
        expected.push_back(std::move(payload));
    }

    for (std::size_t i = 0; i < expected.size(); ++i) {
        const std::size_t len = chron.entry_size(i);
        TEST_ASSERT_EQUAL_UINT32(expected[i].size(), len);
        std::vector<std::uint8_t> read_buf(len);
        const std::size_t bytes =
            chron.read(i, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
        TEST_ASSERT_EQUAL_UINT32(expected[i].size(), bytes);
        TEST_ASSERT_EQUAL_UINT8_ARRAY(expected[i].data(), read_buf.data(), expected[i].size());
    }
}

TEST_CASE("mixed size entries wrap and reload", "[chronicler][wrap]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 2);

    std::size_t max_payload =
        geom.sector_size - detail::Geometry::sector_header_size - detail::Geometry::record_overhead;
    if (max_payload > detail::Geometry::max_entry_size)
        max_payload = detail::Geometry::max_entry_size;
    TEST_ASSERT_GREATER_THAN_UINT32(0, max_payload);

    auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);
    MixedSimState sim;
    sim.used_bytes.assign(geom.data_sector_count, 0);
    sim.entry_counts.assign(geom.data_sector_count, 0);

    const std::vector<std::size_t> sizes = {64, 200, 1500, 300, 700, 1200, 50, 900};
    std::size_t advances = 0;
    const std::size_t max_pushes = geom.data_sector_count * 50U;

    for (std::size_t i = 0; i < max_pushes && advances < geom.data_sector_count + 1U; ++i) {
        std::size_t size = sizes[i % sizes.size()];
        if (size == 0)
            size = 1;
        if (size > max_payload)
            size = max_payload;
        std::vector<std::uint8_t> payload(size);
        const std::uint32_t seed = static_cast<std::uint32_t>(i);
        fill_entry(payload, seed);
        chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
        if (sim_push(sim, geom, payload.size(), seed))
            advances++;
    }

    TEST_ASSERT_GREATER_THAN_UINT32(geom.data_sector_count, advances);

    auto loaded = Chronicler::load(partition, session_id, dispose_other_sessions);
    TEST_ASSERT_TRUE(loaded.has_value());
    TEST_ASSERT_EQUAL_UINT32(sim.entries.size(), loaded->size());

    for (std::size_t i = 0; i < sim.entries.size(); ++i) {
        const std::size_t expected_size = sim.entries[i].size;
        const std::size_t len = loaded->entry_size(i);
        TEST_ASSERT_EQUAL_UINT32(expected_size, len);
        std::vector<std::uint8_t> read_buf(len);
        const std::size_t bytes =
            loaded->read(i, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
        TEST_ASSERT_EQUAL_UINT32(expected_size, bytes);
        std::vector<std::uint8_t> expected_payload(expected_size);
        fill_entry(expected_payload, sim.entries[i].seed);
        TEST_ASSERT_EQUAL_UINT8_ARRAY(expected_payload.data(), read_buf.data(), expected_size);
    }
}

TEST_CASE("session id and sector flags persist on new head", "[chronicler]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    const std::size_t sector_capacity = theoretical_capacity(geom.sector_size, entry_size);
    TEST_ASSERT_GREATER_THAN_UINT32(0, sector_capacity);

    auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);

    std::vector<std::uint8_t> payload(entry_size);
    for (std::size_t i = 0; i < sector_capacity; ++i) {
        fill_entry(payload, static_cast<std::uint32_t>(i));
        chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
    }

    const std::uint8_t new_session = 0x12;
    const std::uint8_t flags = 0xA5;
    auto loaded = Chronicler::load(partition, new_session, false);
    TEST_ASSERT_TRUE(loaded.has_value());
    auto chron_new = std::move(*loaded);
    chron_new.set_sector_flags(flags);

    fill_entry(payload, 999);
    chron_new.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
    TEST_ASSERT_EQUAL_UINT32(new_session, chron_new.session_id());
    TEST_ASSERT_EQUAL_UINT32(flags, chron_new.sector_flags());

    auto meta = detail::Metadata::load(geom, partition);
    TEST_ASSERT_TRUE(meta.has_value());
    const std::size_t head = meta->head();

    SectorHandle head_sector(partition, geom.metadata_sector_count + head);
    TEST_ASSERT_EQUAL_UINT32(new_session, head_sector.read_byte(0));
    TEST_ASSERT_EQUAL_UINT32(flags, head_sector.read_byte(1));

    auto loaded_verify = Chronicler::load(partition, new_session, dispose_other_sessions);
    TEST_ASSERT_TRUE(loaded_verify.has_value());
    TEST_ASSERT_EQUAL_UINT32(new_session, loaded_verify->session_id());
    TEST_ASSERT_EQUAL_UINT32(flags, loaded_verify->sector_flags());
}

TEST_CASE("session id and sector flags persist on older sectors", "[chronicler]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 3);
    const std::size_t sector_capacity = theoretical_capacity(geom.sector_size, entry_size);
    TEST_ASSERT_GREATER_THAN_UINT32(0, sector_capacity);

    std::vector<std::uint8_t> payload(entry_size);

    const std::uint8_t session_ids[] = {0x00, 0x21, 0x22};
    const std::uint8_t flags[] = {0x00, 0xA1, 0xA2};

    auto chron0 = Chronicler::create(partition, session_ids[0], dispose_other_sessions);
    for (std::size_t i = 0; i < sector_capacity; ++i) {
        fill_entry(payload, static_cast<std::uint32_t>(i));
        chron0.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
    }

    auto loaded1 = Chronicler::load(partition, session_ids[1], false);
    TEST_ASSERT_TRUE(loaded1.has_value());
    auto chron1 = std::move(*loaded1);
    chron1.set_sector_flags(flags[1]);
    for (std::size_t i = 0; i < sector_capacity; ++i) {
        fill_entry(payload, static_cast<std::uint32_t>(1000 + i));
        chron1.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
    }

    auto loaded2 = Chronicler::load(partition, session_ids[2], false);
    TEST_ASSERT_TRUE(loaded2.has_value());
    auto chron2 = std::move(*loaded2);
    chron2.set_sector_flags(flags[2]);
    fill_entry(payload, 2000);
    chron2.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);

    SectorHandle sector0(partition, geom.metadata_sector_count + 0);
    SectorHandle sector1(partition, geom.metadata_sector_count + 1);
    SectorHandle sector2(partition, geom.metadata_sector_count + 2);

    TEST_ASSERT_EQUAL_UINT32(session_ids[0], sector0.read_byte(0));
    TEST_ASSERT_EQUAL_UINT32(flags[0], sector0.read_byte(1));
    TEST_ASSERT_EQUAL_UINT32(session_ids[1], sector1.read_byte(0));
    TEST_ASSERT_EQUAL_UINT32(flags[1], sector1.read_byte(1));
    TEST_ASSERT_EQUAL_UINT32(session_ids[2], sector2.read_byte(0));
    TEST_ASSERT_EQUAL_UINT32(flags[2], sector2.read_byte(1));
}

TEST_CASE("session filtering isolates entries", "[chronicler][session]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 2);

    const std::uint8_t session_a = 0x11;
    const std::uint8_t session_b = 0x22;

    auto chron = Chronicler::create(partition, session_a, false);
    std::vector<std::uint8_t> payload(entry_size);

    const std::size_t count_a = 3;
    for (std::size_t i = 0; i < count_a; ++i) {
        fill_entry(payload, static_cast<std::uint32_t>(i));
        chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
    }

    auto loaded_b = Chronicler::load(partition, session_b, false);
    TEST_ASSERT_TRUE(loaded_b.has_value());
    auto chron_b = std::move(*loaded_b);
    const std::size_t count_b = 2;
    for (std::size_t i = 0; i < count_b; ++i) {
        fill_entry(payload, static_cast<std::uint32_t>(100 + i));
        chron_b.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
    }

    auto loaded_a = Chronicler::load(partition, session_a, false);
    TEST_ASSERT_TRUE(loaded_a.has_value());
    TEST_ASSERT_EQUAL_UINT32(count_a, loaded_a->size());

    auto loaded_b_verify = Chronicler::load(partition, session_b, false);
    TEST_ASSERT_TRUE(loaded_b_verify.has_value());
    TEST_ASSERT_EQUAL_UINT32(count_b, loaded_b_verify->size());
}

TEST_CASE("session filtering skips other-session sectors", "[chronicler][session]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 3);

    const std::uint8_t session_a = 0x41;
    const std::uint8_t session_b = 0x42;
    const std::size_t sector_capacity = theoretical_capacity(geom.sector_size, entry_size);
    TEST_ASSERT_GREATER_THAN_UINT32(0, sector_capacity);

    auto chron_a = Chronicler::create(partition, session_a, false);
    std::vector<std::uint8_t> payload(entry_size);
    for (std::size_t i = 0; i < sector_capacity; ++i) {
        fill_entry(payload, static_cast<std::uint32_t>(i));
        chron_a.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
    }

    auto loaded_b = Chronicler::load(partition, session_b, false);
    TEST_ASSERT_TRUE(loaded_b.has_value());
    auto chron_b = std::move(*loaded_b);
    fill_entry(payload, 100);
    chron_b.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);

    auto loaded_a = Chronicler::load(partition, session_a, false);
    TEST_ASSERT_TRUE(loaded_a.has_value());
    auto chron_a2 = std::move(*loaded_a);
    fill_entry(payload, 200);
    chron_a2.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);

    TEST_ASSERT_EQUAL_UINT32(sector_capacity + 1U, chron_a2.size());
    std::vector<std::uint8_t> read_buf(entry_size);
    fill_entry(payload, 200);
    TEST_ASSERT_EQUAL_UINT32(payload.size(),
                             chron_a2.read(sector_capacity,
                                           std::span<std::uint8_t>(read_buf.data(), read_buf.size())));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(payload.data(), read_buf.data(), payload.size());
}

TEST_CASE("mark_synced handle rejects other session", "[chronicler][session]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 1);

    const std::uint8_t session_a = 0x51;
    const std::uint8_t session_b = 0x52;
    auto chron_a = Chronicler::create(partition, session_a, false);

    std::vector<std::uint8_t> payload(entry_size);
    fill_entry(payload, 7);
    auto handle = chron_a.push_with_handle(std::span<const std::uint8_t>(payload.data(), payload.size()), true);

    auto loaded_b = Chronicler::load(partition, session_b, false);
    TEST_ASSERT_TRUE(loaded_b.has_value());
    auto chron_b = std::move(*loaded_b);
    TEST_ASSERT_FALSE(chron_b.mark_synced(handle));
}

TEST_CASE("mark_synced handle rejects erased sector", "[chronicler][session]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 2);

    const std::size_t sector_capacity = theoretical_capacity(geom.sector_size, entry_size);
    TEST_ASSERT_GREATER_THAN_UINT32(0, sector_capacity);

    auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);
    std::vector<std::uint8_t> payload(entry_size);
    fill_entry(payload, 1);
    auto handle = chron.push_with_handle(std::span<const std::uint8_t>(payload.data(), payload.size()), true);

    for (std::size_t i = 1; i < sector_capacity + 1; ++i) {
        fill_entry(payload, static_cast<std::uint32_t>(i));
        chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
    }

    TEST_ASSERT_TRUE(chron.mark_disposable(0));
    TEST_ASSERT_TRUE(chron.sweep_disposable_sector());
    TEST_ASSERT_FALSE(chron.mark_synced(handle));
}

TEST_CASE("mark_synced handle rejects recycled sector", "[chronicler][session]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 2);

    const std::size_t sector_capacity = theoretical_capacity(geom.sector_size, entry_size);
    TEST_ASSERT_GREATER_THAN_UINT32(1, sector_capacity);

    auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);
    std::vector<std::uint8_t> payload(entry_size);
    fill_entry(payload, 1);
    auto handle = chron.push_with_handle(std::span<const std::uint8_t>(payload.data(), payload.size()), true);

    for (std::size_t i = 1; i < sector_capacity + 1; ++i) {
        fill_entry(payload, static_cast<std::uint32_t>(i));
        chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
    }

    TEST_ASSERT_TRUE(chron.mark_disposable(0));
    TEST_ASSERT_TRUE(chron.sweep_disposable_sector());

    fill_entry(payload, 42);
    chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);

    TEST_ASSERT_FALSE(chron.mark_synced(handle));
}

TEST_CASE("session filtering across wrap", "[chronicler][session][wrap]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 4);

    const std::uint8_t session_a = 0x61;
    const std::uint8_t session_b = 0x62;
    const std::size_t sector_capacity = theoretical_capacity(geom.sector_size, entry_size);
    TEST_ASSERT_GREATER_THAN_UINT32(0, sector_capacity);

    auto chron_a = Chronicler::create(partition, session_a, false);
    std::vector<std::uint8_t> payload(entry_size);

    const std::size_t pushes_a = sector_capacity * (geom.data_sector_count + 1);
    for (std::size_t i = 0; i < pushes_a; ++i) {
        fill_entry(payload, static_cast<std::uint32_t>(i));
        chron_a.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
    }

    auto loaded_b = Chronicler::load(partition, session_b, false);
    TEST_ASSERT_TRUE(loaded_b.has_value());
    auto chron_b = std::move(*loaded_b);
    fill_entry(payload, 5000);
    chron_b.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);

    auto loaded_a = Chronicler::load(partition, session_a, false);
    TEST_ASSERT_TRUE(loaded_a.has_value());
    auto chron_a2 = std::move(*loaded_a);
    fill_entry(payload, 200);
    chron_a2.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
    const std::size_t expected = (geom.data_sector_count - 2U) * sector_capacity + 1U;
    TEST_ASSERT_EQUAL_UINT32(expected, chron_a2.size());

    std::vector<std::uint8_t> read_buf(entry_size);
    TEST_ASSERT_EQUAL_UINT32(payload.size(),
                             chron_a2.read(expected - 1,
                                           std::span<std::uint8_t>(read_buf.data(), read_buf.size())));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(payload.data(), read_buf.data(), payload.size());
}

TEST_CASE("dispose other sessions marks disposable", "[chronicler][session]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 2);

    const std::uint8_t session_a = 0x31;
    const std::uint8_t session_b = 0x32;

    auto chron = Chronicler::create(partition, session_a, false);
    std::vector<std::uint8_t> payload(entry_size);
    fill_entry(payload, 1);
    chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);

    auto loaded_b = Chronicler::load(partition, session_b, false);
    TEST_ASSERT_TRUE(loaded_b.has_value());
    auto chron_b = std::move(*loaded_b);
    fill_entry(payload, 2);
    chron_b.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);

    auto loaded = Chronicler::load(partition, session_b, true);
    TEST_ASSERT_TRUE(loaded.has_value());

    auto meta = detail::Metadata::load(geom, partition);
    TEST_ASSERT_TRUE(meta.has_value());
    for (auto sector_idx : detail::collect_used_sector_indices(*meta, geom)) {
        SectorHandle sector(partition, geom.metadata_sector_count + sector_idx);
        const std::uint8_t sid = sector.read_byte(0);
        if (sid != session_b)
            TEST_ASSERT_TRUE(meta->is_disposable(sector_idx));
        else
            TEST_ASSERT_FALSE(meta->is_disposable(sector_idx));
    }
}

TEST_CASE("disposable sweep refuses non-disposable and erases disposable sectors", "[chronicler]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    const std::size_t sector_capacity = theoretical_capacity(geom.sector_size, entry_size);
    TEST_ASSERT_GREATER_THAN_UINT32(0, sector_capacity);
    require_data_sectors_or_skip(geom, 2);

    auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);
    std::vector<std::uint8_t> payload(entry_size);

    const std::size_t entries = sector_capacity + 1;
    for (std::size_t i = 0; i < entries; ++i) {
        fill_entry(payload, static_cast<std::uint32_t>(i));
        chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
    }

    const std::size_t head_entry = sector_capacity;
    TEST_ASSERT_TRUE(chron.mark_disposable(head_entry));
    TEST_ASSERT_FALSE(chron.sweep_disposable_sector());

    TEST_ASSERT_TRUE(chron.mark_disposable(0));
    TEST_ASSERT_TRUE(chron.sweep_disposable_sector());

    SectorHandle oldest(partition, geom.metadata_sector_count);
    TEST_ASSERT_EQUAL_UINT32(0xFFU, oldest.read_byte(0));
    TEST_ASSERT_EQUAL_UINT32(0xFFU, oldest.read_byte(1));
}

TEST_CASE("disposable sweep refuses non-disposable non-head sector", "[chronicler]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    const std::size_t sector_capacity = theoretical_capacity(geom.sector_size, entry_size);
    TEST_ASSERT_GREATER_THAN_UINT32(0, sector_capacity);
    require_data_sectors_or_skip(geom, 3);

    auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);
    std::vector<std::uint8_t> payload(entry_size);

    const std::size_t entries = sector_capacity * 2 + 1;
    for (std::size_t i = 0; i < entries; ++i) {
        fill_entry(payload, static_cast<std::uint32_t>(i));
        chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
    }

    TEST_ASSERT_FALSE(chron.sweep_disposable_sector());
}

TEST_CASE("mark_disposable is idempotent", "[chronicler]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    const std::size_t sector_capacity = theoretical_capacity(geom.sector_size, entry_size);
    TEST_ASSERT_GREATER_THAN_UINT32(0, sector_capacity);

    auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);
    std::vector<std::uint8_t> payload(entry_size);
    fill_entry(payload, 1);
    chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);

    TEST_ASSERT_TRUE(chron.mark_disposable(0));
    TEST_ASSERT_FALSE(chron.mark_disposable(0));
}

TEST_CASE("entry disposable auto marks sector disposable", "[chronicler]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    const std::size_t sector_capacity = theoretical_capacity(geom.sector_size, entry_size);
    TEST_ASSERT_GREATER_THAN_UINT32(0, sector_capacity);
    require_data_sectors_or_skip(geom, 2);

    auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);
    std::vector<std::uint8_t> payload(entry_size);

    const std::size_t entries = sector_capacity + 1;
    for (std::size_t i = 0; i < entries; ++i) {
        fill_entry(payload, static_cast<std::uint32_t>(i));
        chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
    }

    for (std::size_t i = 0; i + 1 < sector_capacity; ++i)
        TEST_ASSERT_TRUE(chron.mark_entry_disposable(i));
    TEST_ASSERT_FALSE(chron.sweep_disposable_sector());

    TEST_ASSERT_TRUE(chron.mark_entry_disposable(sector_capacity - 1));
    TEST_ASSERT_TRUE(chron.sweep_disposable_sector());
}

TEST_CASE("collect_used_sector_indices returns empty when head unused", "[metadata]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 1);

    const std::size_t bitmap_size = (geom.data_sector_count + 1U) / 2U;
    std::vector<std::uint8_t> all_ones(bitmap_size, 0xFF);

    SectorHandle slot0(partition, 0);
    SectorHandle slot1(partition, 1);
    write_metadata_slot(slot0, all_ones, false);
    write_metadata_slot(slot1, all_ones, true);

    auto meta = detail::Metadata::load(geom, partition);
    TEST_ASSERT_TRUE(meta.has_value());
    const auto indices = detail::collect_used_sector_indices(*meta, geom);
    TEST_ASSERT_EQUAL_UINT32(1, indices.size());
    TEST_ASSERT_EQUAL_UINT32(0, indices.front());
}

TEST_CASE("data sector rejects can_append beyond max entry size", "[data_sector]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    auto sector = detail::DataSector::create(geom, partition, 0);
    TEST_ASSERT_FALSE(sector.can_append(detail::Geometry::max_entry_size + 1U));
}

TEST_CASE("wrapped metadata uses other-slot all-zeros ordering", "[metadata]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 4);

    auto active_bitmap = make_bitmap_used(geom, 3);
    const std::size_t bitmap_size = (geom.data_sector_count + 1U) / 2U;
    std::vector<std::uint8_t> all_zeros(bitmap_size, 0x00);

    SectorHandle slot0(partition, 0);
    SectorHandle slot1(partition, 1);
    write_metadata_slot(slot0, active_bitmap, false);
    write_metadata_slot(slot1, all_zeros, false);

    auto meta = detail::Metadata::load(geom, partition);
    TEST_ASSERT_TRUE(meta.has_value());

    const auto indices = detail::collect_used_sector_indices(*meta, geom);
    TEST_ASSERT_EQUAL_UINT32(geom.data_sector_count, indices.size());
    TEST_ASSERT_EQUAL_UINT32((meta->head() + 1U) % geom.data_sector_count, indices.front());
    TEST_ASSERT_EQUAL_UINT32(meta->head(), indices.back());
}
TEST_CASE("disposable flag persists across reload", "[chronicler]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    const std::size_t sector_capacity = theoretical_capacity(geom.sector_size, entry_size);
    TEST_ASSERT_GREATER_THAN_UINT32(0, sector_capacity);
    require_data_sectors_or_skip(geom, 2);

    {
        auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);
        std::vector<std::uint8_t> payload(entry_size);
        for (std::size_t i = 0; i < sector_capacity + 1; ++i) {
            fill_entry(payload, static_cast<std::uint32_t>(i));
            chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
        }
        TEST_ASSERT_TRUE(chron.mark_disposable(0));
    }

    auto loaded = Chronicler::load(partition, session_id, dispose_other_sessions);
    TEST_ASSERT_TRUE(loaded.has_value());
    TEST_ASSERT_TRUE(loaded->sweep_disposable_sector());

    SectorHandle oldest(partition, geom.metadata_sector_count);
    TEST_ASSERT_EQUAL_UINT32(0xFFU, oldest.read_byte(0));
    TEST_ASSERT_EQUAL_UINT32(0xFFU, oldest.read_byte(1));
}

TEST_CASE("metadata version mismatch fails load", "[metadata]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);
    (void)chron;

    SectorHandle slot0(partition, 0);
    SectorHandle slot1(partition, 1);
    slot0.write(detail::layout::g_version, 0U);
    slot1.write(detail::layout::g_version, 0U);

    auto loaded = detail::Metadata::load(geom, partition);
    TEST_ASSERT_FALSE(loaded.has_value());
}

TEST_CASE("chronicler push/read round trip on active sector", "[chronicler]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    const std::size_t sector_capacity = theoretical_capacity(geom.sector_size, entry_size);
    TEST_ASSERT_GREATER_THAN_UINT32(0, sector_capacity);

    auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);

    const std::size_t push_count = sector_capacity + std::min<std::size_t>(sector_capacity, 5);

    std::vector<std::uint8_t> payload(entry_size);
    std::vector<std::uint8_t> read_buf(entry_size);

    for (std::size_t i = 0; i < push_count; ++i) {
        fill_entry(payload, static_cast<std::uint32_t>(i));
        chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
    }

    for (std::size_t i = 0; i < push_count; ++i) {
        const std::size_t bytes = chron.read(i, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
        TEST_ASSERT_EQUAL_UINT32(payload.size(), bytes);
        fill_entry(payload, static_cast<std::uint32_t>(i));
        TEST_ASSERT_EQUAL_UINT8_ARRAY(payload.data(), read_buf.data(), payload.size());
    }
}

TEST_CASE("load fails on blank partition", "[chronicler][load]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    auto loaded = Chronicler::load(partition, session_id, dispose_other_sessions);
    TEST_ASSERT_FALSE(loaded.has_value());
}

TEST_CASE("entries survive power cycle and reload", "[chronicler][load]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    const std::size_t sector_capacity = theoretical_capacity(geom.sector_size, entry_size);
    const std::size_t entry_count = (sector_capacity * 2) + std::min<std::size_t>(sector_capacity, 8);
    std::vector<std::uint8_t> payload(entry_size);
    std::vector<std::uint8_t> read_buf(entry_size);

    {
        auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);
        for (std::size_t i = 0; i < entry_count; ++i) {
            fill_entry(payload, static_cast<std::uint32_t>(i));
            chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), (i % 2) == 0);
        }
    }

    auto loaded = Chronicler::load(partition, session_id, dispose_other_sessions);
    TEST_ASSERT_TRUE(loaded.has_value());
    auto chron = std::move(*loaded);
    TEST_ASSERT_EQUAL_UINT32(entry_count, chron.size());

    for (std::size_t i = 0; i < entry_count; ++i) {
        const std::size_t bytes = chron.read(i, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
        TEST_ASSERT_EQUAL_UINT32(payload.size(), bytes);
        fill_entry(payload, static_cast<std::uint32_t>(i));
        TEST_ASSERT_EQUAL_UINT8_ARRAY(payload.data(), read_buf.data(), payload.size());
    }

    fill_entry(payload, static_cast<std::uint32_t>(entry_count));
    chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), true);
    const std::size_t bytes = chron.read(entry_count, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
    TEST_ASSERT_EQUAL_UINT32(payload.size(), bytes);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(payload.data(), read_buf.data(), payload.size());
}

TEST_CASE("sync callback fires for should_sync entries", "[chronicler][callback]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 2);
    auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);

    SyncCallbackContext ctx;
    ctx.last_entry.resize(entry_size);
    chron.set_sync_callback(sync_test_callback, &ctx);

    std::vector<std::uint8_t> payload(entry_size);

    const std::size_t sector_capacity = theoretical_capacity(geom.sector_size, entry_size);
    const std::size_t total = sector_capacity + std::min<std::size_t>(sector_capacity, 6);
    std::vector<std::uint8_t> expected(entry_size);
    std::uint32_t expected_invocations = 0;
    std::uint32_t last_sync_seed = 0;

    for (std::size_t i = 0; i < total; ++i) {
        fill_entry(payload, static_cast<std::uint32_t>(i));
        const bool should_sync = (i % 2) == 0;
        chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), should_sync);
        if (should_sync) {
            expected_invocations++;
            last_sync_seed = static_cast<std::uint32_t>(i);
        }
    }

    TEST_ASSERT_EQUAL_UINT32(expected_invocations, ctx.invocations);
    fill_entry(expected, last_sync_seed);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected.data(), ctx.last_entry.data(), expected.size());
}

TEST_CASE("sync bookkeeping APIs reflect entry state", "[chronicler][sync]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 2);
    auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);

    std::vector<std::uint8_t> payload(entry_size);

    const std::size_t sector_capacity = theoretical_capacity(geom.sector_size, entry_size);
    const std::size_t idx_first_sync = 1;
    const std::size_t idx_second_sync = sector_capacity + 1;
    const std::size_t total = idx_second_sync + 3;

    for (std::size_t i = 0; i < total; ++i) {
        fill_entry(payload, static_cast<std::uint32_t>(i));
        const bool should_sync = (i == idx_first_sync) || (i == idx_second_sync);
        chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), should_sync);
    }

    TEST_ASSERT_TRUE(chron.is_synced(0));
    TEST_ASSERT_FALSE(chron.is_synced(idx_first_sync));

    auto unsynced = chron.get_unsynced();
    TEST_ASSERT_TRUE(unsynced.has_value());
    TEST_ASSERT_EQUAL_UINT32(idx_first_sync, *unsynced);

    chron.mark_synced(idx_first_sync);
    TEST_ASSERT_TRUE(chron.is_synced(idx_first_sync));

    unsynced = chron.get_unsynced();
    TEST_ASSERT_TRUE(unsynced.has_value());
    TEST_ASSERT_EQUAL_UINT32(idx_second_sync, *unsynced);

    chron.mark_synced(idx_second_sync);
    TEST_ASSERT_FALSE(chron.get_unsynced().has_value());
}

TEST_CASE("push_with_handle returns handle for mark_synced", "[chronicler][sync]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 1);

    auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);
    std::vector<std::uint8_t> payload(entry_size);
    fill_entry(payload, 5);

    auto handle = chron.push_with_handle(std::span<const std::uint8_t>(payload.data(), payload.size()), true);
    TEST_ASSERT_FALSE(chron.is_synced(0));
    TEST_ASSERT_TRUE(chron.mark_synced(handle));
    TEST_ASSERT_TRUE(chron.is_synced(0));
}

TEST_CASE("sweep marks fully synced sectors lazily", "[chronicler][sync][gc]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 2);
    constexpr std::size_t large_entry = 512;
    auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);

    const std::size_t sector_capacity = theoretical_capacity(partition.sector_size(), large_entry);

    std::vector<std::uint8_t> payload(large_entry);
    for (std::size_t i = 0; i < sector_capacity; ++i) {
        fill_entry(payload, static_cast<std::uint32_t>(i));
        chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), true);
        chron.mark_synced(i);
    }

    TEST_ASSERT_TRUE(chron.sweep_synced_sector());
    auto meta = detail::Metadata::load(geom, partition);
    TEST_ASSERT_TRUE(meta.has_value());
    TEST_ASSERT_TRUE(meta->is_sector_used(meta->head()));
    TEST_ASSERT_FALSE(meta->mark_full_and_synced(meta->head()));
    TEST_ASSERT_FALSE(chron.sweep_synced_sector());

    fill_entry(payload, sector_capacity);
    chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), true);
    TEST_ASSERT_FALSE(chron.sweep_synced_sector());

    chron.mark_synced(sector_capacity);
    TEST_ASSERT_TRUE(chron.sweep_synced_sector());
}

TEST_CASE("read indexes span multiple sectors", "[chronicler][sectors]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 2);

    constexpr std::size_t large_entry = 512;
    auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);

    const std::size_t sector_capacity = theoretical_capacity(partition.sector_size(), large_entry);

    std::vector<std::uint8_t> payload(large_entry);
    std::vector<std::uint8_t> read_buf(large_entry);

    const std::size_t total = sector_capacity + 2;
    for (std::size_t i = 0; i < total; ++i) {
        fill_entry(payload, static_cast<std::uint32_t>(i));
        chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
    }

    TEST_ASSERT_EQUAL_UINT32(total, chron.size());

    fill_entry(payload, 0);
    TEST_ASSERT_EQUAL_UINT32(payload.size(), chron.read(0, std::span<std::uint8_t>(read_buf.data(), read_buf.size())));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(payload.data(), read_buf.data(), payload.size());

    fill_entry(payload, static_cast<std::uint32_t>(sector_capacity - 1));
    TEST_ASSERT_EQUAL_UINT32(payload.size(),
                             chron.read(sector_capacity - 1,
                                        std::span<std::uint8_t>(read_buf.data(), read_buf.size())));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(payload.data(), read_buf.data(), payload.size());

    fill_entry(payload, static_cast<std::uint32_t>(sector_capacity));
    TEST_ASSERT_EQUAL_UINT32(payload.size(),
                             chron.read(sector_capacity,
                                        std::span<std::uint8_t>(read_buf.data(), read_buf.size())));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(payload.data(), read_buf.data(), payload.size());

    fill_entry(payload, static_cast<std::uint32_t>(total - 1));
    TEST_ASSERT_EQUAL_UINT32(payload.size(),
                             chron.read(total - 1,
                                        std::span<std::uint8_t>(read_buf.data(), read_buf.size())));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(payload.data(), read_buf.data(), payload.size());
}

TEST_CASE("size accounts for wrap", "[chronicler][wrap]") {
    auto partition = make_partition_handle();
    wipe_partition(partition);

    detail::Geometry geom(partition);
    require_data_sectors_or_skip(geom, 2);
    const std::size_t sector_capacity = theoretical_capacity(geom.sector_size, entry_size);
    TEST_ASSERT_GREATER_THAN_UINT32(0, sector_capacity);

    auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);

    const std::size_t capacity = sector_capacity * geom.data_sector_count;
    const std::size_t extra = std::min<std::size_t>(sector_capacity, 5);
    TEST_ASSERT_GREATER_THAN_UINT32(0, extra);

    std::vector<std::uint8_t> payload(entry_size);
    for (std::size_t i = 0; i < capacity + extra; ++i) {
        fill_entry(payload, static_cast<std::uint32_t>(i));
        chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
    }

    const std::size_t expected = sector_capacity * (geom.data_sector_count - 1) + extra;
    TEST_ASSERT_EQUAL_UINT32(expected, chron.size());
}

#if !CONFIG_IDF_TARGET_LINUX
TEST_CASE_MULTIPLE_STAGES("entries persist across reset", "[chronicler][reset=SW_CPU_RESET]",
                          stage_prepare_power_cycle,
                          stage_verify_after_power_cycle);
#endif

extern "C" void app_main(void) {
    unity_run_menu();
}
