#pragma once

#include "bricks/flash_utils.hpp"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>

namespace bricks::chronicler::detail {

namespace layout {
inline constexpr std::size_t g_magic       = 0;
inline constexpr std::size_t g_version     = 4;
inline constexpr std::size_t g_initialized = 8;
inline constexpr std::size_t g_old         = 9;
inline constexpr std::size_t g_bitmap      = 10;
} // namespace layout

inline constexpr std::uint32_t g_magic = (((std::uint32_t)'C') << 0)
                                       | (((std::uint32_t)'H') << 8)
                                       | (((std::uint32_t)'R') << 16)
                                       | (((std::uint32_t)'N') << 24);
inline constexpr std::uint32_t g_version = 2U;

struct Geometry {
    std::size_t data_offset;
    std::size_t metadata_sector_count;
    std::size_t data_sector_count;
    std::size_t sector_size;

    static constexpr std::size_t sector_session_offset = 0;
    static constexpr std::size_t sector_flags_offset = 1;
    static constexpr std::size_t sector_first_entry_id_offset = 2;
    static constexpr std::size_t sector_commit_offset = 6;
    static constexpr std::size_t sector_header_size = 7;
    static constexpr std::uint8_t sector_commit_marker(std::uint8_t generation) {
        return (generation & 1U) == 0 ? 0xFE : 0xFC;
    }
    static constexpr std::uint8_t sector_commit_generation(std::uint8_t marker) {
        return marker == 0xFE ? 0 : marker == 0xFC ? 1 : 0xFF;
    }
    static constexpr std::size_t length_header_size = 2;
    static constexpr std::size_t crc_size = 1;
    static constexpr std::size_t record_overhead = length_header_size + crc_size;
    static constexpr std::uint16_t length_mask = 0x0FFF;
    static constexpr std::uint16_t flag_mask = 0xF000;
    static constexpr std::uint16_t flag_should_sync = 1U << 12;
    static constexpr std::uint16_t flag_synced = 1U << 13;
    static constexpr std::uint16_t flag_crc_escaped = 1U << 14;
    static constexpr std::uint16_t flag_entry_disposable = 1U << 15;
    static constexpr std::size_t max_entry_size = length_mask;

    constexpr std::size_t calc_data_sector_count(const PartitionHandle& partition) {
        if (partition.sector_count() <= metadata_sector_count)
            return 0;

        const std::size_t partition_limit = partition.sector_count() - metadata_sector_count;

        if (partition.sector_size() <= layout::g_bitmap)
            return 0;

        const std::size_t available_bytes = partition.sector_size() - layout::g_bitmap;
        const std::size_t metadata_limit = available_bytes * 2U;

        if (metadata_limit == 0 || partition_limit == 0)
            return 0;

        const std::size_t count = std::min(metadata_limit, partition_limit);
        return (count / 2U) * 2U;
    }

    constexpr Geometry(const PartitionHandle& partition)
        : data_offset(sector_header_size)
        , metadata_sector_count(2)
        , data_sector_count(calc_data_sector_count(partition))
        , sector_size(partition.sector_size()) {}
};

} // namespace bricks::chronicler::detail
