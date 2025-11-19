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
inline constexpr std::size_t g_entry_size  = 8;
inline constexpr std::size_t g_initialized = 12;
inline constexpr std::size_t g_old         = 16;
inline constexpr std::size_t g_bitmap      = 20;
} // namespace layout

inline constexpr std::uint32_t g_magic = (((std::uint32_t)'C') << 0)
                                       | (((std::uint32_t)'H') << 8)
                                       | (((std::uint32_t)'R') << 16)
                                       | (((std::uint32_t)'N') << 24);
inline constexpr std::uint32_t g_version = 1U;

struct Geometry {
    std::uint32_t entry_size;
    std::size_t sector_capacity;
    std::size_t data_offset;
    std::size_t metadata_sector_count;
    std::size_t data_sector_count;

    static constexpr std::size_t calc_sector_capacity(std::size_t sector_size, std::size_t entry_size) {
        std::size_t capacity = 0;
        while (sector_size != 0) {
            std::size_t step = entry_size + (capacity % 8 == 0 ? 4 : 0);
            if (sector_size < step)
                break;
            sector_size -= step;
            ++capacity;
        }
        return capacity;
    }

    static constexpr std::size_t calc_data_offset(std::size_t sector_capacity) {
        std::size_t data_offset = sector_capacity / 2;
        if (sector_capacity % 2 != 0)
            data_offset++;
        data_offset = (data_offset + 3U) & ~std::size_t(3);
        return data_offset;
    }

    constexpr std::size_t calc_data_sector_count(const PartitionHandle& partition) {
        if (partition.sector_count() <= metadata_sector_count)
            return 0;

        const std::size_t partition_limit = partition.sector_count() - metadata_sector_count;
        const std::size_t rounded_partition_limit = (partition_limit / 16U) * 16U;

        if (partition.sector_size() <= layout::g_bitmap)
            return 0;

        const std::size_t available_words = (partition.sector_size() - layout::g_bitmap) / 4U;
        const std::size_t metadata_limit = available_words * 16U;

        if (metadata_limit == 0 || rounded_partition_limit == 0)
            return 0;

        return std::min(metadata_limit, rounded_partition_limit);
    }

    constexpr Geometry(std::size_t entry_sz, const PartitionHandle& partition)
        : entry_size(static_cast<std::uint32_t>(entry_sz))
        , sector_capacity(calc_sector_capacity(partition.sector_size(), entry_sz))
        , data_offset(calc_data_offset(sector_capacity))
        , metadata_sector_count(2)
        , data_sector_count(calc_data_sector_count(partition)) {
        assert(entry_sz % 4 == 0);
    }
};

} // namespace bricks::chronicler::detail
