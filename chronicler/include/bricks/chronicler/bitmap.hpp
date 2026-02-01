#pragma once

#include "bricks/chronicler/geometry.hpp"
#include "bricks/flash_utils.hpp"

#include <optional>

namespace bricks::chronicler::detail {

class Bitmap {
public:
    enum Flags : uint8_t {
        Used          = 1U << 0,
        FullAndSynced = 1U << 1,
        Disposable    = 1U << 2,
        Reserved      = 1U << 3,
    };

    enum class Pattern : uint8_t {
        AllOnes,
        AllZeros,
        Partial,
    };

private:
    Geometry m_geometry;
    SectorHandle m_sector;
    Cache m_cache;
    std::optional<std::size_t> m_head;

    uint8_t _read_flags(std::size_t idx) const {
        uint8_t flags = m_cache.read(idx / 2);
        flags = ~flags;
        if (idx % 2 == 1)
            flags >>= 4;
        flags &= 0x0F;
        return flags;
    }

    void _mark_flags(std::size_t idx, std::uint8_t flags) {
        flags &= 0x0F;
        std::uint8_t nibble = static_cast<std::uint8_t>(~flags) & 0x0F;
        std::uint8_t target;
        if (idx % 2 == 0)
            target = static_cast<std::uint8_t>(nibble | 0xF0);
        else
            target = static_cast<std::uint8_t>((nibble << 4) | 0x0F);
        std::uint8_t current = m_cache.read(idx / 2);
        std::uint8_t next = static_cast<std::uint8_t>(current & target);
        m_cache.write(idx / 2, next);
    }

    std::optional<std::size_t> _find_head() {
        if (!is_used(0))
            return std::nullopt;
        for (std::size_t i = 1; i < m_geometry.data_sector_count; i++)
            if (!is_used(i))
                return i - 1;
        return m_geometry.data_sector_count - 1;
    }

public:
    Bitmap(const Geometry& geometry, SectorHandle sector)
        : m_geometry(geometry)
        , m_sector(sector)
        , m_cache(m_sector, layout::g_bitmap, (geometry.data_sector_count + 1U) / 2U) {}

    void load() {
        m_cache.load();
        m_head = _find_head();
    }

    void load_erased() {
        m_cache.load_erased();
        m_head = std::nullopt;
    }

    void unload() { m_cache.unload(); }

    bool is_used(std::size_t idx) const { return _read_flags(idx) & Used; }

    void advance_head() {
        assert(!all_used());
        if (empty()) {
            _mark_flags(0, Used);
            m_head = 0;
            return;
        }
        _mark_flags(*m_head + 1, Used);
        (*m_head)++;
    }

    bool is_full_and_synced(std::size_t idx) const { return _read_flags(idx) & FullAndSynced; }
    void mark_full_and_synced(std::size_t idx) { _mark_flags(idx, FullAndSynced); }

    bool is_disposable(std::size_t idx) const { return _read_flags(idx) & Disposable; }
    void mark_disposable(std::size_t idx) { _mark_flags(idx, Disposable); }

    std::size_t count_used() const {
        std::size_t count = 0;
        for (std::size_t i = 0; i < m_geometry.data_sector_count; ++i)
            count += is_used(i) ? 1U : 0U;
        return count;
    }

    Pattern pattern() const {
        const std::size_t size = (m_geometry.data_sector_count + 1U) / 2U;
        bool all_ones = true;
        bool all_zeros = true;
        for (std::size_t i = 0; i < size; ++i) {
            const std::uint8_t val = m_cache.read(i);
            all_ones &= (val == 0xFF);
            all_zeros &= (val == 0x00);
            if (!all_ones && !all_zeros)
                return Pattern::Partial;
        }
        if (all_ones)
            return Pattern::AllOnes;
        if (all_zeros)
            return Pattern::AllZeros;
        return Pattern::Partial;
    }

    void mark_all_full_and_synced() {
        const std::size_t size = (m_geometry.data_sector_count + 1U) / 2U;
        for (std::size_t i = 0; i < size; ++i)
            m_cache.write(i, 0x00);
        if (m_geometry.data_sector_count == 0)
            m_head = std::nullopt;
        else
            m_head = m_geometry.data_sector_count - 1;
    }

    bool empty() const { return !m_head; }
    bool all_used() const { return m_head && (*m_head + 1) >= m_geometry.data_sector_count; }
    size_t head() const { return *m_head; }
};

} // namespace bricks::chronicler::detail
