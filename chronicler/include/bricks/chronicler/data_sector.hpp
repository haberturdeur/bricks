#pragma once

#include "bricks/chronicler/geometry.hpp"
#include "bricks/flash_utils.hpp"

#include <cassert>
#include <optional>
#include <span>

namespace bricks::chronicler::detail {

class DataSector {
public:
    enum Flags : std::uint8_t {
        Started    = 1U << 0,
        Finished   = 1U << 1,
        ShouldSync = 1U << 2,
        Synced     = 1U << 3,
    };

private:
    Geometry m_geometry;
    std::size_t m_idx;
    SectorHandle m_sector;
    Cache m_cache;
    std::size_t m_size = 0;
    bool m_sealed = false;

    std::size_t _data_start_relative(std::size_t entry_idx) const {
        return m_geometry.data_offset + entry_idx * m_geometry.entry_size;
    }

    void _write_flags(std::size_t idx, std::uint8_t flags) {
        flags &= 0b1111;
        std::uint8_t target;
        if (idx % 2 == 0) {
            std::uint8_t nibble = static_cast<std::uint8_t>(~flags) & 0x0F;
            target = static_cast<std::uint8_t>(nibble | 0xF0);
        } else {
            std::uint8_t nibble = static_cast<std::uint8_t>(~flags) & 0x0F;
            target = static_cast<std::uint8_t>((nibble << 4) | 0x0F);
        }
        std::uint8_t current = m_cache.read(idx / 2);
        std::uint8_t next = static_cast<std::uint8_t>(current & target);
        m_cache.write(idx / 2, next);
    }

    std::uint8_t _read_flags(std::size_t idx) const {
        std::uint8_t flags = m_cache.read(idx / 2);
        flags = ~flags;
        if (idx % 2 == 1)
            flags >>= 4;
        flags &= 0b1111;
        return flags;
    }

    void _ensure_flags(std::size_t idx, std::uint8_t flags) {
        std::uint8_t current = _read_flags(idx);
        if ((current & flags) == flags)
            return;
        _write_flags(idx, current | flags);
    }

    void _start_push(std::size_t idx, bool should_sync) {
        std::uint8_t flags = Started;
        if (should_sync)
            flags |= ShouldSync;
        _write_flags(idx, flags);
    }

    void _write_payload(std::size_t idx, std::span<std::uint8_t> data) {
        m_sector.write(_data_start_relative(idx), data);
    }

    void _finish_push(std::size_t idx) { _ensure_flags(idx, Finished); }

    void _load() {
        m_cache.load();
        for (std::size_t i = 0; i < capacity(); i++) {
            const std::uint8_t flags = _read_flags(i);
            if (!(flags & Started) || !(flags & Finished)) {
                m_size = i;
                m_sealed = (flags & Started) && !(flags & Finished);
                return;
            }
        }
        m_size = m_geometry.sector_capacity;
    }

    void _format() {
        m_sector.erase();
        m_cache.load_erased();
        m_size = 0;
        m_sealed = false;
    }

public:
    DataSector(const Geometry& geometry, PartitionHandle partition, std::size_t idx)
        : m_geometry(geometry)
        , m_idx(idx)
        , m_sector(partition, idx + geometry.metadata_sector_count)
        , m_cache(m_sector, 0, geometry.data_offset) {}

    static DataSector load(const Geometry& geometry, PartitionHandle partition, std::size_t idx) {
        DataSector out(geometry, partition, idx);
        out._load();
        return out;
    }

    static DataSector create(const Geometry& geometry, PartitionHandle partition, std::size_t idx) {
        DataSector out(geometry, partition, idx);
        out._format();
        return out;
    }

    void push(std::span<std::uint8_t> data, bool should_sync) {
        assert(!m_sealed);
        assert(m_size < m_geometry.sector_capacity);
        _start_push(m_size, should_sync);
        _write_payload(m_size, data);
        _finish_push(m_size);
        m_size++;
    }

    void read(std::size_t idx, std::span<std::uint8_t> data) const {
        assert(idx < m_size);
        m_sector.read(_data_start_relative(idx), data);
    }

    std::size_t capacity() const { return m_geometry.sector_capacity; }
    std::size_t size() const { return m_size; }
    std::size_t idx() const { return m_idx; }
    bool sealed() const { return m_sealed; }

    bool should_sync(std::size_t idx) const {
        assert(idx < m_size);
        return _read_flags(idx) & ShouldSync;
    }

    bool is_synced(std::size_t idx) const {
        assert(idx < m_size);
        const std::uint8_t flags = _read_flags(idx);
        if (!(flags & ShouldSync))
            return true;
        return flags & Synced;
    }

    void mark_synced(std::size_t idx) {
        assert(idx < m_size);
        const std::uint8_t flags = _read_flags(idx);
        if (!(flags & ShouldSync) || (flags & Synced))
            return;
        _write_flags(idx, flags | Synced);
    }

    std::optional<std::size_t> find_unsynced() const {
        for (std::size_t i = 0; i < m_size; ++i) {
            const std::uint8_t flags = _read_flags(i);
            if ((flags & ShouldSync) && !(flags & Synced))
                return i;
        }
        return std::nullopt;
    }

    bool all_required_synced() const {
        for (std::size_t i = 0; i < m_size; ++i) {
            const std::uint8_t flags = _read_flags(i);
            if ((flags & ShouldSync) && !(flags & Synced))
                return false;
        }
        return true;
    }
};

} // namespace bricks::chronicler::detail
