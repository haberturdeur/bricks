#pragma once

#include "bricks/chronicler/bitmap.hpp"

#include <algorithm>
#include <array>
#include <vector>
#include <optional>

namespace bricks::chronicler::detail {

class MetadataSector {
private:
    Geometry m_geometry;
    SectorHandle m_sector;
    Bitmap m_bitmap;
    bool m_old = false;

    void _format() {
        m_sector.write(layout::g_magic, g_magic);
        m_sector.write(layout::g_version, g_version);
        m_sector.write(layout::g_entry_size, m_geometry.entry_size);
    }

    void _mark_initialized() {
        m_sector.write(layout::g_initialized, 0U);
        m_bitmap.load_erased();
    }

public:
    MetadataSector(const Geometry& geometry, SectorHandle sector)
        : m_geometry(geometry)
        , m_sector(sector)
        , m_bitmap(geometry, sector) {}

    static std::optional<MetadataSector> load(const Geometry& geometry, PartitionHandle partition, std::size_t idx) {
        SectorHandle sector(partition, idx);
        bool initialized = sector.read(layout::g_magic) == g_magic
                        && sector.read(layout::g_version) == g_version
                        && sector.read(layout::g_entry_size) == geometry.entry_size
                        && sector.read(layout::g_initialized) == 0;
        if (!initialized)
            return std::nullopt;
        MetadataSector out(geometry, sector);
        out.m_old = sector.read(layout::g_old) == 0;
        if (!out.m_old)
            out.bitmap().load();
        return out;
    }

    static MetadataSector create(const Geometry& geometry, PartitionHandle partition, std::size_t idx) {
        SectorHandle sector(partition, idx);
        MetadataSector out(geometry, sector);
        out.erase();
        out._format();
        out._mark_initialized();
        return out;
    }

    void erase() {
        m_sector.erase();
        m_old = false;
        m_bitmap.unload();
    }

    bool is_old() const { return m_old; }
    void mark_old() {
        m_sector.write(layout::g_old, 0U);
        m_old = true;
    }

    Bitmap& bitmap() { return m_bitmap; }
    const Bitmap& bitmap() const { return m_bitmap; }
};

class Metadata {
private:
    Geometry m_geometry;
    PartitionHandle m_partition;
    std::array<std::optional<MetadataSector>, 2> m_slots;
    std::size_t m_active_slot = 0;

    std::optional<MetadataSector>& _active_slot() { return m_slots[m_active_slot]; }
    const std::optional<MetadataSector>& _active_slot() const { return m_slots[m_active_slot]; }

    void _switch_slot() {
        const std::size_t previous_slot = m_active_slot;
        if (m_slots[previous_slot])
            m_slots[previous_slot]->mark_old();
        m_active_slot = (m_active_slot + 1) % 2;
        _active_slot().emplace(MetadataSector::create(m_geometry, m_partition, m_active_slot));
    }

    bool _choose_slot() {
        for (std::size_t i = 0; i < 2; i++)
            m_slots[i] = MetadataSector::load(m_geometry, m_partition, i);
        uint8_t initialized = ((bool)m_slots[0]) | (((bool)m_slots[1]) << 1);
        if (initialized == 0)
            return false;
        if (initialized == 0b11) {
            const bool slot0_old = m_slots[0]->is_old();
            const bool slot1_old = m_slots[1]->is_old();
            if (slot0_old == slot1_old)
                return false;
            m_active_slot = slot0_old ? 1 : 0;
            return true;
        }
        m_active_slot = initialized >> 1;
        if (_active_slot()->is_old())
            _switch_slot();
        return true;
    }

public:
    Metadata(const Geometry& geometry, PartitionHandle partition)
        : m_geometry(geometry)
        , m_partition(partition) {}

    static Metadata create(const Geometry& geometry, PartitionHandle partition) {
        partition.erase_sectors(1, 1);
        Metadata out(geometry, partition);
        out._active_slot().emplace(MetadataSector::create(geometry, partition, 0));
        assert(geometry.data_sector_count > 0);
        out.advance_head();
        return out;
    }

    static std::optional<Metadata> load(const Geometry& geometry, PartitionHandle partition) {
        Metadata out(geometry, partition);
        if (!out._choose_slot())
            return std::nullopt;
        out._active_slot()->bitmap().load();
        return out;
    }

    std::size_t head() const { return _active_slot()->bitmap().head(); }
    bool is_sector_used(std::size_t idx) const {
        const auto& slot = _active_slot();
        if (!slot || idx >= m_geometry.data_sector_count)
            return false;
        return slot->bitmap().is_used(idx);
    }

    bool mark_full_and_synced(std::size_t idx) {
        auto& slot = _active_slot();
        if (!slot || idx >= m_geometry.data_sector_count)
            return false;
        if (slot->bitmap().is_full_and_synced(idx))
            return false;
        slot->bitmap().mark_full_and_synced(idx);
        return true;
    }

    void advance_head() {
        if (_active_slot()->bitmap().all_used())
            _switch_slot();
        _active_slot()->bitmap().advance_head();
    }
};

inline std::vector<std::size_t> collect_used_sector_indices(const Metadata& metadata, const Geometry& geometry) {
    std::vector<std::size_t> indices;
    if (geometry.data_sector_count == 0)
        return indices;
    const std::size_t head = metadata.head();
    if (!metadata.is_sector_used(head))
        return indices;
    indices.push_back(head);
    std::size_t cursor = (head + geometry.data_sector_count - 1) % geometry.data_sector_count;
    std::size_t steps = 1;
    while (steps < geometry.data_sector_count && metadata.is_sector_used(cursor)) {
        indices.push_back(cursor);
        cursor = (cursor + geometry.data_sector_count - 1) % geometry.data_sector_count;
        steps++;
    }
    std::reverse(indices.begin(), indices.end());
    return indices;
}

} // namespace bricks::chronicler::detail
