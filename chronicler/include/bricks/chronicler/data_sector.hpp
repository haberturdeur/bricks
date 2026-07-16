#pragma once

#include "bricks/chronicler/geometry.hpp"
#include "bricks/flash_utils.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <optional>
#include <span>
#include <limits>

namespace bricks::chronicler::detail {

class DataSector {
private:
    Geometry m_geometry;
    std::size_t m_idx;
    SectorHandle m_sector;
    std::size_t m_size = 0;
    std::size_t m_write_offset = 0;
    bool m_sealed = false;
    std::uint8_t m_session_id = 0xFF;
    std::uint8_t m_sector_flags = 0xFF;
    std::uint32_t m_first_entry_id = 0;
    std::uint8_t m_commit_marker = 0xFF;
    std::uint8_t m_generation = 0xFF;
    bool m_committed = false;
    mutable std::size_t m_cached_index = std::numeric_limits<std::size_t>::max();
    mutable std::size_t m_cached_offset = 0;

    static uint8_t _crc8_update(uint8_t crc, uint8_t data) {
        crc ^= data;
        for (int i = 0; i < 8; ++i)
            crc = (crc & 0x80U) ? static_cast<uint8_t>((crc << 1U) ^ 0x07U)
                               : static_cast<uint8_t>(crc << 1U);
        return crc;
    }

    static uint8_t _crc8_seed_for_length(std::uint16_t length) {
        uint8_t crc = 0;
        crc = _crc8_update(crc, static_cast<uint8_t>(length & 0xFFU));
        crc = _crc8_update(crc, static_cast<uint8_t>((length >> 8) & 0x0FU));
        return crc;
    }

    static uint8_t _crc8_compute(std::uint16_t length, std::span<const std::uint8_t> payload) {
        uint8_t crc = _crc8_seed_for_length(length);
        for (auto byte : payload)
            crc = _crc8_update(crc, byte);
        return crc;
    }

    uint8_t _crc8_compute_flash(std::uint16_t length, std::size_t payload_offset) const {
        uint8_t crc = _crc8_seed_for_length(length);
        std::array<std::uint8_t, 64> buf{};
        std::size_t remaining = length;
        std::size_t offset = payload_offset;
        while (remaining > 0) {
            const std::size_t chunk = remaining < buf.size() ? remaining : buf.size();
            m_sector.read(offset, { buf.data(), chunk });
            for (std::size_t i = 0; i < chunk; ++i)
                crc = _crc8_update(crc, buf[i]);
            offset += chunk;
            remaining -= chunk;
        }
        return crc;
    }

    static bool _flag_set(std::uint16_t length_flags, std::uint16_t flag_bit) {
        return (length_flags & flag_bit) == 0;
    }

    std::uint16_t _read_length_flags(std::size_t offset) const {
        std::uint8_t bytes[2]{};
        m_sector.read(offset, { bytes, sizeof(bytes) });
        return static_cast<std::uint16_t>(bytes[0] | (bytes[1] << 8));
    }

    void _write_length_flags(std::size_t offset, std::uint16_t length_flags) {
        std::uint8_t bytes[2]{};
        bytes[0] = static_cast<std::uint8_t>(length_flags & 0xFFU);
        bytes[1] = static_cast<std::uint8_t>((length_flags >> 8) & 0xFFU);
        m_sector.write(offset, { bytes, sizeof(bytes) });
    }

    static std::uint8_t _msb_mask_for_flag(std::uint16_t flag_bit) {
        switch (flag_bit) {
        case Geometry::flag_should_sync:
            return 0x10U;
        case Geometry::flag_synced:
            return 0x20U;
        case Geometry::flag_crc_escaped:
            return 0x40U;
        case Geometry::flag_entry_disposable:
            return 0x80U;
        default:
            return 0x00U;
        }
    }

    void _clear_flag(std::size_t record_offset, std::uint16_t flag_bit) {
        const std::uint8_t bit = _msb_mask_for_flag(flag_bit);
        const std::uint8_t mask = static_cast<std::uint8_t>(~bit);
        m_sector.write_byte(record_offset + 1, mask);
    }

    void _load() {
        m_session_id = m_sector.read_byte(Geometry::sector_session_offset);
        m_sector_flags = m_sector.read_byte(Geometry::sector_flags_offset);
        m_first_entry_id = m_sector.read(Geometry::sector_first_entry_id_offset);
        m_commit_marker = m_sector.read_byte(Geometry::sector_commit_offset);
        m_generation = Geometry::sector_commit_generation(m_commit_marker);
        m_committed = m_generation != 0xFF && m_first_entry_id != 0;
        m_size = 0;
        m_sealed = !m_committed;
        m_write_offset = m_geometry.data_offset;
        m_cached_index = std::numeric_limits<std::size_t>::max();
        m_cached_offset = 0;

        if (!m_committed)
            return;

        std::size_t cursor = m_geometry.data_offset;
        while (cursor + Geometry::length_header_size <= m_geometry.sector_size) {
            std::uint8_t header[Geometry::length_header_size]{};
            m_sector.read(cursor, { header, sizeof(header) });
            const std::uint16_t length_flags = static_cast<std::uint16_t>(header[0] | (header[1] << 8));
            const std::uint16_t length = static_cast<std::uint16_t>(length_flags & Geometry::length_mask);
            if (length_flags == 0xFFFFU) {
                m_write_offset = cursor;
                return;
            }

            if (length == 0 || length > Geometry::max_entry_size) {
                m_write_offset = cursor;
                m_sealed = true;
                return;
            }

            const std::size_t record_size = Geometry::record_overhead + length;
            if (cursor + record_size > m_geometry.sector_size) {
                m_write_offset = cursor;
                m_sealed = true;
                return;
            }

            const std::uint8_t crc_byte =
                m_sector.read_byte(cursor + Geometry::length_header_size + length);
            if (crc_byte == 0xFFU) {
                m_write_offset = cursor;
                m_sealed = true;
                return;
            }

            std::uint8_t stored_crc = crc_byte;
            if (_flag_set(length_flags, Geometry::flag_crc_escaped)) {
                if (stored_crc != 0xFEU) {
                    m_write_offset = cursor;
                    m_sealed = true;
                    return;
                }
                stored_crc = 0xFFU;
            }

            const std::uint8_t expected_crc =
                _crc8_compute_flash(length, cursor + Geometry::length_header_size);
            if (stored_crc != expected_crc) {
                m_write_offset = cursor;
                m_sealed = true;
                return;
            }

            m_size++;
            cursor += record_size;
        }

        m_write_offset = cursor;
        if (cursor + Geometry::record_overhead > m_geometry.sector_size)
            m_sealed = true;
    }

    void _format(std::uint8_t session_id,
                 std::uint8_t sector_flags,
                 std::uint32_t first_entry_id,
                 std::uint8_t generation) {
        m_sector.erase();
        m_sector.write_byte(Geometry::sector_session_offset, session_id);
        m_sector.write_byte(Geometry::sector_flags_offset, sector_flags);
        m_sector.write(Geometry::sector_first_entry_id_offset, first_entry_id);
        generation &= 1U;
        const std::uint8_t commit_marker = Geometry::sector_commit_marker(generation);
        m_sector.write_byte(Geometry::sector_commit_offset, commit_marker);
        m_session_id = session_id;
        m_sector_flags = sector_flags;
        m_first_entry_id = first_entry_id;
        m_commit_marker = commit_marker;
        m_generation = generation;
        m_committed = true;
        m_size = 0;
        m_sealed = false;
        m_write_offset = m_geometry.data_offset;
        m_cached_index = std::numeric_limits<std::size_t>::max();
        m_cached_offset = 0;
    }

    std::optional<std::size_t> _locate_record(std::size_t idx,
                                              std::uint16_t& length_flags,
                                              std::uint16_t& length) const {
        if (idx >= m_size)
            return std::nullopt;

        std::size_t cursor = m_geometry.data_offset;
        std::size_t i = 0;
        if (m_cached_index != std::numeric_limits<std::size_t>::max() && idx >= m_cached_index) {
            cursor = m_cached_offset;
            i = m_cached_index;
        }
        for (; i < m_size; ++i) {
            const std::uint16_t raw = _read_length_flags(cursor);
            const std::uint16_t len = static_cast<std::uint16_t>(raw & Geometry::length_mask);
            if (i == idx) {
                length_flags = raw;
                length = len;
                m_cached_index = idx;
                m_cached_offset = cursor;
                return cursor;
            }
            cursor += Geometry::record_overhead + len;
        }
        return std::nullopt;
    }

public:
    DataSector(const Geometry& geometry, PartitionHandle partition, std::size_t idx)
        : m_geometry(geometry)
        , m_idx(idx)
        , m_sector(partition, idx + geometry.metadata_sector_count) {}

    static DataSector load(const Geometry& geometry, PartitionHandle partition, std::size_t idx) {
        DataSector out(geometry, partition, idx);
        out._load();
        return out;
    }

    static DataSector create(const Geometry& geometry,
                             PartitionHandle partition,
                             std::size_t idx,
                             std::uint8_t session_id = 0,
                             std::uint8_t sector_flags = 0,
                             std::uint32_t first_entry_id = 1,
                             std::uint8_t generation = 0) {
        DataSector out(geometry, partition, idx);
        out._format(session_id, sector_flags, first_entry_id, generation);
        return out;
    }

    bool can_append(std::size_t length) const {
        if (m_sealed || length == 0 || length > Geometry::max_entry_size)
            return false;
        return m_write_offset + Geometry::record_overhead + length <= m_geometry.sector_size;
    }

    void push(std::span<const std::uint8_t> data, bool should_sync) {
        assert(can_append(data.size()));

        const std::uint16_t length = static_cast<std::uint16_t>(data.size());
        std::uint8_t crc = _crc8_compute(length, data);

        std::uint16_t length_flags = static_cast<std::uint16_t>(length & Geometry::length_mask);
        length_flags |= Geometry::flag_mask;
        if (should_sync)
            length_flags &= static_cast<std::uint16_t>(~Geometry::flag_should_sync);
        if (crc == 0xFFU) {
            length_flags &= static_cast<std::uint16_t>(~Geometry::flag_crc_escaped);
            crc = 0xFEU;
        }

        const std::size_t record_offset = m_write_offset;
        _write_length_flags(record_offset, length_flags);
        m_sector.write(record_offset + Geometry::length_header_size, data);
        m_sector.write_byte(record_offset + Geometry::length_header_size + data.size(), crc);

        m_write_offset += Geometry::record_overhead + data.size();
        m_size++;
        m_cached_index = m_size - 1;
        m_cached_offset = record_offset;
        if (m_write_offset + Geometry::record_overhead > m_geometry.sector_size)
            m_sealed = true;
    }

    std::size_t read(std::size_t idx, std::span<std::uint8_t> data) const {
        std::uint16_t length_flags = 0;
        std::uint16_t length = 0;
        const auto offset = _locate_record(idx, length_flags, length);
        assert(offset && "index out of range");
        assert(data.size() >= length);
        m_sector.read(*offset + Geometry::length_header_size, { data.data(), length });
        return length;
    }

    std::size_t entry_size(std::size_t idx) const {
        std::uint16_t length_flags = 0;
        std::uint16_t length = 0;
        const auto offset = _locate_record(idx, length_flags, length);
        assert(offset && "index out of range");
        return length;
    }

    std::size_t size() const { return m_size; }
    std::size_t idx() const { return m_idx; }
    bool sealed() const { return m_sealed; }
    bool committed() const { return m_committed; }
    bool committed(std::uint8_t generation) const {
        return m_committed && m_generation == (generation & 1U);
    }
    bool can_complete_commit(std::uint8_t generation) const {
        const auto target = Geometry::sector_commit_marker(generation);
        return m_first_entry_id != 0 && (m_commit_marker & target) == target;
    }
    void complete_commit(std::uint8_t generation) {
        assert(can_complete_commit(generation));
        m_sector.write_byte(Geometry::sector_commit_offset,
                            Geometry::sector_commit_marker(generation));
        _load();
    }
    std::uint32_t first_entry_id() const { return m_first_entry_id; }
    static std::uint32_t advance_entry_id(std::uint32_t entry_id, std::size_t count) {
        constexpr std::uint64_t id_count = std::numeric_limits<std::uint32_t>::max();
        if (entry_id == 0)
            entry_id = 1;
        const auto offset = static_cast<std::uint64_t>(count) % id_count;
        return static_cast<std::uint32_t>(
            ((static_cast<std::uint64_t>(entry_id) - 1U + offset) % id_count) + 1U);
    }
    std::uint32_t entry_id(std::size_t idx) const {
        assert(idx < m_size);
        return advance_entry_id(m_first_entry_id, idx);
    }
    std::uint32_t next_entry_id() const { return advance_entry_id(m_first_entry_id, m_size); }

    bool should_sync(std::size_t idx) const {
        std::uint16_t length_flags = 0;
        std::uint16_t length = 0;
        const auto offset = _locate_record(idx, length_flags, length);
        assert(offset && "index out of range");
        return _flag_set(length_flags, Geometry::flag_should_sync);
    }

    bool is_synced(std::size_t idx) const {
        std::uint16_t length_flags = 0;
        std::uint16_t length = 0;
        const auto offset = _locate_record(idx, length_flags, length);
        assert(offset && "index out of range");
        if (!_flag_set(length_flags, Geometry::flag_should_sync))
            return true;
        return _flag_set(length_flags, Geometry::flag_synced);
    }

    void mark_synced(std::size_t idx) {
        std::uint16_t length_flags = 0;
        std::uint16_t length = 0;
        const auto offset = _locate_record(idx, length_flags, length);
        assert(offset && "index out of range");
        if (!_flag_set(length_flags, Geometry::flag_should_sync))
            return;
        if (_flag_set(length_flags, Geometry::flag_synced))
            return;
        _clear_flag(*offset, Geometry::flag_synced);
    }

    bool is_entry_disposable(std::size_t idx) const {
        std::uint16_t length_flags = 0;
        std::uint16_t length = 0;
        const auto offset = _locate_record(idx, length_flags, length);
        assert(offset && "index out of range");
        return _flag_set(length_flags, Geometry::flag_entry_disposable);
    }

    void mark_entry_disposable(std::size_t idx) {
        std::uint16_t length_flags = 0;
        std::uint16_t length = 0;
        const auto offset = _locate_record(idx, length_flags, length);
        assert(offset && "index out of range");
        if (_flag_set(length_flags, Geometry::flag_entry_disposable))
            return;
        _clear_flag(*offset, Geometry::flag_entry_disposable);
    }

    bool all_entries_disposable() const {
        if (m_size == 0)
            return false;
        std::size_t cursor = m_geometry.data_offset;
        for (std::size_t i = 0; i < m_size; ++i) {
            const std::uint16_t length_flags = _read_length_flags(cursor);
            if (!_flag_set(length_flags, Geometry::flag_entry_disposable))
                return false;
            const std::uint16_t length = static_cast<std::uint16_t>(length_flags & Geometry::length_mask);
            cursor += Geometry::record_overhead + length;
        }
        return true;
    }

    std::optional<std::size_t> find_unsynced() const {
        std::size_t cursor = m_geometry.data_offset;
        for (std::size_t i = 0; i < m_size; ++i) {
            const std::uint16_t length_flags = _read_length_flags(cursor);
            const std::uint16_t length = static_cast<std::uint16_t>(length_flags & Geometry::length_mask);
            if (_flag_set(length_flags, Geometry::flag_should_sync)
                && !_flag_set(length_flags, Geometry::flag_synced))
                return i;
            cursor += Geometry::record_overhead + length;
        }
        return std::nullopt;
    }

    bool all_required_synced() const {
        std::size_t cursor = m_geometry.data_offset;
        for (std::size_t i = 0; i < m_size; ++i) {
            const std::uint16_t length_flags = _read_length_flags(cursor);
            const std::uint16_t length = static_cast<std::uint16_t>(length_flags & Geometry::length_mask);
            if (_flag_set(length_flags, Geometry::flag_should_sync)
                && !_flag_set(length_flags, Geometry::flag_synced))
                return false;
            cursor += Geometry::record_overhead + length;
        }
        return true;
    }

    std::uint8_t session_id() const { return m_session_id; }
    std::uint8_t sector_flags() const { return m_sector_flags; }
};

} // namespace bricks::chronicler::detail
