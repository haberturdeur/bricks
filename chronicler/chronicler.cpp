#include "bricks/chronicler.hpp"

namespace bricks::chronicler {

using detail::collect_used_sector_indices;

Chronicler::Chronicler(detail::Geometry geometry,
                       PartitionHandle partition,
                       detail::Metadata&& metadata,
                       detail::DataSector&& data_sector)
    : m_geometry(geometry)
    , m_partition(partition)
    , m_metadata(std::move(metadata))
    , m_active_sector(std::move(data_sector)) {}

Chronicler::Chronicler(Chronicler&&) noexcept = default;

std::optional<Chronicler> Chronicler::load(PartitionHandle partition, std::size_t entry_size) {
    detail::Geometry geometry(entry_size, partition);
    std::optional<detail::Metadata> metadata = detail::Metadata::load(geometry, partition);
    if (!metadata)
        return std::nullopt;

    detail::DataSector active = detail::DataSector::load(geometry, partition, metadata->head());

    return Chronicler(geometry, partition, std::move(*metadata), std::move(active));
}

Chronicler Chronicler::create(PartitionHandle partition, std::size_t entry_size) {
    detail::Geometry geometry(entry_size, partition);
    detail::Metadata metadata = detail::Metadata::create(geometry, partition);

    return Chronicler(geometry,
                      partition,
                      std::move(metadata),
                      detail::DataSector::create(geometry, partition, metadata.head()));
}

Chronicler Chronicler::load_or_create(PartitionHandle partition, std::size_t entry_size) {
    std::optional<Chronicler> loaded = load(partition, entry_size);
    if (loaded)
        return std::move(*loaded);

    return create(partition, entry_size);
}

void Chronicler::push(std::span<std::uint8_t> data, bool should_sync) {
    assert(data.size() == m_geometry.entry_size);

    if (m_active_sector->size() == m_active_sector->capacity()) {
        m_metadata.advance_head();
        m_active_sector.emplace(detail::DataSector::create(m_geometry, m_partition, m_metadata.head()));
    }

    m_active_sector->push(data, should_sync);

    if (should_sync && m_sync_callback)
        m_sync_callback(*this, data, m_sync_ctx);
}

void Chronicler::read(std::size_t idx, std::span<std::uint8_t> data) const {
    assert(data.size() == m_geometry.entry_size);

    std::size_t remaining = idx;
    for (auto sector_idx : collect_used_sector_indices(m_metadata, m_geometry)) {
        bool is_head = sector_idx == m_metadata.head();
        if (is_head) {
            const std::size_t sector_size = m_active_sector->size();
            if (remaining >= sector_size) {
                remaining -= sector_size;
                continue;
            }

            m_active_sector->read(remaining, data);
            return;
        }

        detail::DataSector sector = detail::DataSector::load(m_geometry, m_partition, sector_idx);
        const std::size_t sector_size = sector.size();
        if (remaining >= sector_size) {
            remaining -= sector_size;
            continue;
        }

        sector.read(remaining, data);
        return;
    }

    assert(false && "index out of range");
}

void Chronicler::mark_synced(std::size_t idx) {
    std::size_t remaining = idx;
    for (auto sector_idx : collect_used_sector_indices(m_metadata, m_geometry)) {
        bool is_head = sector_idx == m_metadata.head();
        if (is_head) {
            const std::size_t sector_size = m_active_sector->size();
            if (remaining >= sector_size) {
                remaining -= sector_size;
                continue;
            }

            m_active_sector->mark_synced(remaining);
            return;
        }

        detail::DataSector sector = detail::DataSector::load(m_geometry, m_partition, sector_idx);
        const std::size_t sector_size = sector.size();
        if (remaining >= sector_size) {
            remaining -= sector_size;
            continue;
        }

        sector.mark_synced(remaining);
        return;
    }

    assert(false && "index out of range");
}

bool Chronicler::is_synced(std::size_t idx) const {
    std::size_t remaining = idx;
    for (auto sector_idx : collect_used_sector_indices(m_metadata, m_geometry)) {
        bool is_head = sector_idx == m_metadata.head();
        if (is_head) {
            const std::size_t sector_size = m_active_sector->size();
            if (remaining >= sector_size) {
                remaining -= sector_size;
                continue;
            }

            return m_active_sector->is_synced(remaining);
        }

        detail::DataSector sector = detail::DataSector::load(m_geometry, m_partition, sector_idx);
        const std::size_t sector_size = sector.size();
        if (remaining >= sector_size) {
            remaining -= sector_size;
            continue;
        }

        return sector.is_synced(remaining);
    }

    assert(false && "index out of range");
    return false;
}

std::optional<std::size_t> Chronicler::get_unsynced() const {
    std::size_t base = 0;
    for (auto sector_idx : collect_used_sector_indices(m_metadata, m_geometry)) {
        bool is_head = sector_idx == m_metadata.head();
        if (is_head) {
            if (auto local = m_active_sector->find_unsynced())
                return base + *local;
            base += m_active_sector->size();
        } else {
            detail::DataSector sector = detail::DataSector::load(m_geometry, m_partition, sector_idx);
            if (auto local = sector.find_unsynced())
                return base + *local;
            base += sector.size();
        }
    }

    return std::nullopt;
}

void Chronicler::set_sync_callback(SyncCallback callback, void* ctx) {
    m_sync_callback = callback;
    m_sync_ctx = ctx;
}

std::size_t Chronicler::size() const {
    std::size_t total = 0;
    for (auto sector_idx : collect_used_sector_indices(m_metadata, m_geometry)) {
        if (sector_idx == m_metadata.head())
            total += m_active_sector->size();
        else {
            detail::DataSector sector = detail::DataSector::load(m_geometry, m_partition, sector_idx);
            total += sector.size();
        }
    }

    return total;
}

bool Chronicler::sweep_synced_sector() {
    const auto indices = collect_used_sector_indices(m_metadata, m_geometry);
    if (indices.empty())
        return false;

    std::size_t start = m_last_gc_sector % indices.size();
    for (std::size_t offset = 0; offset < indices.size(); ++offset) {
        const std::size_t idx = indices[(start + offset) % indices.size()];
        bool is_head = idx == m_metadata.head();

        bool ready = false;
        if (is_head)
            ready = m_active_sector->all_required_synced();
        else {
            detail::DataSector sector = detail::DataSector::load(m_geometry, m_partition, idx);
            ready = sector.all_required_synced();
        }

        if (ready && m_metadata.mark_full_and_synced(idx)) {
            m_last_gc_sector = (start + offset + 1) % indices.size();
            return true;
        }
    }

    m_last_gc_sector = 0;
    return false;
}

} // namespace bricks::chronicler
