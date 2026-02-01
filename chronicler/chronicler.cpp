#include "bricks/chronicler.hpp"

namespace bricks::chronicler {

using detail::collect_used_sector_indices;

Chronicler::Chronicler(detail::Geometry geometry,
                       PartitionHandle partition,
                       detail::Metadata&& metadata,
                       detail::DataSector&& data_sector,
                       std::uint8_t session_id)
    : m_geometry(geometry)
    , m_partition(partition)
    , m_metadata(std::move(metadata))
    , m_active_sector(std::move(data_sector))
    , m_sector_sizes(geometry.data_sector_count, 0)
    , m_sector_sizes_valid(geometry.data_sector_count, false) {
    m_session_id = session_id;
    if (m_active_sector) {
        if (m_active_sector->session_id() == m_session_id)
            m_next_sector_flags = m_active_sector->sector_flags();
        if (m_metadata.head() < m_sector_sizes.size()) {
            m_sector_sizes[m_metadata.head()] = m_active_sector->size();
            m_sector_sizes_valid[m_metadata.head()] = true;
        }
    }
}

Chronicler::Chronicler(Chronicler&& other) noexcept
    : m_geometry(other.m_geometry)
    , m_partition(other.m_partition)
    , m_metadata(std::move(other.m_metadata))
    , m_active_sector(std::move(other.m_active_sector))
    , m_cached_sector(std::move(other.m_cached_sector))
    , m_cached_sector_idx(other.m_cached_sector_idx)
    , m_sector_sizes(std::move(other.m_sector_sizes))
    , m_sector_sizes_valid(std::move(other.m_sector_sizes_valid))
    , m_sync_callback(other.m_sync_callback)
    , m_sync_ctx(other.m_sync_ctx)
    , m_last_gc_sector(other.m_last_gc_sector)
    , m_last_disposable_sector(other.m_last_disposable_sector)
    , m_session_id(other.m_session_id)
    , m_next_sector_flags(other.m_next_sector_flags) {
}

void Chronicler::_invalidate_cache() {
    m_cached_sector.reset();
    m_cached_sector_idx = std::numeric_limits<std::size_t>::max();
}

detail::DataSector& Chronicler::_cached_sector(std::size_t idx) const {
    if (!m_cached_sector || m_cached_sector_idx != idx) {
        m_cached_sector_idx = idx;
        m_cached_sector.emplace(detail::DataSector::load(m_geometry, m_partition, idx));
        if (idx < m_sector_sizes.size()) {
            m_sector_sizes[idx] = m_cached_sector->size();
            m_sector_sizes_valid[idx] = true;
        }
    }
    return *m_cached_sector;
}

std::uint8_t Chronicler::_read_sector_session_id(std::size_t idx) const {
    const std::size_t partition_sector = idx + m_geometry.metadata_sector_count;
    SectorHandle sector(m_partition, partition_sector);
    return sector.read_byte(0);
}

bool Chronicler::_sector_matches_session(std::size_t idx) const {
    if (idx == m_metadata.head() && m_active_sector)
        return m_active_sector->session_id() == m_session_id;
    return _read_sector_session_id(idx) == m_session_id;
}

void Chronicler::_mark_other_sessions_disposable() {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto sector_idx : collect_used_sector_indices(m_metadata, m_geometry)) {
        if (_read_sector_session_id(sector_idx) == m_session_id)
            continue;
        m_metadata.mark_disposable(sector_idx);
    }
}

std::optional<Chronicler> Chronicler::load(PartitionHandle partition,
                                           std::uint8_t session_id,
                                           bool dispose_other_sessions) {
    detail::Geometry geometry(partition);
    std::optional<detail::Metadata> metadata = detail::Metadata::load(geometry, partition);
    if (!metadata)
        return std::nullopt;

    detail::DataSector active = detail::DataSector::load(geometry, partition, metadata->head());

    Chronicler out(geometry, partition, std::move(*metadata), std::move(active), session_id);
    if (dispose_other_sessions)
        out._mark_other_sessions_disposable();
    return out;
}

Chronicler Chronicler::create(PartitionHandle partition,
                              std::uint8_t session_id,
                              bool dispose_other_sessions) {
    detail::Geometry geometry(partition);
    detail::Metadata metadata = detail::Metadata::create(geometry, partition);

    Chronicler out(geometry,
                      partition,
                      std::move(metadata),
                      detail::DataSector::create(geometry,
                                                 partition,
                                                 metadata.head(),
                                                 session_id,
                                                 0),
                      session_id);
    if (dispose_other_sessions)
        out._mark_other_sessions_disposable();
    return out;
}

Chronicler Chronicler::load_or_create(PartitionHandle partition,
                                      std::uint8_t session_id,
                                      bool dispose_other_sessions) {
    std::optional<Chronicler> loaded = load(partition, session_id, dispose_other_sessions);
    if (loaded)
        return std::move(*loaded);

    return create(partition, session_id, dispose_other_sessions);
}

void Chronicler::push(std::span<const std::uint8_t> data, bool should_sync) {
    (void)push_with_handle(data, should_sync);
}

Chronicler::EntryHandle Chronicler::push_with_handle(std::span<const std::uint8_t> data, bool should_sync) {
    assert(data.size() > 0);
    assert(data.size() <= detail::Geometry::max_entry_size);

    SyncCallback callback = nullptr;
    void* callback_ctx = nullptr;
    EntryHandle handle{};
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (!m_active_sector->can_append(data.size())
            || m_active_sector->session_id() != m_session_id) {
            _invalidate_cache();
            m_metadata.advance_head();
            m_active_sector.emplace(detail::DataSector::create(m_geometry,
                                                               m_partition,
                                                               m_metadata.head(),
                                                               m_session_id,
                                                               m_next_sector_flags));
            const auto head_idx = m_metadata.head();
            if (head_idx < m_sector_sizes.size()) {
                m_sector_sizes[head_idx] = 0;
                m_sector_sizes_valid[head_idx] = true;
            }
        }

        const std::size_t local_index = m_active_sector->size();
        assert(m_metadata.head() <= std::numeric_limits<std::uint16_t>::max());
        assert(local_index <= std::numeric_limits<std::uint16_t>::max());
        handle.sector = static_cast<std::uint16_t>(m_metadata.head());
        handle.index = static_cast<std::uint16_t>(local_index);

        m_active_sector->push(data, should_sync);
        if (m_metadata.head() < m_sector_sizes.size()) {
            m_sector_sizes[m_metadata.head()] = m_active_sector->size();
            m_sector_sizes_valid[m_metadata.head()] = true;
        }
        if (m_active_sector->sealed() && m_active_sector->all_entries_disposable())
            m_metadata.mark_disposable(m_metadata.head());

        if (should_sync && m_sync_callback) {
            callback = m_sync_callback;
            callback_ctx = m_sync_ctx;
        }
    }

    if (should_sync && callback)
        callback(*this, data, callback_ctx);
    return handle;
}

std::size_t Chronicler::read(std::size_t idx, std::span<std::uint8_t> data) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::size_t remaining = idx;
    for (auto sector_idx : collect_used_sector_indices(m_metadata, m_geometry)) {
        if (!_sector_matches_session(sector_idx))
            continue;
        bool is_head = sector_idx == m_metadata.head();
        if (is_head) {
            const std::size_t sector_size = m_active_sector->size();
            if (remaining >= sector_size) {
                remaining -= sector_size;
                continue;
            }

            return m_active_sector->read(remaining, data);
        }

        detail::DataSector* sector = nullptr;
        std::size_t sector_size = 0;
        if (sector_idx < m_sector_sizes_valid.size() && m_sector_sizes_valid[sector_idx]) {
            sector_size = m_sector_sizes[sector_idx];
        } else {
            sector = &_cached_sector(sector_idx);
            sector_size = sector->size();
        }
        if (remaining >= sector_size) {
            remaining -= sector_size;
            continue;
        }

        if (!sector)
            sector = &_cached_sector(sector_idx);
        return sector->read(remaining, data);
    }

    assert(false && "index out of range");
    return 0;
}

std::size_t Chronicler::entry_size(std::size_t idx) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::size_t remaining = idx;
    for (auto sector_idx : collect_used_sector_indices(m_metadata, m_geometry)) {
        if (!_sector_matches_session(sector_idx))
            continue;
        const bool is_head = sector_idx == m_metadata.head();
        if (is_head) {
            const std::size_t sector_size = m_active_sector->size();
            if (remaining >= sector_size) {
                remaining -= sector_size;
                continue;
            }
            return m_active_sector->entry_size(remaining);
        }

        detail::DataSector* sector = nullptr;
        std::size_t sector_size = 0;
        if (sector_idx < m_sector_sizes_valid.size() && m_sector_sizes_valid[sector_idx]) {
            sector_size = m_sector_sizes[sector_idx];
        } else {
            sector = &_cached_sector(sector_idx);
            sector_size = sector->size();
        }
        if (remaining >= sector_size) {
            remaining -= sector_size;
            continue;
        }

        if (!sector)
            sector = &_cached_sector(sector_idx);
        return sector->entry_size(remaining);
    }

    assert(false && "index out of range");
    return 0;
}

void Chronicler::mark_synced(std::size_t idx) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::size_t remaining = idx;
    for (auto sector_idx : collect_used_sector_indices(m_metadata, m_geometry)) {
        if (!_sector_matches_session(sector_idx))
            continue;
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

        detail::DataSector* sector = nullptr;
        std::size_t sector_size = 0;
        if (sector_idx < m_sector_sizes_valid.size() && m_sector_sizes_valid[sector_idx]) {
            sector_size = m_sector_sizes[sector_idx];
        } else {
            sector = &_cached_sector(sector_idx);
            sector_size = sector->size();
        }
        if (remaining >= sector_size) {
            remaining -= sector_size;
            continue;
        }

        if (!sector)
            sector = &_cached_sector(sector_idx);
        sector->mark_synced(remaining);
        return;
    }

    assert(false && "index out of range");
}

bool Chronicler::mark_synced(EntryHandle handle) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (handle.sector >= m_geometry.data_sector_count)
        return false;
    if (!m_metadata.is_sector_used(handle.sector))
        return false;
    if (_read_sector_session_id(handle.sector) != m_session_id)
        return false;

    detail::DataSector* sector = nullptr;
    if (handle.sector == m_metadata.head()) {
        sector = &*m_active_sector;
    } else {
        sector = &_cached_sector(handle.sector);
    }

    if (handle.index >= sector->size())
        return false;
    sector->mark_synced(handle.index);
    return true;
}

bool Chronicler::is_synced(std::size_t idx) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::size_t remaining = idx;
    for (auto sector_idx : collect_used_sector_indices(m_metadata, m_geometry)) {
        if (!_sector_matches_session(sector_idx))
            continue;
        bool is_head = sector_idx == m_metadata.head();
        if (is_head) {
            const std::size_t sector_size = m_active_sector->size();
            if (remaining >= sector_size) {
                remaining -= sector_size;
                continue;
            }

            return m_active_sector->is_synced(remaining);
        }

        detail::DataSector* sector = nullptr;
        std::size_t sector_size = 0;
        if (sector_idx < m_sector_sizes_valid.size() && m_sector_sizes_valid[sector_idx]) {
            sector_size = m_sector_sizes[sector_idx];
        } else {
            sector = &_cached_sector(sector_idx);
            sector_size = sector->size();
        }
        if (remaining >= sector_size) {
            remaining -= sector_size;
            continue;
        }

        if (!sector)
            sector = &_cached_sector(sector_idx);
        return sector->is_synced(remaining);
    }

    assert(false && "index out of range");
    return false;
}

std::optional<std::size_t> Chronicler::get_unsynced() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::size_t base = 0;
    for (auto sector_idx : collect_used_sector_indices(m_metadata, m_geometry)) {
        if (!_sector_matches_session(sector_idx))
            continue;
        bool is_head = sector_idx == m_metadata.head();
        if (is_head) {
            if (auto local = m_active_sector->find_unsynced())
                return base + *local;
            base += m_active_sector->size();
        } else {
            detail::DataSector& sector = _cached_sector(sector_idx);
            if (auto local = sector.find_unsynced())
                return base + *local;
            base += sector.size();
        }
    }

    return std::nullopt;
}

bool Chronicler::mark_entry_disposable(std::size_t idx) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::size_t remaining = idx;
    for (auto sector_idx : collect_used_sector_indices(m_metadata, m_geometry)) {
        if (!_sector_matches_session(sector_idx))
            continue;
        const bool is_head = sector_idx == m_metadata.head();
        detail::DataSector* sector = nullptr;
        std::size_t sector_size = 0;
        if (is_head) {
            sector = &*m_active_sector;
            sector_size = sector->size();
        } else if (sector_idx < m_sector_sizes_valid.size() && m_sector_sizes_valid[sector_idx]) {
            sector_size = m_sector_sizes[sector_idx];
        } else {
            sector = &_cached_sector(sector_idx);
            sector_size = sector->size();
        }

        if (remaining >= sector_size) {
            remaining -= sector_size;
            continue;
        }

        if (!sector)
            sector = &_cached_sector(sector_idx);
        sector->mark_entry_disposable(remaining);
        if (sector->all_entries_disposable() && (!is_head || sector->sealed()))
            m_metadata.mark_disposable(sector_idx);
        return true;
    }

    assert(false && "index out of range");
    return false;
}

bool Chronicler::mark_disposable(std::size_t idx) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::size_t remaining = idx;
    for (auto sector_idx : collect_used_sector_indices(m_metadata, m_geometry)) {
        if (!_sector_matches_session(sector_idx))
            continue;
        const bool is_head = sector_idx == m_metadata.head();
        std::size_t sector_size = 0;
        if (is_head) {
            sector_size = m_active_sector->size();
        } else if (sector_idx < m_sector_sizes_valid.size() && m_sector_sizes_valid[sector_idx]) {
            sector_size = m_sector_sizes[sector_idx];
        } else {
            sector_size = _cached_sector(sector_idx).size();
        }
        if (remaining >= sector_size) {
            remaining -= sector_size;
            continue;
        }
        return m_metadata.mark_disposable(sector_idx);
    }

    assert(false && "index out of range");
    return false;
}

void Chronicler::set_sync_callback(SyncCallback callback, void* ctx) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_sync_callback = callback;
    m_sync_ctx = ctx;
}

void Chronicler::set_sector_flags(std::uint8_t flags) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_next_sector_flags = flags;
}

std::uint8_t Chronicler::session_id() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_session_id;
}

std::uint8_t Chronicler::sector_flags() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_active_sector && m_active_sector->session_id() == m_session_id)
        return m_active_sector->sector_flags();
    return m_next_sector_flags;
}

std::size_t Chronicler::size() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_geometry.data_sector_count == 0)
        return 0;

    std::size_t total = 0;
    for (auto sector_idx : collect_used_sector_indices(m_metadata, m_geometry)) {
        if (!_sector_matches_session(sector_idx))
            continue;
        if (sector_idx == m_metadata.head()) {
            total += m_active_sector->size();
        } else if (sector_idx < m_sector_sizes_valid.size() && m_sector_sizes_valid[sector_idx]) {
            total += m_sector_sizes[sector_idx];
        } else {
            total += _cached_sector(sector_idx).size();
        }
    }

    return total;
}

bool Chronicler::sweep_synced_sector() {
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto indices = collect_used_sector_indices(m_metadata, m_geometry);
    if (indices.empty())
        return false;

    std::size_t start = m_last_gc_sector % indices.size();
    for (std::size_t offset = 0; offset < indices.size(); ++offset) {
        const std::size_t idx = indices[(start + offset) % indices.size()];
        if (!_sector_matches_session(idx))
            continue;
        bool is_head = idx == m_metadata.head();

        bool ready = false;
        if (is_head)
            ready = m_active_sector->all_required_synced();
        else {
            detail::DataSector& sector = _cached_sector(idx);
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

bool Chronicler::sweep_disposable_sector() {
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto indices = collect_used_sector_indices(m_metadata, m_geometry);
    if (indices.empty())
        return false;

    std::vector<std::size_t> filtered;
    filtered.reserve(indices.size());
    for (auto idx : indices) {
        if (_sector_matches_session(idx))
            filtered.push_back(idx);
    }
    if (filtered.empty())
        return false;

    std::size_t cursor = m_last_disposable_sector;
    if (cursor >= filtered.size())
        cursor = 0;

    const std::size_t sector_idx = filtered[cursor];
    if (sector_idx == m_metadata.head())
        return false;
    if (!m_metadata.is_disposable(sector_idx))
        return false;

    const std::size_t partition_sector = sector_idx + m_geometry.metadata_sector_count;
    m_partition.erase_sectors(partition_sector, 1);
    if (m_cached_sector && m_cached_sector_idx == sector_idx)
        _invalidate_cache();
    if (sector_idx < m_sector_sizes.size()) {
        m_sector_sizes[sector_idx] = 0;
        m_sector_sizes_valid[sector_idx] = true;
    }

    m_last_disposable_sector = (cursor + 1) % filtered.size();
    return true;
}

} // namespace bricks::chronicler
