#pragma once

#include "bricks/chronicler/data_sector.hpp"
#include "bricks/chronicler/metadata.hpp"

#include <cstdint>
#include <limits>
#include <mutex>
#include <optional>
#include <span>
#include <vector>

namespace bricks::chronicler {

class Chronicler {
public:
    struct EntryHandle {
        std::uint16_t sector;
        std::uint16_t index;
    };

    using SyncCallback = void(*)(Chronicler&, std::span<const std::uint8_t>, void*);

    static std::optional<Chronicler> load(PartitionHandle partition,
                                          std::uint8_t session_id,
                                          bool dispose_other_sessions);
    static Chronicler create(PartitionHandle partition,
                             std::uint8_t session_id,
                             bool dispose_other_sessions);
    static Chronicler load_or_create(PartitionHandle partition,
                                     std::uint8_t session_id,
                                     bool dispose_other_sessions);

    void push(std::span<const std::uint8_t> data, bool should_sync);
    EntryHandle push_with_handle(std::span<const std::uint8_t> data, bool should_sync);
    std::size_t read(std::size_t idx, std::span<std::uint8_t> data) const;
    std::size_t entry_size(std::size_t idx) const;

    void mark_synced(std::size_t idx);
    bool mark_synced(EntryHandle handle);
    bool is_synced(std::size_t idx) const;
    std::optional<std::size_t> get_unsynced() const;
    bool mark_entry_disposable(std::size_t idx);
    bool mark_disposable(std::size_t idx);

    void set_sync_callback(SyncCallback callback, void* ctx);
    void set_sector_flags(std::uint8_t flags);
    std::uint8_t session_id() const;
    std::uint8_t sector_flags() const;
    std::size_t size() const;
    bool sweep_synced_sector();
    bool sweep_disposable_sector();

    Chronicler(const Chronicler&) = delete;
    Chronicler& operator=(const Chronicler&) = delete;

    Chronicler(Chronicler&&) noexcept;
    Chronicler& operator=(Chronicler&&) noexcept = delete;

    ~Chronicler() = default;

private:
    detail::Geometry m_geometry;
    PartitionHandle m_partition;
    detail::Metadata m_metadata;
    std::optional<detail::DataSector> m_active_sector;
    mutable std::optional<detail::DataSector> m_cached_sector;
    mutable std::size_t m_cached_sector_idx = std::numeric_limits<std::size_t>::max();
    mutable std::vector<std::size_t> m_sector_sizes;
    mutable std::vector<bool> m_sector_sizes_valid;
    mutable std::mutex m_mutex;
    SyncCallback m_sync_callback = nullptr;
    void* m_sync_ctx = nullptr;
    std::size_t m_last_gc_sector = 0;
    std::size_t m_last_disposable_sector = 0;
    std::uint8_t m_session_id = 0;
    std::uint8_t m_next_sector_flags = 0;

    Chronicler(detail::Geometry geometry,
               PartitionHandle partition,
               detail::Metadata&& metadata,
               detail::DataSector&& data_sector,
               std::uint8_t session_id);

    void _invalidate_cache();
    detail::DataSector& _cached_sector(std::size_t idx) const;
    std::uint8_t _read_sector_session_id(std::size_t idx) const;
    bool _sector_matches_session(std::size_t idx) const;
    void _mark_other_sessions_disposable();
};

} // namespace bricks::chronicler
