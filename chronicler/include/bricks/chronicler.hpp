#pragma once

#include "bricks/chronicler/data_sector.hpp"
#include "bricks/chronicler/metadata.hpp"

#include <optional>
#include <span>

namespace bricks::chronicler {

class Chronicler {
public:
    using SyncCallback = void(*)(Chronicler&, std::span<std::uint8_t>, void*);

    static std::optional<Chronicler> load(PartitionHandle partition, std::size_t entry_size);
    static Chronicler create(PartitionHandle partition, std::size_t entry_size);
    static Chronicler load_or_create(PartitionHandle partition, std::size_t entry_size);

    void push(std::span<std::uint8_t> data, bool should_sync);
    void read(std::size_t idx, std::span<std::uint8_t> data) const;

    void mark_synced(std::size_t idx);
    bool is_synced(std::size_t idx) const;
    std::optional<std::size_t> get_unsynced() const;

    void set_sync_callback(SyncCallback callback, void* ctx);
    std::size_t size() const;
    bool sweep_synced_sector();

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
    SyncCallback m_sync_callback = nullptr;
    void* m_sync_ctx = nullptr;
    std::size_t m_last_gc_sector = 0;

    Chronicler(detail::Geometry geometry,
               PartitionHandle partition,
               detail::Metadata&& metadata,
               detail::DataSector&& data_sector);
};

} // namespace bricks::chronicler
