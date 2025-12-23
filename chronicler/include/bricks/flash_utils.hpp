#pragma once

#include <cstdlib>
#include <esp_err.h>
#include <esp_partition.h>
#include <spi_flash_mmap.h>

#include <sys/types.h>
#include <array>
#include <memory>
#include <span>
#include <cstdint>
#include <cassert>
#include <cstddef>
#include <cstdio>
#include <cstring>

namespace bricks::chronicler {

class PartitionHandle {
private:
    const esp_partition_t* m_partition;

    void _write_bytes(std::size_t start, const std::uint8_t* data, std::size_t size) {
#ifdef BRICKS_CHRONICLER_TESTING
        std::size_t to_write = size;
        bool skip = false;
        if (s_write_hook) {
            const WriteHookResult res = s_write_hook(start, size, s_write_ctx);
            skip = res.skip;
            to_write = res.bytes_to_write < size ? res.bytes_to_write : size;
        }
        if (skip || to_write == 0)
            return;
        ESP_ERROR_CHECK(esp_partition_write(m_partition, start, data, to_write));
#else
        ESP_ERROR_CHECK(esp_partition_write(m_partition, start, data, size));
#endif
    }

public:
#ifdef BRICKS_CHRONICLER_TESTING
    struct WriteHookResult {
        std::size_t bytes_to_write;
        bool skip;
    };

    using WriteHook = WriteHookResult(*)(std::size_t start, std::size_t size, void* ctx);
#endif

    PartitionHandle(const esp_partition_t* partition)
        : m_partition(partition) {}

    void read(std::size_t start, std::span<std::uint8_t> buf) const {
        ESP_ERROR_CHECK(esp_partition_read(m_partition, start, buf.data(), buf.size()));
    }

    uint32_t read(std::size_t start) const {
        std::uint32_t val;
        ESP_ERROR_CHECK(esp_partition_read(m_partition, start, &val, 4));
        return val;
    }

    void write(std::size_t start, std::span<const std::uint8_t> buf) {
        _write_bytes(start, buf.data(), buf.size());
    }

    void write(std::size_t start, std::uint32_t val) {
        std::array<std::uint8_t, 4> bytes{};
        std::memcpy(bytes.data(), &val, bytes.size());
        _write_bytes(start, bytes.data(), bytes.size());
    }

    void erase_range(std::size_t start, std::size_t size) {
        ESP_ERROR_CHECK(esp_partition_erase_range(m_partition, start, size));
    }

    void erase_sectors(std::size_t idx, std::size_t count) {
        erase_range(idx * sector_size(), sector_size() * count);
    }

    operator const   esp_partition_t*() const noexcept { return m_partition;             }
    const esp_partition_t* operator->() const noexcept { return m_partition;             }
    const esp_partition_t&  operator*() const noexcept { return *m_partition;            }
    const esp_partition_t*        get() const noexcept { return m_partition;             }
    esp_flash_t*           flash_chip() const noexcept { return m_partition->flash_chip; }
    esp_partition_type_t         type() const noexcept { return m_partition->type;       }
    esp_partition_subtype_t   subtype() const noexcept { return m_partition->subtype;    }
    std::size_t               address() const noexcept { return m_partition->address;    }
    std::size_t                  size() const noexcept { return m_partition->size;       }
    std::size_t           sector_size() const noexcept { return SPI_FLASH_SEC_SIZE; }
    std::size_t          sector_count() const noexcept { return size() / sector_size();  }
    const char*                 label() const noexcept { return m_partition->label;      }
    bool                    encrypted() const noexcept { return m_partition->encrypted;  }
    bool                    read_only() const noexcept { return m_partition->readonly;   }

#ifdef BRICKS_CHRONICLER_TESTING
    static inline WriteHook s_write_hook = nullptr;
    static inline void* s_write_ctx = nullptr;

    static void set_write_hook(WriteHook hook, void* ctx) {
        s_write_hook = hook;
        s_write_ctx = ctx;
    }

    static void clear_write_hook() {
        s_write_hook = nullptr;
        s_write_ctx = nullptr;
    }
#endif

    PartitionHandle(const PartitionHandle&) = default;
    PartitionHandle& operator=(const PartitionHandle&) = default;

    PartitionHandle(PartitionHandle&&) = default;
    PartitionHandle& operator=(PartitionHandle&&) = default;

    ~PartitionHandle() = default;
};

class SectorHandle {
private:
    PartitionHandle m_partition;
    std::size_t m_idx;
    std::size_t m_start;

public:
    SectorHandle(PartitionHandle partition, std::size_t idx)
        : m_partition(partition)
        , m_idx(idx)
        , m_start(idx * partition.sector_size()) {
    }

    void read(std::size_t start, std::span<std::uint8_t> buf) const {
        assert(start + buf.size() <= m_partition.sector_size()); 
        m_partition.read(m_start + start, buf);
    }

    std::uint32_t read(std::size_t start) const {
        assert(start + 4 <= m_partition.sector_size()); 
        return m_partition.read(m_start + start);
    }

    void write(std::size_t start, std::span<const std::uint8_t> buf) {
        assert(start + buf.size() <= m_partition.sector_size()); 
        m_partition.write(m_start + start, buf);
    }

    void write(std::size_t idx, std::uint32_t val) {
        assert(idx + 4 <= m_partition.sector_size());
        m_partition.write(m_start + idx, val);
    }

    void erase() {
        m_partition.erase_sectors(m_idx, 1); 
    }

    PartitionHandle partition() const noexcept { return m_partition; }
    std::size_t           idx() const noexcept { return m_idx;       }

    SectorHandle(const SectorHandle&) = default;
    SectorHandle& operator=(const SectorHandle&) = default;

    SectorHandle(SectorHandle&&) = default;
    SectorHandle& operator=(SectorHandle&&) = default;

    ~SectorHandle() = default;
};

class Cache {
private:
    SectorHandle m_sector;

    std::size_t m_start;
    std::size_t m_size;

    mutable std::unique_ptr<std::uint8_t[]> m_cache;

    void _alloc() {
        m_cache.reset(new uint8_t[m_size]);
        assert(m_cache);
    }

public:
    Cache(SectorHandle sector, std::size_t start, std::size_t size)
        : m_sector(sector)
        , m_start(start)
        , m_size(size) {
        assert(start % 4 == 0);
        assert(size % 4 == 0);
    }

    void load() {
        if (!m_cache)
            _alloc();

        m_sector.read(m_start, { m_cache.get(), m_size });
    }

    void unload() {
        m_cache.reset(nullptr);
    }

    void load_erased() {
        if (!m_cache)
            _alloc();

        std::span<std::uint8_t> cache = { m_cache.get(), m_size };
        for (auto& e : cache)
            e = 0xFF;
    }

    std::uint8_t read(std::size_t idx) const {
        if (m_cache)
            return m_cache[idx];

        std::uint32_t data = m_sector.read(idx - (idx % 4));

        return data >> (8 * (idx % 4));
    }

    void write(std::size_t idx, std::uint8_t val) {
        const std::size_t shift = 8 * (idx % 4);
        std::uint32_t data = 0xFFFFFFFF;
        data &= ~(0xFFu << shift);
        data |= static_cast<std::uint32_t>(val) << shift;

        const std::size_t addr = idx - (idx % 4);

        m_sector.write(m_start + addr, data);

        if (m_cache)
            m_cache[idx] &= val;
    }

    Cache(const Cache&) = delete;
    Cache& operator=(const Cache&) = delete;

    Cache(Cache&&) = default;
    Cache& operator=(Cache&&) = default;

    ~Cache() = default;
};

} // namespace bricks::chronicler
