#include <bricks/chronicler.hpp>
#include <bricks/chronicler/data_sector.hpp>
#include <bricks/chronicler/geometry.hpp>
#include <bricks/chronicler/metadata.hpp>

#include <esp_err.h>
#include <esp_partition.h>
#include <esp_private/partition_linux.h>
#include <sdkconfig.h>

#include <rapidcheck.h>
#include <rapidcheck/state.h>

#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>

#include <cassert>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <span>
#include <string>
#include <vector>

using namespace bricks::chronicler;

namespace {

constexpr char partition_label[] = "storage";
constexpr std::size_t flash_bytes = 4 * 1024 * 1024;
constexpr std::uint8_t session_id = 0x01;
constexpr bool dispose_other_sessions = false;

void fill_entry(std::vector<std::uint8_t>& buf, std::uint32_t seed) {
    for (std::size_t i = 0; i < buf.size(); ++i)
        buf[i] = static_cast<std::uint8_t>((seed + i * 17U) & 0xFFU);
}

std::vector<std::uint8_t> make_all_ones_bitmap(const detail::Geometry& geom) {
    const std::size_t size = (geom.data_sector_count + 1U) / 2U;
    return std::vector<std::uint8_t>(size, 0xFF);
}

void write_metadata_slot(SectorHandle& slot,
                         const std::vector<std::uint8_t>& bitmap_bytes,
                         bool old_flag) {
    slot.erase();
    slot.write(detail::layout::g_magic, detail::g_magic);
    slot.write(detail::layout::g_version, detail::g_version);
    slot.write_byte(detail::layout::g_initialized, 0x00);
    if (old_flag)
        slot.write_byte(detail::layout::g_old, 0x00);
    if (!bitmap_bytes.empty())
        slot.write(detail::layout::g_bitmap,
                   std::span<const std::uint8_t>(bitmap_bytes.data(), bitmap_bytes.size()));
}

std::string partition_table_path() {
#ifdef BUILD_DIR
    return std::string(BUILD_DIR) + "/partition_table/partition-table.bin";
#else
    return "build/partition_table/partition-table.bin";
#endif
}

std::string create_flash_image(std::size_t flash_size) {
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd)))
        std::abort();

    char path_template[PATH_MAX];
    int rc = std::snprintf(path_template, sizeof(path_template), "%s/build/flash-XXXXXX", cwd);
    if (rc < 0 || rc >= static_cast<int>(sizeof(path_template)))
        rc = std::snprintf(path_template, sizeof(path_template), "%s/flash-XXXXXX", cwd);
    if (rc < 0 || rc >= static_cast<int>(sizeof(path_template)))
        std::abort();

    int fd = mkstemp(path_template);
    if (fd < 0)
        std::abort();

    if (ftruncate(fd, static_cast<off_t>(flash_size)) != 0) {
        close(fd);
        std::abort();
    }

    std::array<std::uint8_t, 4096> fill{};
    fill.fill(0xFF);
    std::size_t remaining = flash_size;
    off_t offset = 0;
    while (remaining > 0) {
        const std::size_t chunk = remaining < fill.size() ? remaining : fill.size();
        const ssize_t wrote = pwrite(fd, fill.data(), chunk, offset);
        if (wrote < 0 || static_cast<std::size_t>(wrote) != chunk) {
            close(fd);
            std::abort();
        }
        remaining -= chunk;
        offset += static_cast<off_t>(chunk);
    }

    std::string part_path = partition_table_path();
    FILE* part = std::fopen(part_path.c_str(), "rb");
    if (!part) {
        close(fd);
        std::abort();
    }
    if (std::fseek(part, 0L, SEEK_END) != 0) {
        std::fclose(part);
        close(fd);
        std::abort();
    }
    const long part_size = std::ftell(part);
    if (part_size <= 0) {
        std::fclose(part);
        close(fd);
        std::abort();
    }
    if (std::fseek(part, 0L, SEEK_SET) != 0) {
        std::fclose(part);
        close(fd);
        std::abort();
    }
    std::vector<std::uint8_t> part_bytes(static_cast<std::size_t>(part_size));
    const size_t read_count = std::fread(part_bytes.data(), 1, part_bytes.size(), part);
    std::fclose(part);
    if (read_count != part_bytes.size()) {
        close(fd);
        std::abort();
    }
    const ssize_t part_written =
        pwrite(fd, part_bytes.data(), part_bytes.size(), CONFIG_PARTITION_TABLE_OFFSET);
    if (part_written < 0 || static_cast<std::size_t>(part_written) != part_bytes.size()) {
        close(fd);
        std::abort();
    }
    fsync(fd);
    close(fd);
    return std::string(path_template);
}

PartitionHandle prepare_partition() {
    // Use a flash image outside /tmp to avoid SIGBUS when tmpfs space is tight.
    esp_partition_file_mmap_ctrl_t* ctrl = esp_partition_get_file_mmap_ctrl_input();
    *ctrl = esp_partition_file_mmap_ctrl_t{};
    const std::string flash_path = create_flash_image(flash_bytes);
    std::strncpy(ctrl->flash_file_name, flash_path.c_str(), sizeof(ctrl->flash_file_name) - 1);
    ctrl->flash_file_name[sizeof(ctrl->flash_file_name) - 1] = '\0';
    ctrl->remove_dump = true;

    const esp_partition_t* part = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, partition_label);
    if (!part)
        part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, nullptr);

    assert(part && "host_test requires a data partition");

    PartitionHandle handle(part);
    handle.erase_range(0, handle.size());
    return handle;
}

struct Model {
    struct Entry {
        std::uint32_t seed{};
        bool should_sync{};
        bool synced{true};
    };

    std::vector<Entry> entries;
    std::size_t capacity{};
    std::size_t sector_capacity{};
    std::size_t data_sector_count{};
    std::size_t head_size{};
    bool wrapped{};

    std::size_t expected_size() const {
        if (capacity == 0 || sector_capacity == 0 || data_sector_count == 0)
            return 0;
        if (!wrapped)
            return entries.size();
        return sector_capacity * (data_sector_count - 1) + head_size;
    }
};

struct Sut {
    PartitionHandle partition;
    detail::Geometry geom;
    std::size_t entry_size{};
    std::optional<Chronicler> chron;
};

std::size_t entry_size(const Sut& sut) {
    return sut.entry_size;
}

struct SyncCallbackContext {
    std::vector<bool> decisions;
    std::size_t idx = 0;
};

struct PartialWriteContext {
    std::size_t crc_addr{};
    std::size_t payload_addr{};
    std::size_t payload_size{};
    std::size_t payload_written{};
    bool truncated_payload{};
};

PartitionHandle::WriteHookResult partial_write_hook(std::size_t start,
                                                    std::size_t size,
                                                    void* ctx) {
    auto* info = static_cast<PartialWriteContext*>(ctx);
    if (!info)
        return {size, false};
    if (!info->truncated_payload
        && start == info->payload_addr
        && size == info->payload_size) {
        info->truncated_payload = true;
        info->payload_written = size / 2;
        return {info->payload_written, false};
    }
    if (start == info->crc_addr && size == 1)
        return {0, true};
    return {size, false};
}

void sync_callback(Chronicler& chron, std::span<const std::uint8_t>, void* ctx) {
    auto* info = static_cast<SyncCallbackContext*>(ctx);
    if (!info || info->idx >= info->decisions.size())
        return;
    const bool should_mark = info->decisions[info->idx];
    if (should_mark && chron.size() > 0)
        chron.mark_synced(chron.size() - 1);
    info->idx++;
}

void push_into_model(Model& model, std::uint32_t seed, bool should_sync = false) {
    if (model.capacity == 0)
        return;
    if (model.sector_capacity == 0 || model.data_sector_count == 0)
        return;
    if (model.head_size >= model.sector_capacity) {
        model.head_size = 0;
        if (model.entries.size() >= model.capacity) {
            const auto to_remove = std::min(model.sector_capacity, model.entries.size());
            model.entries.erase(model.entries.begin(), model.entries.begin() + to_remove);
            model.wrapped = true;
        }
    }
    Model::Entry e;
    e.seed = seed;
    e.should_sync = should_sync;
    e.synced = !should_sync;
    model.entries.push_back(e);
    model.head_size++;
}

std::optional<std::size_t> first_unsynced(const Model& model) {
    for (std::size_t i = 0; i < model.entries.size(); ++i) {
        const auto& e = model.entries[i];
        if (e.should_sync && !e.synced)
            return i;
    }
    return std::nullopt;
}

class PushMany : public rc::state::Command<Model, Sut> {
public:
    explicit PushMany(std::vector<std::uint32_t> seeds)
        : m_seeds(std::move(seeds)) {}

    void apply(Model& state) const override {
        for (auto seed : m_seeds)
            push_into_model(state, seed, false);
    }

    void run(const Model& state, Sut& sut) const override {
        Model expected = state;
        for (auto seed : m_seeds)
            push_into_model(expected, seed, false);

        if (!sut.chron)
            sut.chron.emplace(Chronicler::create(sut.partition, session_id, dispose_other_sessions));
        std::vector<std::uint8_t> payload(entry_size(sut));
        for (auto seed : m_seeds) {
            fill_entry(payload, seed);
            sut.chron->push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
        }
        RC_ASSERT(sut.chron->size() == expected.expected_size());

        std::vector<std::uint8_t> read_buf(entry_size(sut));
        std::vector<std::uint8_t> expected_payload(entry_size(sut));
        for (std::size_t i = 0; i < expected.entries.size(); ++i) {
            const std::size_t bytes =
                sut.chron->read(i, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
            RC_ASSERT(bytes == entry_size(sut));
            fill_entry(expected_payload, expected.entries[i].seed);
            RC_ASSERT(std::equal(read_buf.begin(), read_buf.end(), expected_payload.begin(), expected_payload.end()));
            if (expected.entries[i].should_sync)
                RC_ASSERT(sut.chron->is_synced(i) == expected.entries[i].synced);
            else
                RC_ASSERT(sut.chron->is_synced(i));
        }

        RC_ASSERT(sut.chron->get_unsynced() == first_unsynced(expected));
    }

    void show(std::ostream& os) const override {
        os << "PushMany(" << m_seeds.size() << " entries)";
    }

private:
    std::vector<std::uint32_t> m_seeds;
};

class ReloadAndVerify : public rc::state::Command<Model, Sut> {
public:
    void run(const Model& state, Sut& sut) const override {
        RC_PRE(sut.chron.has_value());
        sut.chron.reset();
        auto loaded = Chronicler::load(sut.partition, session_id, dispose_other_sessions);
        RC_ASSERT(loaded.has_value());
        sut.chron.emplace(std::move(*loaded));

        RC_ASSERT(sut.chron->size() == state.expected_size());

        std::vector<std::uint8_t> read_buf(entry_size(sut));
        std::vector<std::uint8_t> expected(entry_size(sut));
        for (std::size_t i = 0; i < state.entries.size(); ++i) {
            const std::size_t bytes =
                sut.chron->read(i, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
            RC_ASSERT(bytes == entry_size(sut));
            fill_entry(expected, state.entries[i].seed);
            RC_ASSERT(std::equal(read_buf.begin(), read_buf.end(), expected.begin(), expected.end()));
            if (state.entries[i].should_sync)
                RC_ASSERT(sut.chron->is_synced(i) == state.entries[i].synced);
            else
                RC_ASSERT(sut.chron->is_synced(i));
        }

        RC_ASSERT(sut.chron->get_unsynced() == first_unsynced(state));
    }

    void show(std::ostream& os) const override {
        os << "ReloadAndVerify";
    }
};

class MarkFirstUnsynced : public rc::state::Command<Model, Sut> {
public:
    void checkPreconditions(const Model& state) const override {
        RC_PRE(first_unsynced(state).has_value());
    }

    void apply(Model& state) const override {
        if (auto idx = first_unsynced(state))
            state.entries[*idx].synced = true;
    }

    void run(const Model& state, Sut& sut) const override {
        RC_PRE(sut.chron.has_value());
        const auto expected_idx = first_unsynced(state);
        RC_ASSERT(expected_idx.has_value());
        const auto chron_idx = sut.chron->get_unsynced();
        RC_ASSERT(chron_idx.has_value());
        RC_ASSERT(*chron_idx == *expected_idx);
        sut.chron->mark_synced(*chron_idx);
        RC_ASSERT(sut.chron->is_synced(*chron_idx));
    }

    void show(std::ostream& os) const override { os << "MarkFirstUnsynced"; }
};

class PushWithSync : public rc::state::Command<Model, Sut> {
public:
    PushWithSync(std::vector<std::pair<std::uint32_t, bool>> seeds_with_sync)
        : m_seeds_with_sync(std::move(seeds_with_sync)) {}

    void apply(Model& state) const override {
        for (auto [seed, sync] : m_seeds_with_sync)
            push_into_model(state, seed, sync);
    }

    void run(const Model& state, Sut& sut) const override {
        Model expected = state;
        for (auto [seed, sync] : m_seeds_with_sync)
            push_into_model(expected, seed, sync);

        if (!sut.chron)
            sut.chron.emplace(Chronicler::create(sut.partition, session_id, dispose_other_sessions));

        std::vector<std::uint8_t> payload(entry_size(sut));
        for (auto [seed, sync] : m_seeds_with_sync) {
            fill_entry(payload, seed);
            sut.chron->push(std::span<const std::uint8_t>(payload.data(), payload.size()), sync);
            if (!sync)
                RC_ASSERT(sut.chron->is_synced(sut.chron->size() - 1));
        }

        RC_ASSERT(sut.chron->size() == expected.expected_size());

        std::vector<std::uint8_t> read_buf(entry_size(sut));
        std::vector<std::uint8_t> expected_payload(entry_size(sut));
        for (std::size_t i = 0; i < expected.entries.size(); ++i) {
            const std::size_t bytes =
                sut.chron->read(i, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
            RC_ASSERT(bytes == entry_size(sut));
            fill_entry(expected_payload, expected.entries[i].seed);
            RC_ASSERT(std::equal(read_buf.begin(), read_buf.end(), expected_payload.begin(), expected_payload.end()));
            if (expected.entries[i].should_sync)
                RC_ASSERT(sut.chron->is_synced(i) == expected.entries[i].synced);
            else
                RC_ASSERT(sut.chron->is_synced(i));
        }

        RC_ASSERT(sut.chron->get_unsynced() == first_unsynced(expected));
    }

    void show(std::ostream& os) const override {
        os << "PushWithSync(" << m_seeds_with_sync.size() << ")";
    }

private:
    std::vector<std::pair<std::uint32_t, bool>> m_seeds_with_sync;
};

class PushWithSyncAndCallback : public rc::state::Command<Model, Sut> {
public:
    PushWithSyncAndCallback(std::vector<std::pair<std::uint32_t, bool>> seeds_with_sync,
                            SyncCallbackContext decisions)
        : m_seeds_with_sync(std::move(seeds_with_sync))
        , m_decisions(std::move(decisions)) {}

    static Model project_next(const Model& state,
                              const std::vector<std::pair<std::uint32_t, bool>>& seeds_with_sync,
                              const SyncCallbackContext& decisions) {
        Model next = state;
        std::size_t idx = 0;
        for (auto [seed, sync] : seeds_with_sync) {
            push_into_model(next, seed, sync);
            if (sync && idx < decisions.decisions.size() && decisions.decisions[idx])
                next.entries.back().synced = true;
            if (sync)
                idx++;
        }
        return next;
    }

    void apply(Model& state) const override {
        state = project_next(state, m_seeds_with_sync, m_decisions);
    }

    void run(const Model& state, Sut& sut) const override {
        Model expected = project_next(state, m_seeds_with_sync, m_decisions);

        if (!sut.chron)
            sut.chron.emplace(Chronicler::create(sut.partition, session_id, dispose_other_sessions));

        SyncCallbackContext local_ctx = m_decisions;
        local_ctx.idx = 0;
        sut.chron->set_sync_callback(sync_callback, &local_ctx);

        std::vector<std::uint8_t> payload(entry_size(sut));
        for (auto [seed, sync] : m_seeds_with_sync) {
            fill_entry(payload, seed);
            sut.chron->push(std::span<const std::uint8_t>(payload.data(), payload.size()), sync);
        }

        RC_ASSERT(sut.chron->size() == expected.expected_size());

        std::vector<std::uint8_t> read_buf(entry_size(sut));
        std::vector<std::uint8_t> expected_payload(entry_size(sut));
        for (std::size_t i = 0; i < expected.entries.size(); ++i) {
            const std::size_t bytes =
                sut.chron->read(i, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
            RC_ASSERT(bytes == entry_size(sut));
            fill_entry(expected_payload, expected.entries[i].seed);
            RC_ASSERT(std::equal(read_buf.begin(), read_buf.end(), expected_payload.begin(), expected_payload.end()));
            if (expected.entries[i].should_sync)
                RC_ASSERT(sut.chron->is_synced(i) == expected.entries[i].synced);
            else
                RC_ASSERT(sut.chron->is_synced(i));
        }

        RC_ASSERT(sut.chron->get_unsynced() == first_unsynced(expected));
    }

    void show(std::ostream& os) const override {
        os << "PushWithSyncAndCallback(" << m_seeds_with_sync.size() << ")";
    }

private:
    std::vector<std::pair<std::uint32_t, bool>> m_seeds_with_sync;
    SyncCallbackContext m_decisions;
};

auto gen_seeds(std::size_t max_ops) {
    return rc::gen::map(rc::gen::arbitrary<std::vector<std::uint32_t>>(),
                        [max_ops](std::vector<std::uint32_t> vals) {
                            if (vals.size() > max_ops)
                                vals.resize(max_ops);
                            return vals;
                        });
}

auto gen_seeds_overflow(std::size_t capacity, std::size_t sector_capacity) {
    const std::size_t min_len = capacity + sector_capacity;
    const std::size_t max_len = capacity + sector_capacity * 3;
    return rc::gen::apply(
        [min_len, max_len](std::vector<std::uint32_t> base,
                           std::vector<std::uint32_t> extra) {
            if (base.size() < min_len) {
                const auto needed = min_len - base.size();
                if (extra.size() < needed)
                    extra.resize(needed, 0);
                base.insert(base.end(), extra.begin(), extra.begin() + needed);
            }
            if (base.size() > max_len)
                base.resize(max_len);
            if (base.size() < min_len)
                base.resize(min_len, 0);
            return base;
        },
        rc::gen::container<std::vector<std::uint32_t>>(rc::gen::arbitrary<std::uint32_t>()),
        rc::gen::container<std::vector<std::uint32_t>>(rc::gen::arbitrary<std::uint32_t>()));
}

auto gen_seeds_with_sync(std::size_t max_ops) {
    return rc::gen::map(
        rc::gen::arbitrary<std::vector<std::pair<std::uint32_t, bool>>>(),
        [max_ops](std::vector<std::pair<std::uint32_t, bool>> vals) {
            if (vals.size() > max_ops)
                vals.resize(max_ops);
            return vals;
        });
}

auto gen_seeds_with_sync_at_least_one(std::size_t max_ops) {
    return rc::gen::map(gen_seeds_with_sync(max_ops),
                        [](std::vector<std::pair<std::uint32_t, bool>> vals) {
                            bool any = std::any_of(vals.begin(), vals.end(),
                                                   [](const auto& p) { return p.second; });
                            if (!any) {
                                if (vals.empty())
                                    vals.push_back({0, true});
                                else
                                    vals.front().second = true;
                            }
                            return vals;
                        });
}

auto gen_decisions(std::size_t max_ops) {
    return rc::gen::map(rc::gen::arbitrary<std::vector<bool>>(),
                        [max_ops](std::vector<bool> vals) {
                            if (vals.size() > max_ops)
                                vals.resize(max_ops);
                            return vals;
                        });
}

struct TestContext {
    Model model;
    Sut sut;
};

std::size_t pick_entry_size() {
    return (*rc::gen::inRange<std::size_t>(1, 128)) * 4; // 4..512 bytes
}

std::size_t pick_entry_size_biased_large() {
    return (*rc::gen::inRange<std::size_t>(64, 129)) * 4; // 256..512 bytes
}

std::size_t sector_capacity_for_entry(const detail::Geometry& geom, std::size_t entry_size_bytes) {
    if (entry_size_bytes == 0 || geom.sector_size <= detail::Geometry::sector_header_size)
        return 0;
    const std::size_t available = geom.sector_size - detail::Geometry::sector_header_size;
    const std::size_t record_bytes = detail::Geometry::record_overhead + entry_size_bytes;
    return record_bytes == 0 ? 0 : (available / record_bytes);
}

TestContext make_context(std::size_t entry_size_bytes) {
    auto partition = prepare_partition();
    detail::Geometry geom(partition);
    RC_PRE(geom.data_sector_count > 0);
    const std::size_t sector_capacity = sector_capacity_for_entry(geom, entry_size_bytes);
    RC_PRE(sector_capacity > 0);
    const std::size_t capacity = sector_capacity * geom.data_sector_count;
    RC_PRE(capacity > 0);

    Model model;
    model.capacity = capacity;
    model.sector_capacity = sector_capacity;
    model.data_sector_count = geom.data_sector_count;
    model.head_size = 0;
    model.wrapped = false;

    Sut sut{partition, geom, entry_size_bytes, Chronicler::create(partition, session_id, dispose_other_sessions)};
    return {std::move(model), std::move(sut)};
}

TestContext make_context() {
    return make_context(pick_entry_size());
}

} // namespace

extern "C" void app_main(void) {
    rc::check("load fails when metadata slots are corrupted",
              [] {
                  auto partition = prepare_partition();
                  const std::size_t entry_sz = pick_entry_size();
                  detail::Geometry geom(partition);
                  RC_PRE(geom.data_sector_count > 0);

                  auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);
                  std::vector<std::uint8_t> payload(entry_sz);
                  fill_entry(payload, 1);
                  chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);

                  SectorHandle slot0(partition, 0);
                  SectorHandle slot1(partition, 1);
                  slot0.write(detail::layout::g_magic, 0U);
                  slot1.write(detail::layout::g_magic, 0U);

                  auto loaded = Chronicler::load(partition, session_id, dispose_other_sessions);
                  RC_ASSERT(!loaded.has_value());
              });

    rc::check("corrupting payload word changes readback",
              [] {
                  auto partition = prepare_partition();
                  const std::size_t entry_sz = pick_entry_size();
                  detail::Geometry geom(partition);
                  RC_PRE(geom.data_sector_count > 0);

                  auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);
                  std::vector<std::uint8_t> payload(entry_sz);
                  fill_entry(payload, 42);
                  chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);

                  std::size_t word_offset = 0;
                  bool found = false;
                  for (std::size_t i = 0; i + 4 <= payload.size(); i += 4) {
                      std::uint32_t word = 0;
                      std::memcpy(&word, payload.data() + i, sizeof(word));
                      if (word != 0U) {
                          word_offset = i;
                          found = true;
                          break;
                      }
                  }
                  RC_PRE(found);

                  SectorHandle sector(partition, geom.metadata_sector_count);
                  const std::size_t addr =
                      geom.data_offset + detail::Geometry::length_header_size + word_offset;
                  sector.write(addr, 0U);

                  std::vector<std::uint8_t> read_buf(entry_sz);
                  chron.read(0, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
                  RC_ASSERT(!std::equal(read_buf.begin(), read_buf.end(), payload.begin(), payload.end()));
              });

    rc::check("partial entry write seals sector and avoids overwrite",
              [] {
                  auto partition = prepare_partition();
                  const std::size_t entry_sz = pick_entry_size();
                  detail::Geometry geom(partition);
                  RC_PRE(geom.data_sector_count > 1);
                  const std::size_t sector_capacity = sector_capacity_for_entry(geom, entry_sz);
                  RC_PRE(sector_capacity > 0);

                  auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);
                  std::vector<std::uint8_t> payload(entry_sz);
                  fill_entry(payload, 123);

                  PartialWriteContext ctx;
                  const std::size_t sector_start =
                      geom.metadata_sector_count * partition.sector_size();
                  ctx.crc_addr =
                      sector_start + geom.data_offset + detail::Geometry::length_header_size + entry_sz;
                  ctx.payload_addr = sector_start + geom.data_offset + detail::Geometry::length_header_size;
                  ctx.payload_size = entry_sz;
                  ctx.payload_written = 0;
                  ctx.truncated_payload = false;

                  PartitionHandle::set_write_hook(partial_write_hook, &ctx);
                  chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
                  PartitionHandle::clear_write_hook();

                  SectorHandle sector(partition, geom.metadata_sector_count);
                  std::vector<std::uint8_t> raw_payload(entry_sz);
                  sector.read(geom.data_offset + detail::Geometry::length_header_size,
                              std::span<std::uint8_t>(raw_payload.data(), raw_payload.size()));

                  RC_ASSERT(ctx.truncated_payload);
                  for (std::size_t i = 0; i < ctx.payload_written; ++i)
                      RC_ASSERT(raw_payload[i] == payload[i]);
                  for (std::size_t i = ctx.payload_written; i < raw_payload.size(); ++i)
                      RC_ASSERT(raw_payload[i] == 0xFF);

                  const std::uint8_t crc_byte =
                      sector.read_byte(geom.data_offset + detail::Geometry::length_header_size + entry_sz);

                  auto loaded = Chronicler::load(partition, session_id, dispose_other_sessions);
                  RC_ASSERT(loaded.has_value());
                  auto chron2 = std::move(*loaded);

                  fill_entry(payload, 456);
                  chron2.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);

                  const std::uint8_t crc_byte_after =
                      sector.read_byte(geom.data_offset + detail::Geometry::length_header_size + entry_sz);
                  RC_ASSERT(crc_byte_after == crc_byte);

                  std::vector<std::uint8_t> read_buf(entry_sz);
                  chron2.read(0, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
                  RC_ASSERT(std::equal(read_buf.begin(), read_buf.end(), payload.begin(), payload.end()));
              });

    rc::check("erased header leaves sector appendable",
              [] {
                  auto partition = prepare_partition();
                  detail::Geometry geom(partition);
                  RC_PRE(geom.data_sector_count > 0);

                  auto sector = detail::DataSector::load(geom, partition, 0);
                  RC_ASSERT(sector.size() == 0);
                  RC_ASSERT(!sector.sealed());
                  RC_ASSERT(sector.can_append(1));
              });

    rc::check("length header overflow seals sector",
              [] {
                  auto partition = prepare_partition();
                  detail::Geometry geom(partition);
                  RC_PRE(geom.data_sector_count > 0);

                  SectorHandle sector(partition, geom.metadata_sector_count);
                  const std::uint16_t length_flags =
                      static_cast<std::uint16_t>((detail::Geometry::flag_mask & ~detail::Geometry::flag_should_sync)
                                                 | detail::Geometry::length_mask);
                  std::uint8_t header[detail::Geometry::length_header_size]{};
                  header[0] = static_cast<std::uint8_t>(length_flags & 0xFFU);
                  header[1] = static_cast<std::uint8_t>((length_flags >> 8) & 0xFFU);
                  sector.write(geom.data_offset, { header, sizeof(header) });

                  auto loaded = detail::DataSector::load(geom, partition, 0);
                  RC_ASSERT(loaded.size() == 0);
                  RC_ASSERT(loaded.sealed());
              });

    rc::check("crc escape flag mismatch seals sector",
              [] {
                  auto partition = prepare_partition();
                  detail::Geometry geom(partition);
                  RC_PRE(geom.data_sector_count > 0);

                  SectorHandle sector(partition, geom.metadata_sector_count);
                  const std::uint16_t length_flags =
                      static_cast<std::uint16_t>((detail::Geometry::flag_mask & ~detail::Geometry::flag_crc_escaped)
                                                 | 1U);
                  std::uint8_t header[detail::Geometry::length_header_size]{};
                  header[0] = static_cast<std::uint8_t>(length_flags & 0xFFU);
                  header[1] = static_cast<std::uint8_t>((length_flags >> 8) & 0xFFU);
                  sector.write(geom.data_offset, { header, sizeof(header) });

                  const std::uint8_t payload = 0xAA;
                  sector.write(geom.data_offset + detail::Geometry::length_header_size,
                               std::span<const std::uint8_t>(&payload, 1));
                  sector.write_byte(geom.data_offset + detail::Geometry::length_header_size + 1, 0x00);

                  auto loaded = detail::DataSector::load(geom, partition, 0);
                  RC_ASSERT(loaded.size() == 0);
                  RC_ASSERT(loaded.sealed());
              });

    rc::check("crc escape byte without flag seals sector",
              [] {
                  auto partition = prepare_partition();
                  detail::Geometry geom(partition);
                  RC_PRE(geom.data_sector_count > 0);

                  SectorHandle sector(partition, geom.metadata_sector_count);
                  const std::uint16_t length_flags =
                      static_cast<std::uint16_t>(detail::Geometry::flag_mask | 1U);
                  std::uint8_t header[detail::Geometry::length_header_size]{};
                  header[0] = static_cast<std::uint8_t>(length_flags & 0xFFU);
                  header[1] = static_cast<std::uint8_t>((length_flags >> 8) & 0xFFU);
                  sector.write(geom.data_offset, { header, sizeof(header) });

                  const std::uint8_t payload = 0x55;
                  sector.write(geom.data_offset + detail::Geometry::length_header_size,
                               std::span<const std::uint8_t>(&payload, 1));
                  sector.write_byte(geom.data_offset + detail::Geometry::length_header_size + 1, 0xFE);

                  auto loaded = detail::DataSector::load(geom, partition, 0);
                  RC_ASSERT(loaded.size() == 0);
                  RC_ASSERT(loaded.sealed());
              });

    rc::check("collect_used_sector_indices adds head after load when bitmap empty",
              [] {
                  auto partition = prepare_partition();
                  detail::Geometry geom(partition);
                  RC_PRE(geom.data_sector_count > 0);

                  auto all_ones = make_all_ones_bitmap(geom);
                  SectorHandle slot0(partition, 0);
                  SectorHandle slot1(partition, 1);
                  write_metadata_slot(slot0, all_ones, false);
                  write_metadata_slot(slot1, all_ones, true);

                  auto meta = detail::Metadata::load(geom, partition);
                  RC_ASSERT(meta.has_value());
                  const auto indices = detail::collect_used_sector_indices(*meta, geom);
                  RC_ASSERT(indices.size() == 1);
                  RC_ASSERT(indices.front() == 0);
              });

    rc::check("entry disposable flag toggles",
              [] {
                  auto partition = prepare_partition();
                  detail::Geometry geom(partition);
                  RC_PRE(geom.data_sector_count > 0);

                  const std::size_t entry_sz = pick_entry_size();
                  auto sector = detail::DataSector::create(geom, partition, 0);
                  std::vector<std::uint8_t> payload(entry_sz);
                  fill_entry(payload, 1);
                  sector.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);

                  RC_ASSERT(!sector.is_entry_disposable(0));
                  sector.mark_entry_disposable(0);
                  RC_ASSERT(sector.is_entry_disposable(0));
              });

    rc::check("mark_disposable is idempotent",
              [] {
                  auto partition = prepare_partition();
                  const std::size_t entry_sz = pick_entry_size();
                  detail::Geometry geom(partition);
                  RC_PRE(geom.data_sector_count > 0);

                  auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);
                  std::vector<std::uint8_t> payload(entry_sz);
                  fill_entry(payload, 1);
                  chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);

                  RC_ASSERT(chron.mark_disposable(0));
                  RC_ASSERT(!chron.mark_disposable(0));
              });

    rc::check("entry disposable auto marks sector disposable",
              [] {
                  auto partition = prepare_partition();
                  const std::size_t entry_sz = pick_entry_size();
                  detail::Geometry geom(partition);
                  RC_PRE(geom.data_sector_count > 1);
                  const std::size_t sector_capacity = sector_capacity_for_entry(geom, entry_sz);
                  RC_PRE(sector_capacity > 0);

                  auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);
                  std::vector<std::uint8_t> payload(entry_sz);
                  for (std::size_t i = 0; i < sector_capacity + 1; ++i) {
                      fill_entry(payload, static_cast<std::uint32_t>(i));
                      chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
                  }

                  for (std::size_t i = 0; i + 1 < sector_capacity; ++i)
                      RC_ASSERT(chron.mark_entry_disposable(i));
                  RC_ASSERT(!chron.sweep_disposable_sector());

                  RC_ASSERT(chron.mark_entry_disposable(sector_capacity - 1));
                  RC_ASSERT(chron.sweep_disposable_sector());
              });

    rc::check("session filtering isolates entries",
              [] {
                  auto partition = prepare_partition();
                  detail::Geometry geom(partition);
                  RC_PRE(geom.data_sector_count > 1);

                  const std::uint8_t session_a = 0x11;
                  const std::uint8_t session_b = 0x22;

                  auto chron = Chronicler::create(partition, session_a, false);
                  std::vector<std::uint8_t> payload(pick_entry_size());
                  fill_entry(payload, 1);
                  chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
                  fill_entry(payload, 2);
                  chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);

                  auto loaded_b = Chronicler::load(partition, session_b, false);
                  RC_ASSERT(loaded_b.has_value());
                  auto chron_b = std::move(*loaded_b);
                  fill_entry(payload, 3);
                  chron_b.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);

                  auto loaded_a = Chronicler::load(partition, session_a, false);
                  RC_ASSERT(loaded_a.has_value());
                  RC_ASSERT(loaded_a->size() == 2);

                  auto loaded_b_verify = Chronicler::load(partition, session_b, false);
                  RC_ASSERT(loaded_b_verify.has_value());
                  RC_ASSERT(loaded_b_verify->size() == 1);
              });

    rc::check("session filtering skips other-session sectors",
              [] {
                  auto partition = prepare_partition();
                  detail::Geometry geom(partition);
                  RC_PRE(geom.data_sector_count > 2);

                  const std::uint8_t session_a = 0x41;
                  const std::uint8_t session_b = 0x42;
                  const std::size_t entry_sz = pick_entry_size();
                  const std::size_t sector_capacity = sector_capacity_for_entry(geom, entry_sz);
                  RC_PRE(sector_capacity > 0);

                  auto chron_a = Chronicler::create(partition, session_a, false);
                  std::vector<std::uint8_t> payload(entry_sz);
                  for (std::size_t i = 0; i < sector_capacity; ++i) {
                      fill_entry(payload, static_cast<std::uint32_t>(i));
                      chron_a.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
                  }

                  auto loaded_b = Chronicler::load(partition, session_b, false);
                  RC_ASSERT(loaded_b.has_value());
                  auto chron_b = std::move(*loaded_b);
                  fill_entry(payload, 100);
                  chron_b.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);

                  auto loaded_a = Chronicler::load(partition, session_a, false);
                  RC_ASSERT(loaded_a.has_value());
                  auto chron_a2 = std::move(*loaded_a);
                  fill_entry(payload, 200);
                  chron_a2.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);

                  RC_ASSERT(chron_a2.size() == sector_capacity + 1);
                  std::vector<std::uint8_t> read_buf(entry_sz);
                  fill_entry(payload, 200);
                  RC_ASSERT(chron_a2.read(sector_capacity,
                                          std::span<std::uint8_t>(read_buf.data(), read_buf.size()))
                            == payload.size());
                  RC_ASSERT(std::equal(payload.begin(), payload.end(), read_buf.begin(), read_buf.end()));
              });

    rc::check("mark_synced handle rejects other session",
              [] {
                  auto partition = prepare_partition();
                  detail::Geometry geom(partition);
                  RC_PRE(geom.data_sector_count > 0);

                  const std::uint8_t session_a = 0x51;
                  const std::uint8_t session_b = 0x52;
                  const std::size_t entry_sz = pick_entry_size();

                  auto chron_a = Chronicler::create(partition, session_a, false);
                  std::vector<std::uint8_t> payload(entry_sz);
                  fill_entry(payload, 7);
                  auto handle =
                      chron_a.push_with_handle(std::span<const std::uint8_t>(payload.data(), payload.size()), true);

                  auto loaded_b = Chronicler::load(partition, session_b, false);
                  RC_ASSERT(loaded_b.has_value());
                  auto chron_b = std::move(*loaded_b);
                  RC_ASSERT(!chron_b.mark_synced(handle));
              });

    rc::check("mark_synced handle rejects erased sector",
              [] {
                  auto partition = prepare_partition();
                  detail::Geometry geom(partition);
                  RC_PRE(geom.data_sector_count > 1);

                  const std::size_t entry_sz = pick_entry_size();
                  const std::size_t sector_capacity = sector_capacity_for_entry(geom, entry_sz);
                  RC_PRE(sector_capacity > 0);

                  auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);
                  std::vector<std::uint8_t> payload(entry_sz);
                  fill_entry(payload, 1);
                  auto handle =
                      chron.push_with_handle(std::span<const std::uint8_t>(payload.data(), payload.size()), true);

                  for (std::size_t i = 1; i < sector_capacity + 1; ++i) {
                      fill_entry(payload, static_cast<std::uint32_t>(i));
                      chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
                  }

                  RC_ASSERT(chron.mark_disposable(0));
                  RC_ASSERT(chron.sweep_disposable_sector());
                  RC_ASSERT(!chron.mark_synced(handle));
              });

    rc::check("mark_synced handle rejects recycled sector",
              [] {
                  auto partition = prepare_partition();
                  detail::Geometry geom(partition);
                  RC_PRE(geom.data_sector_count > 1);

                  const std::size_t entry_sz = pick_entry_size();
                  const std::size_t sector_capacity = sector_capacity_for_entry(geom, entry_sz);
                  RC_PRE(sector_capacity > 1);

                  auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);
                  std::vector<std::uint8_t> payload(entry_sz);
                  fill_entry(payload, 1);
                  auto handle =
                      chron.push_with_handle(std::span<const std::uint8_t>(payload.data(), payload.size()), true);

                  for (std::size_t i = 1; i < sector_capacity + 1; ++i) {
                      fill_entry(payload, static_cast<std::uint32_t>(i));
                      chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
                  }

                  RC_ASSERT(chron.mark_disposable(0));
                  RC_ASSERT(chron.sweep_disposable_sector());

                  fill_entry(payload, 42);
                  chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);

                  RC_ASSERT(!chron.mark_synced(handle));
              });

    rc::check("session filtering across wrap",
              [] {
                  auto partition = prepare_partition();
                  detail::Geometry geom(partition);
                  RC_PRE(geom.data_sector_count > 3);

                  const std::uint8_t session_a = 0x61;
                  const std::uint8_t session_b = 0x62;
                  const std::size_t entry_sz = pick_entry_size();
                  const std::size_t sector_capacity = sector_capacity_for_entry(geom, entry_sz);
                  RC_PRE(sector_capacity > 0);

                  auto chron_a = Chronicler::create(partition, session_a, false);
                  std::vector<std::uint8_t> payload(entry_sz);
                  const std::size_t pushes_a = sector_capacity * (geom.data_sector_count + 1);
                  for (std::size_t i = 0; i < pushes_a; ++i) {
                      fill_entry(payload, static_cast<std::uint32_t>(i));
                      chron_a.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
                  }

                  auto loaded_b = Chronicler::load(partition, session_b, false);
                  RC_ASSERT(loaded_b.has_value());
                  auto chron_b = std::move(*loaded_b);
                  fill_entry(payload, 5000);
                  chron_b.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);

                  auto loaded_a = Chronicler::load(partition, session_a, false);
                  RC_ASSERT(loaded_a.has_value());
                  RC_ASSERT(loaded_a->size() == geom.data_sector_count * sector_capacity);
              });

    rc::check("dispose other sessions marks disposable",
              [] {
                  auto partition = prepare_partition();
                  detail::Geometry geom(partition);
                  RC_PRE(geom.data_sector_count > 1);

                  const std::uint8_t session_a = 0x33;
                  const std::uint8_t session_b = 0x34;

                  auto chron = Chronicler::create(partition, session_a, false);
                  std::vector<std::uint8_t> payload(pick_entry_size());
                  fill_entry(payload, 7);
                  chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);

                  auto loaded_b = Chronicler::load(partition, session_b, false);
                  RC_ASSERT(loaded_b.has_value());
                  auto chron_b = std::move(*loaded_b);
                  fill_entry(payload, 8);
                  chron_b.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);

                  auto loaded = Chronicler::load(partition, session_b, true);
                  RC_ASSERT(loaded.has_value());

                  auto meta = detail::Metadata::load(geom, partition);
                  RC_ASSERT(meta.has_value());
                  for (auto sector_idx : detail::collect_used_sector_indices(*meta, geom)) {
                      SectorHandle sector(partition, geom.metadata_sector_count + sector_idx);
                      const std::uint8_t sid = sector.read_byte(0);
                      if (sid != session_b)
                          RC_ASSERT(meta->is_disposable(sector_idx));
                      else
                          RC_ASSERT(!meta->is_disposable(sector_idx));
                  }
              });

    rc::check("sweep_disposable refuses non-disposable non-head sector",
              [] {
                  auto partition = prepare_partition();
                  const std::size_t entry_sz = pick_entry_size();
                  detail::Geometry geom(partition);
                  RC_PRE(geom.data_sector_count > 2);
                  const std::size_t sector_capacity = sector_capacity_for_entry(geom, entry_sz);
                  RC_PRE(sector_capacity > 0);

                  auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);
                  std::vector<std::uint8_t> payload(entry_sz);
                  const std::size_t entries = sector_capacity * 2 + 1;
                  for (std::size_t i = 0; i < entries; ++i) {
                      fill_entry(payload, static_cast<std::uint32_t>(i));
                      chron.push(std::span<const std::uint8_t>(payload.data(), payload.size()), false);
                  }

                  RC_ASSERT(!chron.sweep_disposable_sector());
              });

    rc::check("append and reload preserves data across wrap",
              [] {
                  auto ctx = make_context();
                  const std::size_t max_ops = ctx.model.capacity * 3;
                  const auto first_batch = *gen_seeds(max_ops);
                  const auto second_batch = *gen_seeds(max_ops);

                  rc::state::Commands<rc::state::Command<Model, Sut>> commands;
                  commands.push_back(std::make_shared<PushMany>(first_batch));
                  commands.push_back(std::make_shared<ReloadAndVerify>());
                  commands.push_back(std::make_shared<PushMany>(second_batch));
                  commands.push_back(std::make_shared<ReloadAndVerify>());

                  rc::state::runAll(commands, ctx.model, ctx.sut);
              });

    rc::check("overflow evicts full sectors",
              [] {
                  const auto entry_size_bytes = pick_entry_size_biased_large();
                  auto ctx = make_context(entry_size_bytes);
                  const auto seeds =
                      *gen_seeds_overflow(ctx.model.capacity, ctx.model.sector_capacity);

                  rc::state::Commands<rc::state::Command<Model, Sut>> commands;
                  commands.push_back(std::make_shared<PushMany>(seeds));
                  commands.push_back(std::make_shared<ReloadAndVerify>());

                  rc::state::runAll(commands, ctx.model, ctx.sut);
              });

    rc::check("sync bookkeeping reflects unsynced markers",
              [] {
                  auto ctx = make_context();
                  const std::size_t max_ops = ctx.model.capacity * 2;
                  const auto sync_batch = *gen_seeds_with_sync_at_least_one(max_ops);

                  rc::state::Commands<rc::state::Command<Model, Sut>> commands;
                  commands.push_back(std::make_shared<PushWithSync>(sync_batch));
                  commands.push_back(std::make_shared<ReloadAndVerify>());
                  commands.push_back(std::make_shared<MarkFirstUnsynced>());
                  commands.push_back(std::make_shared<ReloadAndVerify>());

                  rc::state::runAll(commands, ctx.model, ctx.sut);
              });

    rc::check("push_with_handle returns handle for mark_synced",
              [] {
                  auto partition = prepare_partition();
                  detail::Geometry geom(partition);
                  RC_PRE(geom.data_sector_count > 0);

                  const std::size_t entry_sz = pick_entry_size();
                  auto chron = Chronicler::create(partition, session_id, dispose_other_sessions);
                  std::vector<std::uint8_t> payload(entry_sz);
                  fill_entry(payload, 7);

                  auto handle = chron.push_with_handle(std::span<const std::uint8_t>(payload.data(), payload.size()), true);
                  RC_ASSERT(!chron.is_synced(0));
                  RC_ASSERT(chron.mark_synced(handle));
                  RC_ASSERT(chron.is_synced(0));
              });

    rc::check("mixed sync/non-sync pushes survive reloads",
              [] {
                  auto ctx = make_context();
                  const std::size_t max_ops = ctx.model.capacity * 2;
                  const auto sync_batch = *gen_seeds_with_sync(max_ops);
                  const auto extra_plain = *gen_seeds(max_ops);

                  rc::state::Commands<rc::state::Command<Model, Sut>> commands;
                  commands.push_back(std::make_shared<PushWithSync>(sync_batch));
                  commands.push_back(std::make_shared<ReloadAndVerify>());
                  commands.push_back(std::make_shared<PushMany>(extra_plain));
                  commands.push_back(std::make_shared<ReloadAndVerify>());
                  if (first_unsynced(ctx.model))
                      commands.push_back(std::make_shared<MarkFirstUnsynced>());

                  rc::state::runAll(commands, ctx.model, ctx.sut);
              });

    rc::check("sync callback can clear unsynced entries and get_unsynced tracks correctly",
              [] {
                  auto ctx = make_context();
                  const std::size_t max_ops = ctx.model.capacity * 2;
                  auto seeds_with_sync = *gen_seeds_with_sync_at_least_one(max_ops);
                  auto decisions = *gen_decisions(max_ops);

                  SyncCallbackContext cb_ctx;
                  cb_ctx.decisions = decisions;
                  cb_ctx.idx = 0;

                  rc::state::Commands<rc::state::Command<Model, Sut>> commands;
                  commands.push_back(std::make_shared<PushWithSyncAndCallback>(seeds_with_sync, cb_ctx));
                  commands.push_back(std::make_shared<ReloadAndVerify>());
                  if (first_unsynced(ctx.model))
                      commands.push_back(std::make_shared<MarkFirstUnsynced>());
                  commands.push_back(std::make_shared<ReloadAndVerify>());

                  rc::state::runAll(commands, ctx.model, ctx.sut);
              });
}
