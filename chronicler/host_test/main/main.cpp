#include <bricks/chronicler.hpp>
#include <bricks/chronicler/geometry.hpp>

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

constexpr char kPartitionLabel[] = "storage";
constexpr std::size_t kFlashBytes = 4 * 1024 * 1024;

void fill_entry(std::vector<std::uint8_t>& buf, std::uint32_t seed) {
    for (std::size_t i = 0; i < buf.size(); ++i)
        buf[i] = static_cast<std::uint8_t>((seed + i * 17U) & 0xFFU);
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
    const std::string flash_path = create_flash_image(kFlashBytes);
    std::strncpy(ctrl->flash_file_name, flash_path.c_str(), sizeof(ctrl->flash_file_name) - 1);
    ctrl->flash_file_name[sizeof(ctrl->flash_file_name) - 1] = '\0';
    ctrl->remove_dump = true;

    const esp_partition_t* part = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, kPartitionLabel);
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
    std::optional<Chronicler> chron;
};

std::size_t entry_size(const Sut& sut) {
    return static_cast<std::size_t>(sut.geom.entry_size);
}

struct SyncCallbackContext {
    std::vector<bool> decisions;
    std::size_t idx = 0;
};

struct PartialWriteContext {
    std::size_t flags_addr{};
    std::size_t payload_addr{};
    std::size_t payload_size{};
    std::size_t payload_written{};
    int flag_writes{};
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
    if (start == info->flags_addr && size == 4) {
        info->flag_writes++;
        if (info->flag_writes == 2)
            return {0, true};
    }
    return {size, false};
}

void sync_callback(Chronicler& chron, std::span<std::uint8_t>, void* ctx) {
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
            sut.chron.emplace(Chronicler::create(sut.partition, entry_size(sut)));
        std::vector<std::uint8_t> payload(entry_size(sut));
        for (auto seed : m_seeds) {
            fill_entry(payload, seed);
            sut.chron->push(std::span<std::uint8_t>(payload.data(), payload.size()), false);
        }
        RC_ASSERT(sut.chron->size() == expected.expected_size());

        std::vector<std::uint8_t> read_buf(entry_size(sut));
        std::vector<std::uint8_t> expected_payload(entry_size(sut));
        for (std::size_t i = 0; i < expected.entries.size(); ++i) {
            sut.chron->read(i, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
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
        auto loaded = Chronicler::load(sut.partition, entry_size(sut));
        RC_ASSERT(loaded.has_value());
        sut.chron.emplace(std::move(*loaded));

        RC_ASSERT(sut.chron->size() == state.expected_size());

        std::vector<std::uint8_t> read_buf(entry_size(sut));
        std::vector<std::uint8_t> expected(entry_size(sut));
        for (std::size_t i = 0; i < state.entries.size(); ++i) {
            sut.chron->read(i, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
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
            sut.chron.emplace(Chronicler::create(sut.partition, entry_size(sut)));

        std::vector<std::uint8_t> payload(entry_size(sut));
        for (auto [seed, sync] : m_seeds_with_sync) {
            fill_entry(payload, seed);
            sut.chron->push(std::span<std::uint8_t>(payload.data(), payload.size()), sync);
            if (!sync)
                RC_ASSERT(sut.chron->is_synced(sut.chron->size() - 1));
        }

        RC_ASSERT(sut.chron->size() == expected.expected_size());

        std::vector<std::uint8_t> read_buf(entry_size(sut));
        std::vector<std::uint8_t> expected_payload(entry_size(sut));
        for (std::size_t i = 0; i < expected.entries.size(); ++i) {
            sut.chron->read(i, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
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
            sut.chron.emplace(Chronicler::create(sut.partition, entry_size(sut)));

        SyncCallbackContext local_ctx = m_decisions;
        local_ctx.idx = 0;
        sut.chron->set_sync_callback(sync_callback, &local_ctx);

        std::vector<std::uint8_t> payload(entry_size(sut));
        for (auto [seed, sync] : m_seeds_with_sync) {
            fill_entry(payload, seed);
            sut.chron->push(std::span<std::uint8_t>(payload.data(), payload.size()), sync);
        }

        RC_ASSERT(sut.chron->size() == expected.expected_size());

        std::vector<std::uint8_t> read_buf(entry_size(sut));
        std::vector<std::uint8_t> expected_payload(entry_size(sut));
        for (std::size_t i = 0; i < expected.entries.size(); ++i) {
            sut.chron->read(i, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
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

TestContext make_context(std::size_t entry_size_bytes) {
    auto partition = prepare_partition();
    detail::Geometry geom(entry_size_bytes, partition);
    RC_PRE(geom.data_sector_count > 0);
    RC_PRE(geom.sector_capacity > 0);
    const std::size_t capacity = geom.sector_capacity * geom.data_sector_count;
    RC_PRE(capacity > 0);

    Model model;
    model.capacity = capacity;
    model.sector_capacity = geom.sector_capacity;
    model.data_sector_count = geom.data_sector_count;
    model.head_size = 0;
    model.wrapped = false;

    Sut sut{partition, geom, Chronicler::create(partition, entry_size_bytes)};
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
                  detail::Geometry geom(entry_sz, partition);
                  RC_PRE(geom.data_sector_count > 0);

                  auto chron = Chronicler::create(partition, entry_sz);
                  std::vector<std::uint8_t> payload(entry_sz);
                  fill_entry(payload, 1);
                  chron.push(std::span<std::uint8_t>(payload.data(), payload.size()), false);

                  SectorHandle slot0(partition, 0);
                  SectorHandle slot1(partition, 1);
                  slot0.write(detail::layout::g_magic, 0U);
                  slot1.write(detail::layout::g_magic, 0U);

                  auto loaded = Chronicler::load(partition, entry_sz);
                  RC_ASSERT(!loaded.has_value());
              });

    rc::check("load fails when wrapped count mismatch detected",
              [] {
                  auto partition = prepare_partition();
                  detail::Geometry geom(pick_entry_size(), partition);
                  RC_PRE(geom.data_sector_count > 1);
                  RC_PRE(geom.sector_capacity > 0);

                  const std::size_t entry_sz = static_cast<std::size_t>(geom.entry_size);
                  auto chron = Chronicler::create(partition, entry_sz);
                  const std::size_t extra = std::min<std::size_t>(geom.sector_capacity, 5);
                  RC_PRE(extra > 0);

                  std::vector<std::uint8_t> payload(entry_sz);
                  for (std::size_t i = 0; i < extra; ++i) {
                      fill_entry(payload, static_cast<std::uint32_t>(i));
                      chron.push(std::span<std::uint8_t>(payload.data(), payload.size()), false);
                  }

                  SectorHandle slot1(partition, 1);
                  slot1.write(detail::layout::g_magic, detail::g_magic);
                  slot1.write(detail::layout::g_version, detail::g_version);
                  slot1.write(detail::layout::g_entry_size, geom.entry_size);
                  slot1.write(detail::layout::g_initialized, 0U);

                  const std::size_t bitmap_bytes = geom.data_sector_count / 4;
                  for (std::size_t offset = 0; offset < bitmap_bytes; offset += 4)
                      slot1.write(detail::layout::g_bitmap + offset, 0U);

                  auto loaded = Chronicler::load(partition, entry_sz);
                  RC_ASSERT(!loaded.has_value());
              });

    rc::check("corrupting payload word changes readback",
              [] {
                  auto partition = prepare_partition();
                  const std::size_t entry_sz = pick_entry_size();
                  detail::Geometry geom(entry_sz, partition);
                  RC_PRE(geom.data_sector_count > 0);

                  auto chron = Chronicler::create(partition, entry_sz);
                  std::vector<std::uint8_t> payload(entry_sz);
                  fill_entry(payload, 42);
                  chron.push(std::span<std::uint8_t>(payload.data(), payload.size()), false);

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
                  const std::size_t addr = geom.data_offset + word_offset;
                  sector.write(addr, 0U);

                  std::vector<std::uint8_t> read_buf(entry_sz);
                  chron.read(0, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
                  RC_ASSERT(!std::equal(read_buf.begin(), read_buf.end(), payload.begin(), payload.end()));
              });

    rc::check("partial entry write seals sector and avoids overwrite",
              [] {
                  auto partition = prepare_partition();
                  const std::size_t entry_sz = pick_entry_size();
                  detail::Geometry geom(entry_sz, partition);
                  RC_PRE(geom.data_sector_count > 1);
                  RC_PRE(geom.sector_capacity > 0);

                  auto chron = Chronicler::create(partition, entry_sz);
                  std::vector<std::uint8_t> payload(entry_sz);
                  fill_entry(payload, 123);

                  PartialWriteContext ctx;
                  const std::size_t sector_start =
                      geom.metadata_sector_count * partition.sector_size();
                  ctx.flags_addr = sector_start;
                  ctx.payload_addr = sector_start + geom.data_offset;
                  ctx.payload_size = entry_sz;
                  ctx.payload_written = 0;
                  ctx.flag_writes = 0;
                  ctx.truncated_payload = false;

                  PartitionHandle::set_write_hook(partial_write_hook, &ctx);
                  chron.push(std::span<std::uint8_t>(payload.data(), payload.size()), false);
                  PartitionHandle::clear_write_hook();

                  SectorHandle sector(partition, geom.metadata_sector_count);
                  std::vector<std::uint8_t> raw_payload(entry_sz);
                  sector.read(geom.data_offset,
                              std::span<std::uint8_t>(raw_payload.data(), raw_payload.size()));

                  RC_ASSERT(ctx.truncated_payload);
                  for (std::size_t i = 0; i < ctx.payload_written; ++i)
                      RC_ASSERT(raw_payload[i] == payload[i]);
                  for (std::size_t i = ctx.payload_written; i < raw_payload.size(); ++i)
                      RC_ASSERT(raw_payload[i] == 0xFF);

                  const std::uint32_t flags_word = sector.read(0);
                  const std::uint8_t flags_byte = static_cast<std::uint8_t>(flags_word & 0xFF);

                  auto loaded = Chronicler::load(partition, entry_sz);
                  RC_ASSERT(loaded.has_value());
                  auto chron2 = std::move(*loaded);

                  fill_entry(payload, 456);
                  chron2.push(std::span<std::uint8_t>(payload.data(), payload.size()), false);

                  const std::uint32_t flags_word_after = sector.read(0);
                  const std::uint8_t flags_byte_after =
                      static_cast<std::uint8_t>(flags_word_after & 0xFF);
                  RC_ASSERT(flags_byte_after == flags_byte);

                  std::vector<std::uint8_t> read_buf(entry_sz);
                  chron2.read(0, std::span<std::uint8_t>(read_buf.data(), read_buf.size()));
                  RC_ASSERT(std::equal(read_buf.begin(), read_buf.end(), payload.begin(), payload.end()));
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
