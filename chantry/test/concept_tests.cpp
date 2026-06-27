#include "bricks/chantry.hpp"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <tuple>
#include <vector>

// ============================================================
// Serializable types
// ============================================================

struct Counter {
    std::uint32_t value = 0;
    auto operator<=>(const Counter&) const = default;

    std::vector<std::uint8_t> serialize() const {
        std::vector<std::uint8_t> buf(sizeof(value));
        std::memcpy(buf.data(), &value, sizeof(value));
        return buf;
    }

    static std::optional<Counter> deserialize(std::span<const std::uint8_t> bytes) {
        if (bytes.size() != sizeof(std::uint32_t)) {
            return std::nullopt;
        }
        Counter c;
        std::memcpy(&c.value, bytes.data(), sizeof(c.value));
        return c;
    }
};

static_assert(bricks::Serializable<Counter>,
              "Counter must satisfy Serializable");

struct Text {
    std::string text;
    auto operator<=>(const Text&) const = default;

    std::vector<std::uint8_t> serialize() const {
        return {text.begin(), text.end()};
    }

    static std::optional<Text> deserialize(std::span<const std::uint8_t> bytes) {
        return Text{std::string(bytes.begin(), bytes.end())};
    }
};

static_assert(bricks::Serializable<Text>,
              "Text must satisfy Serializable");

// --- Not Serializable ---

struct NoSerialize {
    int x;
};

static_assert(!bricks::Serializable<NoSerialize>,
              "NoSerialize must NOT satisfy Serializable");

struct BadDeserializeReturn {
    std::vector<std::uint8_t> serialize() const { return {}; }
    static BadDeserializeReturn deserialize(std::span<const std::uint8_t>) { return {}; }
};

static_assert(!bricks::Serializable<BadDeserializeReturn>,
              "BadDeserializeReturn must NOT satisfy Serializable (not optional)");

// ============================================================
// Versioned types
// ============================================================

struct CounterDevice {
    using State = Counter;
    using Version = std::uint32_t;
    using TimePoint = std::uint32_t;

    State state{};
    Version ver = 0;
    TimePoint updated_at = 0;

    Version version() const { return ver; }
    std::tuple<Version, TimePoint, State> snapshot() const { return {ver, updated_at, state}; }

    std::optional<bool> update(State new_state, TimePoint now) {
        if (new_state == state) {
            updated_at = now;
            return false;
        }
        state = new_state;
        updated_at = now;
        ++ver;
        return true;
    }

    std::optional<bool> replace(Version new_version, TimePoint now, State new_state) {
        if (new_version <= ver) {
            return false;
        }
        state = new_state;
        updated_at = now;
        ver = new_version;
        return true;
    }
};

static_assert(bricks::chantry::Versioned<CounterDevice>,
              "CounterDevice must satisfy Versioned");

struct TextDevice {
    using State = Text;
    using Version = std::uint64_t;
    using TimePoint = std::uint32_t;

    State state{};
    Version ver = 0;
    TimePoint updated_at = 0;

    Version version() const { return ver; }
    std::tuple<Version, TimePoint, State> snapshot() const { return {ver, updated_at, state}; }

    std::optional<bool> update(State new_state, TimePoint now) {
        if (new_state == state) {
            updated_at = now;
            return false;
        }
        state = std::move(new_state);
        updated_at = now;
        ++ver;
        return true;
    }

    std::optional<bool> replace(Version new_version, TimePoint now, State new_state) {
        if (new_version <= ver) {
            return false;
        }
        state = std::move(new_state);
        updated_at = now;
        ver = new_version;
        return true;
    }
};

static_assert(bricks::chantry::Versioned<TextDevice>,
              "TextDevice must satisfy Versioned");

// --- Not Versioned ---

struct SignedVersionDevice {
    using State = Counter;
    using Version = std::int32_t;
    using TimePoint = std::uint32_t;

    State state{};
    Version ver = 0;

    Version version() const { return ver; }
    std::tuple<Version, TimePoint, State> snapshot() const { return {ver, TimePoint{}, state}; }
    std::optional<bool> update(State, TimePoint) { return false; }
    std::optional<bool> replace(Version, TimePoint, State) { return false; }
};

static_assert(!bricks::chantry::Versioned<SignedVersionDevice>,
              "SignedVersionDevice must NOT satisfy Versioned (signed Version)");

struct NonSerializableStateDevice {
    using State = NoSerialize;
    using Version = std::uint32_t;
    using TimePoint = std::uint32_t;

    State state{};
    Version ver = 0;

    Version version() const { return ver; }
    std::tuple<Version, TimePoint, State> snapshot() const { return {ver, TimePoint{}, state}; }
    std::optional<bool> update(State, TimePoint) { return false; }
    std::optional<bool> replace(Version, TimePoint, State) { return false; }
};

static_assert(!bricks::chantry::Versioned<NonSerializableStateDevice>,
              "NonSerializableStateDevice must NOT satisfy Versioned (State not Serializable)");

struct BadUpdateDevice {
    using State = Counter;
    using Version = std::uint32_t;
    using TimePoint = std::uint32_t;

    State state{};
    Version ver = 0;

    Version version() const { return ver; }
    std::tuple<Version, TimePoint, State> snapshot() const { return {ver, TimePoint{}, state}; }
    bool update(State, TimePoint) { return false; }
    std::optional<bool> replace(Version, TimePoint, State) { return false; }
};

static_assert(!bricks::chantry::Versioned<BadUpdateDevice>,
              "BadUpdateDevice must NOT satisfy Versioned (wrong update return)");

struct MissingReplaceDevice {
    using State = Counter;
    using Version = std::uint32_t;
    using TimePoint = std::uint32_t;

    State state{};
    Version ver = 0;

    Version version() const { return ver; }
    std::tuple<Version, TimePoint, State> snapshot() const { return {ver, TimePoint{}, state}; }
    std::optional<bool> update(State, TimePoint) { return false; }
};

static_assert(!bricks::chantry::Versioned<MissingReplaceDevice>,
              "MissingReplaceDevice must NOT satisfy Versioned (no replace)");

struct MissingVersionMethod {
    using State = Counter;
    using Version = std::uint32_t;
    using TimePoint = std::uint32_t;

    State state{};
    Version ver = 0;

    std::tuple<Version, TimePoint, State> snapshot() const { return {ver, TimePoint{}, state}; }
    std::optional<bool> update(State, TimePoint) { return false; }
    std::optional<bool> replace(Version, TimePoint, State) { return false; }
};

static_assert(!bricks::chantry::Versioned<MissingVersionMethod>,
              "MissingVersionMethod must NOT satisfy Versioned (no version())");

// Non-const version() and snapshot()
struct NonConstAccessors {
    using State = Counter;
    using Version = std::uint32_t;
    using TimePoint = std::uint32_t;

    State state{};
    Version ver = 0;

    Version version() { return ver; }        // not const
    std::tuple<Version, TimePoint, State> snapshot() { return {ver, TimePoint{}, state}; } // not const
    std::optional<bool> update(State, TimePoint) { return false; }
    std::optional<bool> replace(Version, TimePoint, State) { return false; }
};

static_assert(!bricks::chantry::Versioned<NonConstAccessors>,
              "NonConstAccessors must NOT satisfy Versioned (version/snapshot not const)");

// ============================================================
// Repository test support
// ============================================================

using CounterRepository = bricks::chantry::Repository<std::uint16_t, CounterDevice>;

// ============================================================
// Runtime tests
// ============================================================

int main() {
    // Counter: serialize / deserialize round-trip
    {
        Counter orig{42};
        auto bytes = orig.serialize();
        auto restored = Counter::deserialize(bytes);
        assert(restored.has_value());
        assert(restored->value == 42);
    }

    // Counter: reject bad input
    {
        std::vector<std::uint8_t> bad = {0x01, 0x02};
        assert(!Counter::deserialize(bad).has_value());
    }

    // Text: round-trip
    {
        Text orig{"hello"};
        auto bytes = orig.serialize();
        auto restored = Text::deserialize(bytes);
        assert(restored.has_value());
        assert(restored->text == "hello");
    }

    // CounterDevice: version() + update
    {
        CounterDevice dev{};
        assert(dev.version() == 0);

        assert(*dev.update(Counter{10}, 100) == true);
        assert(dev.version() == 1);

        assert(*dev.update(Counter{10}, 120) == false);
        assert(dev.version() == 1);

        auto [ver, updated_at, state] = dev.snapshot();
        assert(ver == 1);
        assert(updated_at == 120);
        assert(state.value == 10);
    }

    // CounterDevice: replace with newer version
    {
        CounterDevice dev{.state = Counter{5}, .ver = 3};

        // Newer version accepted
        assert(*dev.replace(10, 200, Counter{99}) == true);
        assert(dev.version() == 10);
        assert(dev.snapshot() == std::make_tuple(10u, 200u, Counter{99}));

        // Older/equal version rejected
        assert(*dev.replace(10, 201, Counter{1}) == false);
        assert(*dev.replace(5, 202, Counter{1}) == false);
        assert(dev.version() == 10);
    }

    // CounterDevice: snapshot state is serializable
    {
        CounterDevice dev{.state = Counter{99}, .ver = 7};
        auto [ver, updated_at, state] = dev.snapshot();
        (void)ver;
        (void)updated_at;
        auto bytes = state.serialize();
        auto restored = Counter::deserialize(bytes);
        assert(restored.has_value());
        assert(restored->value == 99);
    }

    // TextDevice: update + replace + snapshot
    {
        TextDevice dev{};
        assert(*dev.update(Text{"hello"}, 10) == true);
        assert(*dev.update(Text{"hello"}, 11) == false);
        assert(dev.version() == 1);

        assert(*dev.replace(5, 20, Text{"replaced"}) == true);
        assert(dev.version() == 5);

        auto [ver, updated_at, state] = dev.snapshot();
        assert(ver == 5);
        assert(updated_at == 20);
        assert(state.text == "replaced");
    }

    // Repository: versions and snapshots expose data for glue layers
    {
        CounterRepository left_repo{1};
        CounterRepository right_repo{2};

        assert(left_repo.update_self(Counter{123}, 10) == true);
        assert(left_repo.get_self().value == 123);

        auto versions = left_repo.versions();
        assert(versions.size() == 1);
        assert(std::get<0>(versions[0]) == 1);
        assert(std::get<1>(versions[0]) == 1);

        auto snapshots = left_repo.snapshot(std::vector<std::uint16_t>{1, 999});
        assert(snapshots.size() == 1);
        assert(std::get<0>(snapshots[0]) == 1);
        assert(std::get<1>(snapshots[0]) == 1);
        assert(std::get<2>(snapshots[0]) == 10);
        assert(std::get<3>(snapshots[0]).value == 123);

        assert(right_repo.replace(std::get<0>(snapshots[0]), std::get<1>(snapshots[0]), 20, std::get<3>(snapshots[0])) == true);

        auto synced = right_repo.find(1);
        assert(synced.has_value());
        assert(std::get<0>(*synced) == 20);
        assert(std::get<1>(*synced).value == 123);
        assert(right_repo.has(1) == 20);
        assert(right_repo.get(1).has_value());
        assert(right_repo.get(1, 20).has_value());
        assert(right_repo.get(1, 20)->value == 123);
    }

    // Repository: stale remote state is ignored by replace
    {
        CounterRepository left_repo{1};
        CounterRepository right_repo{2};

        assert(left_repo.update_self(Counter{10}, 10) == true);
        assert(right_repo.replace(1, 5, 20, Counter{99}) == true);

        auto snapshots = left_repo.snapshot(std::vector<std::uint16_t>{1});
        assert(snapshots.size() == 1);
        assert(right_repo.replace(std::get<0>(snapshots[0]), std::get<1>(snapshots[0]), 30, std::get<3>(snapshots[0])) == false);

        auto current = right_repo.find(1);
        assert(current.has_value());
        assert(std::get<0>(*current) == 20);
        assert(std::get<1>(*current).value == 99);
        assert(!right_repo.get(1, 21).has_value());
        assert(right_repo.get(1, 20).has_value());
    }

    std::cout << "All chantry concept tests passed.\n";
    return 0;
}
