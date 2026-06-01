#include <bricks/mfrc522.hpp>

#include <cassert>
#include <cstdint>
#include <optional>
#include <vector>

namespace {

struct RecordA { std::uint32_t raw; };
struct RecordB { std::uint32_t raw; };
struct RecordC { std::uint32_t raw; };

using State = bricks::StateBuilder<bricks::eager<RecordA>, RecordB, bricks::vector<RecordC>>;

static_assert(sizeof(RecordA) == 4);
static_assert(State::fixed_record_count == 2);
static_assert(State::record_count == 2);
static_assert(State::page_count == 2);
static_assert(State::template index_of<RecordA>() == 0);
static_assert(State::template index_of<RecordB>() == 1);
static_assert(State::template has_dynamic_vector<RecordC>());

struct FakeSession {
    std::vector<std::uint32_t> memory;

    bool read_word(std::size_t page, std::uint32_t& out) {
        if (page >= memory.size()) return false;
        out = memory[page];
        return true;
    }

    bool write_word(std::size_t page, std::uint32_t value) {
        if (page >= memory.size()) return false;
        memory[page] = value;
        return true;
    }
};

void test_read_fixed_and_eager() {
    FakeSession s{.memory = std::vector<std::uint32_t>(32, 0)};
    s.memory[4] = 0x01020304;
    s.memory[5] = 0x11223344;

    bricks::mfrc522::TypedSession<State, FakeSession> typed(std::move(s), 32);

    std::optional<RecordA> a = typed.read<RecordA>();
    std::optional<RecordB> b = typed.read<1>();

    assert(a.has_value());
    assert(b.has_value());
    assert(a->raw == 0x01020304);
    assert(b->raw == 0x11223344);
}

void test_write_fixed_with_verify() {
    FakeSession s{.memory = std::vector<std::uint32_t>(32, 0)};
    bricks::mfrc522::TypedSession<State, FakeSession> typed(std::move(s), 32);

    const bool ok = typed.write<RecordB>(RecordB{.raw = 0x55667788});
    assert(ok);

    std::optional<RecordB> b = typed.read<RecordB>();
    assert(b.has_value());
    assert(b->raw == 0x55667788);
}

void test_vector_bounds_and_rw() {
    FakeSession s{.memory = std::vector<std::uint32_t>(10, 0)};
    // card pages = 10, usable after base=4 and fixed=2 => 4 entries
    bricks::mfrc522::TypedSession<State, FakeSession> typed(std::move(s), 10);

    assert(typed.max_vector_records() == 4);

    const bool ok0 = typed.write<RecordC>(0, RecordC{.raw = 0xAA});
    const bool ok3 = typed.write<RecordC>(3, RecordC{.raw = 0xDD});
    const bool bad = typed.write<RecordC>(4, RecordC{.raw = 0xEE});

    assert(ok0);
    assert(ok3);
    assert(!bad);

    std::optional<RecordC> c0 = typed.read<RecordC>(0);
    std::optional<RecordC> c3 = typed.read<RecordC>(3);
    std::optional<RecordC> c4 = typed.read<RecordC>(4);

    assert(c0.has_value());
    assert(c3.has_value());
    assert(!c4.has_value());
    assert(c0->raw == 0xAA);
    assert(c3->raw == 0xDD);
}

} // namespace

int main() {
    test_read_fixed_and_eager();
    test_write_fixed_with_verify();
    test_vector_bounds_and_rw();
}
