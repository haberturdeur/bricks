#include "bricks/utility/packed_size.hpp"

#include <array>
#include <cstdint>
#include <iostream>

using namespace bricks::utility;

// --- Fundamentals ---

static_assert(packed_size<std::uint8_t> == 1);
static_assert(packed_size<std::uint16_t> == 2);
static_assert(packed_size<std::uint32_t> == 4);
static_assert(packed_size<std::uint64_t> == 8);
static_assert(packed_size<float> == 4);
static_assert(packed_size<double> == 8);
static_assert(packed_size<char> == 1);
static_assert(packed_size<bool> == 1);

// --- Enums ---

enum class FrameType : std::uint8_t { Data = 0, Preq = 1 };
static_assert(packed_size<FrameType> == 1);

enum BigEnum : std::uint32_t { A = 0 };
static_assert(packed_size<BigEnum> == 4);

// --- C-style arrays ---

static_assert(packed_size<std::uint8_t[6]> == 6);
static_assert(packed_size<std::uint32_t[4]> == 16);
static_assert(packed_size<std::uint16_t[3]> == 6);

// --- std::array ---

static_assert(packed_size<std::array<std::uint8_t, 6>> == 6);
static_assert(packed_size<std::array<std::uint32_t, 4>> == 16);
static_assert(packed_size<std::array<std::uint16_t, 3>> == 6);

// --- Simple aggregates ---

struct Empty {};
static_assert(packed_size<Empty> == 0);

struct SingleField {
    std::uint32_t x;
};
static_assert(packed_size<SingleField> == 4);

struct TwoFields {
    std::uint8_t a;
    std::uint32_t b;
};
// packed_size ignores padding: 1 + 4 = 5, NOT sizeof(TwoFields) which is likely 8
static_assert(packed_size<TwoFields> == 5);
static_assert(packed_size<TwoFields> != sizeof(TwoFields)); // proves we ignore padding

struct MixedFields {
    std::uint8_t type;
    std::uint8_t ttl;
    std::uint32_t seq;
    std::uint16_t metric;
};
// 1 + 1 + 4 + 2 = 8
static_assert(packed_size<MixedFields> == 8);

// --- Nested aggregates (recursive) ---

struct Address {
    std::array<std::uint8_t, 6> bytes;
};
static_assert(packed_size<Address> == 6);

struct DataFrameHeader {
    FrameType type;       // 1
    std::uint8_t ttl;     // 1
    Address source;       // 6
    Address target;       // 6
    std::uint32_t seq;    // 4
};
// 1 + 1 + 6 + 6 + 4 = 18
static_assert(packed_size<DataFrameHeader> == 18);

struct PreqFrame {
    FrameType type;            // 1
    std::uint8_t ttl;          // 1
    std::uint8_t flags;        // 1
    std::uint32_t preq_id;     // 4
    Address originator;        // 6
    std::uint32_t orig_seq;    // 4
    Address target;            // 6
    std::uint32_t target_seq;  // 4
    std::uint32_t metric;      // 4
};
// 1 + 1 + 1 + 4 + 6 + 4 + 6 + 4 + 4 = 31
static_assert(packed_size<PreqFrame> == 31);

// --- Nested structs inside structs ---

struct Outer {
    std::uint8_t header;
    DataFrameHeader frame;
    std::uint16_t checksum;
};
// 1 + 18 + 2 = 21
static_assert(packed_size<Outer> == 21);

// --- std::array of aggregates ---

static_assert(packed_size<std::array<Address, 3>> == 18);
static_assert(packed_size<std::array<DataFrameHeader, 2>> == 36);

// --- Arrays inside structs ---

struct WithArray {
    std::uint8_t type;
    std::array<std::uint8_t, 4> data;
    std::uint32_t crc;
};
// 1 + 4 + 4 = 9
static_assert(packed_size<WithArray> == 9);

// --- Deeply nested ---

struct Inner {
    std::uint16_t x;
    std::uint16_t y;
};

struct Middle {
    Inner pos;
    std::uint8_t flags;
};

struct Deep {
    std::uint32_t id;
    Middle mid;
    std::uint8_t tail;
};
// Inner: 2+2=4, Middle: 4+1=5, Deep: 4+5+1=10
static_assert(packed_size<Inner> == 4);
static_assert(packed_size<Middle> == 5);
static_assert(packed_size<Deep> == 10);

int main() {
    std::cout << "All packed_size tests passed.\n";
    return 0;
}
