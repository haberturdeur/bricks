#pragma once

#include <MFRC522Driver.h>
#include <MFRC522v2.h>

#if __has_include(<driver/gpio.h>)
#include <driver/gpio.h>
#else
using gpio_num_t = int;
#endif

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <tuple>
#include <type_traits>
#include <vector>

namespace bricks {

template <typename T>
struct eager {
    using type = T;
};

template <typename T>
struct vector {
    using type = T;
};

template <typename T>
struct is_eager : std::false_type {};
template <typename T>
struct is_eager<eager<T>> : std::true_type {};

template <typename T>
struct is_vector : std::false_type {};
template <typename T>
struct is_vector<vector<T>> : std::true_type {};

template <typename T>
struct unwrap_eager {
    using type = T;
};
template <typename T>
struct unwrap_eager<eager<T>> {
    using type = T;
};

template <typename T>
struct vector_value_or_void {
    using type = void;
};
template <typename T>
struct vector_value_or_void<vector<T>> {
    using type = T;
};

template <typename... Records>
struct StateBuilder {
    using input_tuple = std::tuple<Records...>;

    static constexpr std::size_t fixed_record_count =
        ((is_vector<typename unwrap_eager<Records>::type>::value ? 0u : 1u) + ... + 0u);

    static constexpr std::size_t vector_count =
        ((is_vector<typename unwrap_eager<Records>::type>::value ? 1u : 0u) + ... + 0u);

    static_assert(vector_count <= 1, "StateBuilder supports at most one bricks::vector<T>");

    static constexpr std::size_t record_count = fixed_record_count;
    static constexpr std::size_t page_count = fixed_record_count;

    template <std::size_t I>
    using input_t = std::tuple_element_t<I, input_tuple>;

    template <std::size_t I>
    using record_t = typename unwrap_eager<input_t<I>>::type;

    template <typename T>
    static consteval std::size_t index_of() {
        constexpr bool is_vec[] = {is_vector<typename unwrap_eager<Records>::type>::value...};
        constexpr bool matches[] = {
            (std::is_same_v<T, typename unwrap_eager<Records>::type> &&
             !is_vector<typename unwrap_eager<Records>::type>::value)...
        };

        std::size_t fixed = 0;
        for (std::size_t i = 0; i < sizeof...(Records); ++i) {
            if (is_vec[i]) continue;
            if (matches[i]) return fixed;
            ++fixed;
        }
        return static_cast<std::size_t>(-1);
    }

    template <typename T>
    static consteval bool has_dynamic_vector() {
        return (std::is_same_v<T, typename vector_value_or_void<typename unwrap_eager<Records>::type>::type> || ... || false);
    }

    static consteval std::array<bool, page_count> eager_pages() {
        std::array<bool, page_count> flags{};
        constexpr bool eager_flags[] = {is_eager<Records>::value...};
        constexpr bool vec_flags[] = {is_vector<typename unwrap_eager<Records>::type>::value...};

        std::size_t fixed = 0;
        for (std::size_t i = 0; i < sizeof...(Records); ++i) {
            if (vec_flags[i]) continue;
            if (eager_flags[i]) flags[fixed] = true;
            ++fixed;
        }
        return flags;
    }
};

namespace mfrc522 {

struct SpiPinout {
    gpio_num_t miso;
    gpio_num_t mosi;
    gpio_num_t sck;
    gpio_num_t ss;
};

class SoftwareSPI {
public:
    explicit SoftwareSPI(SpiPinout pinout);
    void begin();
    std::uint8_t transfer(std::uint8_t data);
    void select();
    void deselect();

private:
    SpiPinout pinout_;
};

class DriverSPISoftware : public MFRC522Driver {
public:
    explicit DriverSPISoftware(SpiPinout pinout);

    bool init() override;
    void PCD_WriteRegister(PCD_Register reg, std::uint8_t value) override;
    void PCD_WriteRegister(PCD_Register reg, std::uint8_t count, std::uint8_t* values) override;
    std::uint8_t PCD_ReadRegister(PCD_Register reg) override;
    void PCD_ReadRegister(PCD_Register reg, std::uint8_t count, std::uint8_t* values, std::uint8_t rxAlign) override;

private:
    SoftwareSPI spi_;
};

class Session {
public:
    explicit Session(MFRC522& pcd);
    ~Session();

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    Session(Session&&) = default;
    Session& operator=(Session&&) = default;

    bool read_page(std::size_t page, std::array<std::uint8_t, 4>& out);
    bool write_page(std::size_t page, const std::array<std::uint8_t, 4>& in);
    bool read_word(std::size_t page, std::uint32_t& out);
    bool write_word(std::size_t page, std::uint32_t value);

    void abort();

private:
    MFRC522* pcd_;
};

template <typename StateDef, typename SessionT = Session>
class TypedSession {
public:
    TypedSession(SessionT&& session, std::size_t card_page_count)
        : session_(std::move(session)), card_page_count_(card_page_count) {
        constexpr std::array<bool, StateDef::page_count> eager = StateDef::eager_pages();
        cache_.reserve(StateDef::page_count);
        for (std::size_t p = 0; p < StateDef::page_count; ++p) {
            if (!eager[p]) continue;
            if (!is_in_range(p)) continue;

            std::uint32_t word = 0;
            if (session_.read_word(pages_base_ + p, word)) {
                cache_.push_back(CacheEntry{.page = p, .word = word});
            }
        }
    }

    [[nodiscard]] std::size_t max_vector_records() const {
        if (card_page_count_ <= pages_base_ + StateDef::fixed_record_count) return 0;
        return card_page_count_ - pages_base_ - StateDef::fixed_record_count;
    }

    template <std::size_t I>
    std::optional<typename StateDef::template record_t<I>> read() {
        using T = typename StateDef::template record_t<I>;
        static_assert(I < StateDef::record_count, "Index out of range");
        static_assert(sizeof(T) == 4, "Record must be exactly 32-bit");
        static_assert(std::is_trivially_copyable_v<T>, "Record must be trivially copyable");

        if (!load_page(I)) return std::nullopt;

        const CacheEntry* entry = find_cache(I);
        if (entry == nullptr) return std::nullopt;

        T out{};
        std::memcpy(&out, &entry->word, 4);
        return out;
    }

    template <typename T>
    std::optional<T> read() {
        constexpr std::size_t idx = StateDef::template index_of<T>();
        static_assert(idx != static_cast<std::size_t>(-1), "Record type not in StateBuilder");
        return read<idx>();
    }

    template <typename T>
    std::optional<T> read(std::size_t index) {
        static_assert(StateDef::template has_dynamic_vector<T>(), "Type is not declared as bricks::vector<T> in StateBuilder");
        static_assert(sizeof(T) == 4, "Record must be exactly 32-bit");
        static_assert(std::is_trivially_copyable_v<T>, "Record must be trivially copyable");

        if (index >= max_vector_records()) return std::nullopt;

        const std::size_t page = StateDef::fixed_record_count + index;
        if (!load_page(page)) return std::nullopt;

        const CacheEntry* entry = find_cache(page);
        if (entry == nullptr) return std::nullopt;

        T out{};
        std::memcpy(&out, &entry->word, 4);
        return out;
    }

    template <std::size_t I>
    bool write(const typename StateDef::template record_t<I>& value) {
        using T = typename StateDef::template record_t<I>;
        static_assert(I < StateDef::record_count, "Index out of range");
        static_assert(sizeof(T) == 4, "Record must be exactly 32-bit");
        static_assert(std::is_trivially_copyable_v<T>, "Record must be trivially copyable");

        if (!is_in_range(I)) return false;

        std::uint32_t word = 0;
        std::memcpy(&word, &value, 4);

        if (!session_.write_word(pages_base_ + I, word)) return false;

        std::uint32_t verify = 0;
        if (!session_.read_word(pages_base_ + I, verify)) return false;
        if (verify != word) return false;

        upsert_cache(I, word);
        return true;
    }

    template <typename T>
    bool write(const T& value) {
        constexpr std::size_t idx = StateDef::template index_of<T>();
        static_assert(idx != static_cast<std::size_t>(-1), "Record type not in StateBuilder");
        return write<idx>(value);
    }

    template <typename T>
    bool write(std::size_t index, const T& value) {
        static_assert(StateDef::template has_dynamic_vector<T>(), "Type is not declared as bricks::vector<T> in StateBuilder");
        static_assert(sizeof(T) == 4, "Record must be exactly 32-bit");
        static_assert(std::is_trivially_copyable_v<T>, "Record must be trivially copyable");

        if (index >= max_vector_records()) return false;

        std::uint32_t word = 0;
        std::memcpy(&word, &value, 4);

        const std::size_t page = StateDef::fixed_record_count + index;
        if (!session_.write_word(pages_base_ + page, word)) return false;

        std::uint32_t verify = 0;
        if (!session_.read_word(pages_base_ + page, verify)) return false;
        if (verify != word) return false;

        upsert_cache(page, word);
        return true;
    }

private:
    struct CacheEntry {
        std::size_t page;
        std::uint32_t word;
    };

    [[nodiscard]] bool is_in_range(std::size_t logical_page) const {
        return (pages_base_ + logical_page) < card_page_count_;
    }

    CacheEntry* find_cache(std::size_t page) {
        for (CacheEntry& e : cache_) {
            if (e.page == page) return &e;
        }
        return nullptr;
    }

    const CacheEntry* find_cache(std::size_t page) const {
        for (const CacheEntry& e : cache_) {
            if (e.page == page) return &e;
        }
        return nullptr;
    }

    void upsert_cache(std::size_t page, std::uint32_t word) {
        CacheEntry* entry = find_cache(page);
        if (entry != nullptr) {
            entry->word = word;
            return;
        }
        cache_.push_back(CacheEntry{.page = page, .word = word});
    }

    bool load_page(std::size_t page) {
        if (!is_in_range(page)) return false;
        if (find_cache(page) != nullptr) return true;

        std::uint32_t word = 0;
        if (!session_.read_word(pages_base_ + page, word)) return false;
        cache_.push_back(CacheEntry{.page = page, .word = word});
        return true;
    }

    SessionT session_;
    std::size_t card_page_count_;
    static constexpr std::size_t pages_base_ = 4;
    std::vector<CacheEntry> cache_{};
};

class Reader {
public:
    explicit Reader(SpiPinout pinout, std::size_t card_page_count = 48);

    void init();
    bool is_alive();
    bool new_card_present();
    std::string uid_hex() const;

    template <typename StateDef>
    TypedSession<StateDef, Session> start_session() {
        return TypedSession<StateDef, Session>{Session{pcd_}, card_page_count_};
    }

private:
    using Clock = std::chrono::steady_clock;

    DriverSPISoftware driver_;
    MFRC522 pcd_;
    std::size_t card_page_count_;
    Clock::time_point last_seen_time_ = Clock::now();
    MFRC522Constants::Uid last_uid_{};
};

}  // namespace mfrc522
}  // namespace bricks
