#pragma once

#include <bricks/exceptions.hpp>

#include <esp_err.h>
#include <esp_log.h>
#include <esp_partition.h>
#include <wear_leveling.h>

#include <cstddef>
#include <cstdint>
#include <vector>
#include <optional>
#include <concepts>

namespace bricks::chronicler {
    
template <typename T>
concept Serializable =
    (requires(const T& t) {
        { t.serialize() } -> std::same_as<std::vector<std::uint8_t>>;
    } || requires(const T& t, std::vector<std::uint8_t>& buf) {
        { t.serialize(buf) } -> std::same_as<void>;
    }) && requires {
        { T::serialized_size() } -> std::same_as<std::size_t>;
    };

template <typename T>
concept Deserializable = requires(T& t, const std::vector<std::uint8_t>& buf) {
    { t.deserialize(buf) } -> std::same_as<void>;
} || requires(const std::vector<std::uint8_t>& buf) {
    { T::deserialize(buf) } -> std::same_as<T>;
};

template <typename T>
concept Loggable = Serializable<T> && Deserializable<T>;

template <Loggable T> 
class Chronicler {
private:
    struct Sizes {
        std::size_t _sector_size;
        std::size_t _partition_size;

        std::size_t sector() const { return _sector_size; }
        std::size_t partition() const { return _partition_size; }
        std::size_t control() const { return _sector_size / T::serialized_size() }
    };
    
    wl_handle_t _wl_handle = WL_INVALID_HANDLE;

    void _update_meta() {
        _sector_size = wl_sector_size(_wl_handle);
        _partition_size = wl_size(_wl_handle);
    }

    Chronicler(const esp_partition_t* part) {
        CHECK_IDF_ERROR(wl_mount(part, &_wl_handle));
    }

public:

    /**
     * Attempts to load the existing log data from the specified partition.
     * Returns std::nullopt if no chronicler data is found on the partition.
     * Throws an exception if any I/O operation fails during the process.
     *
     * @param part - Pointer to the partition from which the log is to be loaded
     *
     * @return std::optional<Chronicler> - A Chronicler object if the load is successful, std::nullopt if no log data is found
     *
     * @throws bricks::exceptions::IDF if any write or read operation fails during the process
     */
    static std::optional<Chronicler> try_load(const esp_partition_t* part) {
        return std::nullopt;
    }

    static Chronicler create(const esp_partition_t* part) {
    }

    static Chronicler load_or_create(const esp_partition_t* part) {
        return load(part).value_or(create(part));
    }

    void push(const T& entry);

    T get(std::size_t idx) const;

    std::size_t size() const {
        if (_wl_handle == WL_INVALID_HANDLE)
            throw exceptions::InvalidState("Chronicler not initialized");
    }

    std::size_t capacity() const {
        if (_wl_handle == WL_INVALID_HANDLE)
            throw exceptions::InvalidState("Chronicler not initialized");

        return _partition_size;
    }
    
    Chronicler(const Chronicler&) = delete;
    Chronicler& operator=(const Chronicler&) = delete;

    Chronicler(Chronicler&& o)
        : _wl_handle(o._wl_handle) {
        o._wl_handle = WL_INVALID_HANDLE;
    }

    Chronicler& operator=(Chronicler&& o) {
        reset();

        _wl_handle = o._wl_handle;
        o._wl_handle = WL_INVALID_HANDLE;

        return *this;
    }

    void reset() {
        if (_wl_handle != WL_INVALID_HANDLE) {
            CHECK_IDF_ERROR(wl_unmount(_wl_handle));
            _wl_handle = WL_INVALID_HANDLE;
        }
    }

    ~Chronicler() {
        reset();
    }
};

} // namespace bricks::chronicler
