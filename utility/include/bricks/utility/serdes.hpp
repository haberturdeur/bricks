#pragma once

#include <concepts>
#include <cstdint>
#include <optional>
#include <span>
#include <type_traits>
#include <vector>

namespace bricks {

namespace detail {

void serialize();
void deserialize();

template <typename T>
concept MemberSerializable = requires(T value, std::span<const std::uint8_t> bytes) {
    { value.serialize() } -> std::same_as<std::vector<std::uint8_t>>;
    { T::deserialize(bytes) } -> std::same_as<std::optional<T>>;
};

template <typename T>
concept AdlSerializable = requires(T value, std::span<const std::uint8_t> bytes) {
    { serialize(value) } -> std::same_as<std::vector<std::uint8_t>>;
    { deserialize(std::type_identity<T>{}, bytes) } -> std::same_as<std::optional<T>>;
};

template <AdlSerializable T>
std::vector<std::uint8_t> adl_serialize(const T& value) {
    return serialize(value);
}

template <AdlSerializable T>
std::optional<T> adl_deserialize(std::span<const std::uint8_t> bytes) {
    return deserialize(std::type_identity<T>{}, bytes);
}

} // namespace detail

template <typename T>
concept Serializable = detail::MemberSerializable<T> || detail::AdlSerializable<T>;

template <Serializable T>
std::vector<std::uint8_t> serialize(const T& value) {
    if constexpr (detail::MemberSerializable<T>) {
        return value.serialize();
    } else {
        return detail::adl_serialize(value);
    }
}

template <Serializable T>
std::optional<T> deserialize(std::span<const std::uint8_t> bytes) {
    if constexpr (detail::MemberSerializable<T>) {
        return T::deserialize(bytes);
    } else {
        return detail::adl_deserialize<T>(bytes);
    }
}

} // namespace bricks
