#pragma once

#include <array>
#include <cstddef>
#include <tuple>
#include <type_traits>
#include <utility>

namespace bricks {

namespace detail {

// --- Forward declaration ---
template <typename T>
struct packed_size_impl;

// --- Aggregate member counting ---

struct any_field {
    template <typename T>
        requires(!std::same_as<T, const char*> && !std::same_as<T, std::nullptr_t>)
    constexpr operator T() const;
};

template <typename T, typename... Args>
    requires std::is_aggregate_v<T>
consteval std::size_t count_fields() {
    if constexpr (requires { T{Args{}..., any_field{}}; }) {
        return count_fields<T, Args..., any_field>();
    } else {
        return sizeof...(Args);
    }
}

// --- Sum packed_size of each member via structured bindings ---
// Returns the sum of packed_size for each field, recursively.

template <typename T>
consteval std::size_t aggregate_packed_size() {
    constexpr std::size_t N = count_fields<T>();

    if constexpr (N == 0) {
        return 0;
    } else {
        // We need to get member types. Use a lambda with structured bindings
        // that builds a tuple of pointers-to-members' types, then sum their packed_size.
        // Since we can't return from structured bindings in consteval easily,
        // we use a helper that deduces types from a reference.
        return []<std::size_t... Is>(std::index_sequence<Is...>) {
            // Create a default-constructed T to decompose
            // (this is fine in consteval context for aggregates)
            T val{};
            if constexpr (N == 1) {
                auto& [a] = val;
                return (packed_size_impl<std::remove_cvref_t<decltype(a)>>::value);
            } else if constexpr (N == 2) {
                auto& [a, b] = val;
                return (packed_size_impl<std::remove_cvref_t<decltype(a)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(b)>>::value);
            } else if constexpr (N == 3) {
                auto& [a, b, c] = val;
                return (packed_size_impl<std::remove_cvref_t<decltype(a)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(b)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(c)>>::value);
            } else if constexpr (N == 4) {
                auto& [a, b, c, d] = val;
                return (packed_size_impl<std::remove_cvref_t<decltype(a)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(b)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(c)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(d)>>::value);
            } else if constexpr (N == 5) {
                auto& [a, b, c, d, e] = val;
                return (packed_size_impl<std::remove_cvref_t<decltype(a)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(b)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(c)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(d)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(e)>>::value);
            } else if constexpr (N == 6) {
                auto& [a, b, c, d, e, f] = val;
                return (packed_size_impl<std::remove_cvref_t<decltype(a)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(b)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(c)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(d)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(e)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(f)>>::value);
            } else if constexpr (N == 7) {
                auto& [a, b, c, d, e, f, g] = val;
                return (packed_size_impl<std::remove_cvref_t<decltype(a)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(b)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(c)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(d)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(e)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(f)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(g)>>::value);
            } else if constexpr (N == 8) {
                auto& [a, b, c, d, e, f, g, h] = val;
                return (packed_size_impl<std::remove_cvref_t<decltype(a)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(b)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(c)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(d)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(e)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(f)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(g)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(h)>>::value);
            } else if constexpr (N == 9) {
                auto& [a, b, c, d, e, f, g, h, i] = val;
                return (packed_size_impl<std::remove_cvref_t<decltype(a)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(b)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(c)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(d)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(e)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(f)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(g)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(h)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(i)>>::value);
            } else if constexpr (N == 10) {
                auto& [a, b, c, d, e, f, g, h, i, j] = val;
                return (packed_size_impl<std::remove_cvref_t<decltype(a)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(b)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(c)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(d)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(e)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(f)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(g)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(h)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(i)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(j)>>::value);
            } else if constexpr (N == 11) {
                auto& [a, b, c, d, e, f, g, h, i, j, k] = val;
                return (packed_size_impl<std::remove_cvref_t<decltype(a)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(b)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(c)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(d)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(e)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(f)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(g)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(h)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(i)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(j)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(k)>>::value);
            } else if constexpr (N == 12) {
                auto& [a, b, c, d, e, f, g, h, i, j, k, l] = val;
                return (packed_size_impl<std::remove_cvref_t<decltype(a)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(b)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(c)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(d)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(e)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(f)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(g)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(h)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(i)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(j)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(k)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(l)>>::value);
            } else if constexpr (N == 13) {
                auto& [a, b, c, d, e, f, g, h, i, j, k, l, m] = val;
                return (packed_size_impl<std::remove_cvref_t<decltype(a)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(b)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(c)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(d)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(e)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(f)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(g)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(h)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(i)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(j)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(k)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(l)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(m)>>::value);
            } else if constexpr (N == 14) {
                auto& [a, b, c, d, e, f, g, h, i, j, k, l, m, n] = val;
                return (packed_size_impl<std::remove_cvref_t<decltype(a)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(b)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(c)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(d)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(e)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(f)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(g)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(h)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(i)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(j)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(k)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(l)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(m)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(n)>>::value);
            } else if constexpr (N == 15) {
                auto& [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o] = val;
                return (packed_size_impl<std::remove_cvref_t<decltype(a)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(b)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(c)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(d)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(e)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(f)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(g)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(h)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(i)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(j)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(k)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(l)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(m)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(n)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(o)>>::value);
            } else if constexpr (N == 16) {
                auto& [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p] = val;
                return (packed_size_impl<std::remove_cvref_t<decltype(a)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(b)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(c)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(d)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(e)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(f)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(g)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(h)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(i)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(j)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(k)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(l)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(m)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(n)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(o)>>::value +
                        packed_size_impl<std::remove_cvref_t<decltype(p)>>::value);
            } else {
                static_assert(N <= 16, "packed_size supports aggregates with up to 16 members");
                return std::size_t{0};
            }
        }(std::make_index_sequence<N>{});
    }
}

// --- packed_size_impl specializations ---

// Fundamental/enum types
template <typename T>
    requires(std::is_arithmetic_v<T> || std::is_enum_v<T>)
struct packed_size_impl<T> {
    static constexpr std::size_t value = sizeof(T);
};

// C-style arrays
template <typename T, std::size_t N>
struct packed_size_impl<T[N]> {
    static constexpr std::size_t value = N * packed_size_impl<T>::value;
};

// std::array
template <typename T, std::size_t N>
struct packed_size_impl<std::array<T, N>> {
    static constexpr std::size_t value = N * packed_size_impl<T>::value;
};

// Aggregates (recursive via structured bindings)
template <typename T>
    requires(std::is_aggregate_v<T> && !std::is_array_v<T> &&
             !std::is_arithmetic_v<T> && !std::is_enum_v<T> &&
             !requires { typename std::tuple_size<T>::type; }) // exclude std::array
struct packed_size_impl<T> {
    static constexpr std::size_t value = aggregate_packed_size<T>();
};

} // namespace detail

/// Compute the packed (wire-format) size of a type at compile time.
/// Recursively sums sizeof for each field, ignoring struct padding.
/// Works on: fundamentals, enums, C-arrays, std::array, and aggregates (up to 16 members).
/// NOTE: Struct members must use std::array<T,N> instead of C-style arrays (T[N]).
///       C-style arrays confuse aggregate-init-based member counting.
template <typename T>
inline constexpr std::size_t packed_size = detail::packed_size_impl<T>::value;

} // namespace bricks
