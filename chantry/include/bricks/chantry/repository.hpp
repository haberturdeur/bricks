#pragma once

#include "bricks/utility/serdes.hpp"

#include <concepts>
#include <map>
#include <optional>
#include <tuple>
#include <utility>
#include <vector>

namespace bricks::chantry {

template <typename T>
concept Versioned = requires(const T cversioned, T versioned, typename T::State new_state,
                             typename T::Version new_version, typename T::TimePoint now) {
    typename T::State;
    typename T::Version;
    typename T::TimePoint;
    requires bricks::Serializable<typename T::State>;
    requires std::unsigned_integral<typename T::Version>;
    requires std::unsigned_integral<typename T::TimePoint>;

    { cversioned.version() } -> std::same_as<typename T::Version>;
    { cversioned.snapshot() } -> std::same_as<std::tuple<typename T::Version, typename T::TimePoint, typename T::State>>;

    { versioned.update(new_state, now) } -> std::same_as<std::optional<bool>>;
    { versioned.replace(new_version, now, new_state) } -> std::same_as<std::optional<bool>>;
};

template <typename AddressT, Versioned VersionedStateT>
class Repository {
public:
    using Address = AddressT;
    using VersionedState = VersionedStateT;
    using State = typename VersionedState::State;
    using Version = typename VersionedState::Version;
    using TimePoint = typename VersionedState::TimePoint;
    using UpdatedAt = TimePoint;
    using Found = std::tuple<UpdatedAt, State>;
    using VersionInfo = std::tuple<Address, Version>;
    using Snapshot = std::tuple<Address, Version, UpdatedAt, State>;

private:
    Address m_self;
    VersionedState m_self_state;
    std::map<Address, VersionedState> m_states;

public:
    /**
     * @brief Create a repository for one self-owned state.
     * @param self Self address.
     * @param self_state Initial self state.
     */
    explicit Repository(Address self, VersionedState self_state = {})
        : m_self(self), m_self_state(std::move(self_state)) {}

    /**
     * @brief Get the self address.
     */
    Address self() const {
        return m_self;
    }

    /**
     * @brief Update self state.
     * @param state New state.
     * @param now Current game time.
     */
    bool update_self(State state, TimePoint now) {
        return m_self_state.update(std::move(state), now).value_or(false);
    }

    /**
     * @brief Get self state.
     */
    State get_self() const {
        const auto [version, updated_at, state] = m_self_state.snapshot();
        (void)version;
        (void)updated_at;
        return state;
    }

    /**
     * @brief Replace a remote state if newer.
     * @param owner Remote owner address.
     * @param version Remote version.
     * @param now Current game time.
     * @param state Remote state.
     */
    bool replace(Address owner, Version version, TimePoint now, State state) {
        if (owner == m_self)
            return false;
        return m_states[owner].replace(version, now, std::move(state)).value_or(false);
    }

    /**
     * @brief Get known state.
     * @param owner Owner address.
     */
    std::optional<State> get(Address owner) const {
        std::optional<Found> found = find(owner);
        if (!found)
            return std::nullopt;
        return std::get<State>(*found);
    }

    /**
     * @brief Get known state if recent enough.
     * @param owner Owner address.
     * @param min_updated_at Minimum update time.
     */
    std::optional<State> get(Address owner, UpdatedAt min_updated_at) const {
        std::optional<Found> found = find(owner);
        if (!found || std::get<UpdatedAt>(*found) < min_updated_at)
            return std::nullopt;
        return std::get<State>(*found);
    }

    /**
     * @brief Get known state update time.
     * @param owner Owner address.
     */
    std::optional<UpdatedAt> has(Address owner) const {
        std::optional<Found> found = find(owner);
        if (!found)
            return std::nullopt;
        return std::get<UpdatedAt>(*found);
    }

    /**
     * @brief Find known state and update time.
     * @param owner Owner address.
     */
    std::optional<Found> find(Address owner) const {
        if (owner == m_self) {
            const auto [version, updated_at, state] = m_self_state.snapshot();
            (void)version;
            return Found{updated_at, state};
        }

        auto it = m_states.find(owner);
        if (it == m_states.end())
            return std::nullopt;

        const auto [version, updated_at, state] = it->second.snapshot();
        (void)version;
        return Found{updated_at, state};
    }

    /**
     * @brief List known versions.
     */
    std::vector<VersionInfo> versions() const {
        std::vector<VersionInfo> result;
        result.reserve(m_states.size() + 1);
        result.emplace_back(m_self, m_self_state.version());
        for (const auto& [owner, state] : m_states)
            result.emplace_back(owner, state.version());
        return result;
    }

    /**
     * @brief Snapshot requested states.
     * @param owners Owner addresses to read.
     */
    std::vector<Snapshot> snapshot(const std::vector<Address>& owners) const {
        std::vector<Snapshot> result;
        result.reserve(owners.size());
        for (Address owner : owners) {
            if (owner == m_self) {
                const auto [version, updated_at, state] = m_self_state.snapshot();
                result.emplace_back(owner, version, updated_at, state);
                continue;
            }

            auto it = m_states.find(owner);
            if (it == m_states.end())
                continue;

            const auto [version, updated_at, state] = it->second.snapshot();
            result.emplace_back(owner, version, updated_at, state);
        }
        return result;
    }
};

} // namespace bricks::chantry
