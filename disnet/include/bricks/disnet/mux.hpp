#pragma once

#include "bricks/disnet/transport.hpp"
#include "bricks/utility/serdes.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <utility>
#include <variant>
#include <vector>

namespace bricks::disnet {

template <typename... Ts>
struct PacketSet {
    using variant_type = std::variant<Ts...>;
    static constexpr std::size_t count = sizeof...(Ts);
};

template <typename T>
concept Protocol = requires {
    typename T::Packets;
};

struct EncodedPacket {
    std::uint8_t packet_index = 0;
    std::vector<std::uint8_t> payload;
};

namespace detail {

inline std::vector<std::uint8_t> encode_packet_envelope(const EncodedPacket& packet) {
    std::vector<std::uint8_t> out;
    out.reserve(1 + packet.payload.size());
    out.push_back(packet.packet_index);
    out.insert(out.end(), packet.payload.begin(), packet.payload.end());
    return out;
}

inline std::optional<EncodedPacket> decode_packet_envelope(std::span<const std::uint8_t> bytes) {
    if (bytes.empty())
        return std::nullopt;
    return EncodedPacket{
        .packet_index = bytes[0],
        .payload = {bytes.begin() + 1, bytes.end()},
    };
}

template <typename Packet, typename Set>
inline constexpr bool packet_in_set_v = false;

template <typename Packet, typename... Packets>
inline constexpr bool packet_in_set_v<Packet, PacketSet<Packets...>> = (std::same_as<Packet, Packets> || ...);

template <typename Packet, typename Set>
concept PacketInSet = packet_in_set_v<Packet, Set>;

template <typename Packet, typename... Packets>
consteval std::size_t packet_set_index_impl() {
    std::size_t result = 0;
    std::size_t current = 0;
    ((std::same_as<Packet, Packets> ? result = current : 0, ++current), ...);
    return result;
}

template <typename Packet, typename Set>
struct packet_set_index;

template <typename Packet, typename... Packets>
struct packet_set_index<Packet, PacketSet<Packets...>> {
    static_assert((std::same_as<Packet, Packets> || ...), "Packet is not present in this PacketSet");
    static constexpr std::size_t value = packet_set_index_impl<Packet, Packets...>();
};

template <typename Packet, typename Set>
inline constexpr std::size_t packet_set_index_v = packet_set_index<Packet, Set>::value;

template <typename PacketSetT, bricks::Serializable Packet>
EncodedPacket serialize_packet(const Packet& packet) {
    static_assert(PacketInSet<Packet, PacketSetT>, "Packet is not present in this PacketSet");
    static_assert(packet_set_index_v<Packet, PacketSetT> <= 0xFF, "Mux packet index must fit in one byte");
    return EncodedPacket{
        .packet_index = static_cast<std::uint8_t>(packet_set_index_v<Packet, PacketSetT>),
        .payload = bricks::serialize(packet),
    };
}

template <std::size_t I, typename PacketSetT, typename Callback>
bool deserialize_packet_at(const std::vector<std::uint8_t>& payload, Callback& callback) {
    using Packet = std::variant_alternative_t<I, typename PacketSetT::variant_type>;
    std::optional<Packet> packet = bricks::deserialize<Packet>(std::span<const std::uint8_t>(payload.data(), payload.size()));
    if (!packet)
        return false;
    callback(std::move(*packet));
    return true;
}

template <typename PacketSetT, typename Callback, std::size_t... Is>
bool deserialize_packet_impl(const EncodedPacket& encoded, Callback&& callback, std::index_sequence<Is...>) {
    bool decoded = false;
    ((encoded.packet_index == Is ? (decoded = deserialize_packet_at<Is, PacketSetT>(encoded.payload, callback), true)
                                 : false)
     || ...);
    return decoded;
}

template <typename PacketSetT, typename Callback>
bool deserialize_packet(const EncodedPacket& encoded, Callback&& callback) {
    return deserialize_packet_impl<PacketSetT>(
        encoded, std::forward<Callback>(callback),
        std::make_index_sequence<std::variant_size_v<typename PacketSetT::variant_type>>{});
}

} // namespace detail

template <Transport TransportT, typename PacketSetT>
class PacketMux;

template <Transport TransportT, typename... Packets>
class PacketMux<TransportT, PacketSet<Packets...>> {
public:
    using Transport = TransportT;
    using Address = typename Transport::Address;
    using PacketsT = PacketSet<Packets...>;
    using Variant = typename PacketsT::variant_type;

private:
    Transport& m_transport;
    std::uint32_t m_source_seq = 0;
    std::array<std::function<void(Address, Variant&)>, sizeof...(Packets)> m_handlers{};

    template <typename Packet>
    void dispatch(Address source, Packet packet) {
        constexpr std::size_t idx = detail::packet_set_index_v<Packet, PacketsT>;
        if (!m_handlers[idx])
            return;
        Variant variant = std::move(packet);
        m_handlers[idx](source, variant);
    }

public:
    /**
     * @brief Create a packet mux over a transport.
     * @param transport Underlying transport.
     */
    explicit PacketMux(Transport& transport) : m_transport(transport) {
        m_transport.register_callback([this](TransportPacket<Address> packet) {
            handle_transport_packet(std::move(packet));
        });
    }

    /**
     * @brief Get this node address.
     */
    Address my_address() const {
        return m_transport.my_address();
    }

    /**
     * @brief Get transport broadcast address.
     */
    static Address broadcast_address() {
        return Transport::broadcast_address();
    }

    /**
     * @brief Serialize a typed packet with its packet index.
     * @param packet Packet to serialize.
     */
    template <typename Packet>
    static EncodedPacket serialize(const Packet& packet) {
        return detail::serialize_packet<PacketsT>(packet);
    }

    /**
     * @brief Send a typed packet.
     * @param target Destination address.
     * @param packet Packet to send.
     */
    template <typename Packet>
    void send(Address target, const Packet& packet) {
        m_transport.send(TransportPacket<Address>{
            .source = my_address(),
            .target = target,
            .source_seq = ++m_source_seq,
            .payload = detail::encode_packet_envelope(serialize(packet)),
        });
    }

    /**
     * @brief Register a packet handler.
     * @param fn Handler called with source and packet.
     */
    template <typename Packet, typename Fn>
    void on(Fn&& fn) {
        static_assert(detail::PacketInSet<Packet, PacketsT>, "Packet is not present in this PacketSet");
        constexpr std::size_t idx = detail::packet_set_index_v<Packet, PacketsT>;
        m_handlers[idx] = [handler = std::forward<Fn>(fn)](Address source, Variant& packet) {
            handler(source, std::get<Packet>(packet));
        };
    }

    /**
     * @brief Handle a transport packet.
     * @param packet Incoming transport packet.
     */
    void handle_transport_packet(TransportPacket<Address> packet) {
        std::optional<EncodedPacket> encoded = detail::decode_packet_envelope(
            std::span<const std::uint8_t>(packet.payload.data(), packet.payload.size()));
        if (!encoded)
            return;

        resolve(packet.source, std::move(*encoded));
    }

    /**
     * @brief Resolve an encoded packet recursively.
     * @param source Logical source address.
     * @param packet Encoded packet.
     */
    void resolve(Address source, EncodedPacket packet) {
        (void)detail::deserialize_packet<PacketsT>(packet, [this, source](auto decoded) {
            dispatch(source, std::move(decoded));
        });
    }
};

} // namespace bricks::disnet
