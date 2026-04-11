#pragma once

#include <compare>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <functional>
#include <vector>

namespace bricks::disnet {

template <typename T>
concept Address = requires(T address, const T other) {
    { address == other } -> std::convertible_to<bool>;
    { address <=> other } -> std::same_as<std::strong_ordering>;
};

template <Address AddressT>
struct TransportPacket {
    AddressT source;
    AddressT target;
    std::uint32_t source_seq;
    std::vector<std::uint8_t> payload;
};

template <Address AddressT>
using TransportReceiveCallback = std::function<void(TransportPacket<AddressT>)>;

template <typename T>
concept Addressed = requires {
    typename T::Address;
} && Address<typename T::Address>;

template <typename T>
concept HasPayloadCapacity = requires {
    { T::max_payload_size } -> std::convertible_to<std::size_t>;
};

template <typename T>
concept HasBroadcastAddress = requires {
    { T::broadcast_address() } -> std::same_as<typename T::Address>;
};

template <typename T>
concept HasOwnAddress = requires(T transport) {
    { transport.my_address() } -> std::same_as<typename T::Address>;
};

template <typename T>
concept Transport = Addressed<T> && HasPayloadCapacity<T> && HasBroadcastAddress<T> && HasOwnAddress<T>
                 && requires(T transport,
                             TransportPacket<typename T::Address> packet,
                             TransportReceiveCallback<typename T::Address> callback) {
    { transport.send(std::move(packet)) } -> std::same_as<void>;
    { transport.register_callback(std::move(callback)) } -> std::same_as<void>;
};

template <typename T, typename TransportT = typename T::Transport>
concept Router = Addressed<T> && HasPayloadCapacity<T> && HasBroadcastAddress<T> && HasOwnAddress<T>
              && Transport<TransportT>
              && requires(T router,
                          TransportT& transport,
                          TransportPacket<typename T::Address> packet,
                          const TransportPacket<typename TransportT::Address>& transport_packet,
                          TransportReceiveCallback<typename T::Address> callback) {
    typename T::Transport;
    requires std::same_as<typename T::Transport, TransportT>;

    { T{transport} };
    { router.send(std::move(packet)) } -> std::same_as<void>;
    { router.register_callback(std::move(callback)) } -> std::same_as<void>;
    { router.handle_packet(transport_packet) } -> std::same_as<void>;
};

} // namespace bricks::disnet
