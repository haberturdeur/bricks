#include "bricks/disnet/mux.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <optional>
#include <ostream>
#include <span>
#include <utility>
#include <vector>

using namespace bricks::disnet;

namespace {

struct TestAddress {
    std::uint8_t value = 0;

    auto operator<=>(const TestAddress&) const = default;

    friend std::ostream& operator<<(std::ostream& os, const TestAddress& address) {
        return os << static_cast<unsigned>(address.value);
    }
};

class CapturingTransport {
public:
    using Address = TestAddress;
    static constexpr std::size_t max_payload_size = 256;

    explicit CapturingTransport(Address self) : m_self(self) {}

    static constexpr Address broadcast_address() {
        return Address{0xFF};
    }

    Address my_address() const {
        return m_self;
    }

    void send(TransportPacket<Address> packet) {
        sent.push_back(std::move(packet));
    }

    void register_callback(TransportReceiveCallback<Address> callback) {
        m_callback = std::move(callback);
    }

    void receive(TransportPacket<Address> packet) const {
        if (m_callback) {
            m_callback(std::move(packet));
        }
    }

    std::vector<TransportPacket<Address>> sent;

private:
    Address m_self{};
    TransportReceiveCallback<Address> m_callback;
};

static_assert(Transport<CapturingTransport>);

struct AppData {
    std::uint8_t value = 0;

    std::vector<std::uint8_t> serialize() const {
        return {value};
    }

    static std::optional<AppData> deserialize(std::span<const std::uint8_t> bytes) {
        if (bytes.size() != 1)
            return std::nullopt;
        return AppData{.value = bytes[0]};
    }
};

struct StatusData {
    std::uint8_t code = 0;

    std::vector<std::uint8_t> serialize() const {
        return {code};
    }

    static std::optional<StatusData> deserialize(std::span<const std::uint8_t> bytes) {
        if (bytes.size() != 1)
            return std::nullopt;
        return StatusData{.code = bytes[0]};
    }
};

struct TunnelData {
    TestAddress origin{};
    EncodedPacket inner{};

    std::vector<std::uint8_t> serialize() const {
        std::vector<std::uint8_t> out;
        out.reserve(2 + inner.payload.size());
        out.push_back(origin.value);
        out.push_back(inner.packet_index);
        out.insert(out.end(), inner.payload.begin(), inner.payload.end());
        return out;
    }

    static std::optional<TunnelData> deserialize(std::span<const std::uint8_t> bytes) {
        if (bytes.size() < 2)
            return std::nullopt;
        return TunnelData{
            .origin = TestAddress{bytes[0]},
            .inner = EncodedPacket{.packet_index = bytes[1], .payload = {bytes.begin() + 2, bytes.end()}},
        };
    }
};

using Packets = PacketSet<AppData, StatusData, TunnelData>;
using Net = PacketMux<CapturingTransport, Packets>;

} // namespace

int main() {
    CapturingTransport a_transport{TestAddress{1}};
    CapturingTransport b_transport{TestAddress{2}};
    Net a{a_transport};
    Net b{b_transport};

    std::vector<std::pair<TestAddress, AppData>> app_received;
    std::vector<std::pair<TestAddress, StatusData>> status_received;

    b.on<AppData>([&](TestAddress source, const AppData& packet) {
        app_received.push_back({source, packet});
    });
    b.on<StatusData>([&](TestAddress source, const StatusData& packet) {
        status_received.push_back({source, packet});
    });
    b.on<TunnelData>([&](TestAddress, const TunnelData& packet) {
        b.resolve(packet.origin, packet.inner);
    });

    a.send(TestAddress{2}, AppData{.value = 42});
    a.send(TestAddress{2}, StatusData{.code = 7});
    a.send(TestAddress{2}, TunnelData{
        .origin = TestAddress{99},
        .inner = Net::serialize(AppData{.value = 123}),
    });

    assert(a_transport.sent.size() == 3);
    b_transport.receive(a_transport.sent[0]);
    b_transport.receive(a_transport.sent[1]);
    b_transport.receive(a_transport.sent[2]);

    assert(app_received.size() == 2);
    assert(app_received[0].first == TestAddress{1});
    assert(app_received[0].second.value == 42);
    assert(app_received[1].first == TestAddress{99});
    assert(app_received[1].second.value == 123);

    assert(status_received.size() == 1);
    assert(status_received[0].first == TestAddress{1});
    assert(status_received[0].second.code == 7);

    std::cout << "All mux protocol tests passed.\n";
    return 0;
}
