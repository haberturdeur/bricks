#pragma once

#include <compare>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <ostream>

namespace bricks::disnet {

struct MacAddress {
    std::uint8_t m_data[6]{};

    std::uint8_t* data() {
        return m_data;
    }

    const std::uint8_t* data() const {
        return m_data;
    }

    bool operator==(const MacAddress& other) const {
        return std::memcmp(m_data, other.m_data, sizeof(m_data)) == 0;
    }

    std::strong_ordering operator<=>(const MacAddress& other) const {
        const int cmp = std::memcmp(m_data, other.m_data, sizeof(m_data));
        if (cmp < 0)
            return std::strong_ordering::less;
        if (cmp > 0)
            return std::strong_ordering::greater;
        return std::strong_ordering::equal;
    }

    friend std::ostream& operator<<(std::ostream& os, const MacAddress& addr) {
        auto flags = os.flags();
        auto fill = os.fill();
        os << std::hex << std::uppercase << std::setfill('0');
        for (int i = 0; i < 6; ++i) {
            if (i > 0)
                os << ':';
            os << std::setw(2) << static_cast<unsigned>(addr.m_data[i]);
        }
        os.flags(flags);
        os.fill(fill);
        return os;
    }
};

} // namespace bricks::disnet
