#pragma once

#include <cstring>
#include <set>
#include <stdexcept>
#include <vector>
#include <mutex>
#include <cstddef>
#include <cstdint>
#include <new>
#include <memory>
#include <iterator>
#include <type_traits>
#include <utility>
#include <algorithm>
#include <initializer_list>

namespace bricks::disnet::utils {
 
template <typename T>
class RingBuffer {
private:
    std::vector<T> _buffer;
    size_t _head;
    size_t _tail;

public:
    explicit RingBuffer(std::size_t capacity)
        : _buffer(capacity), _head(0), _tail(0) {
    }

    void push(const T& item) {
        if (full()) {
            throw std::overflow_error("RingBuffer is full");
        }

        _buffer[_head] = item;
        _head = (_head + 1) % _buffer.size();
        if (_head == _tail) {
            _tail = (_tail + 1) % _buffer.size(); // Overwrite the oldest element
        }
    }

    T pop() {
        if (empty()) {
            throw std::underflow_error("RingBuffer is empty");
        }

        T item = _buffer[_tail];
        _tail = (_tail + 1) % _buffer.size();
        return item;
    }

    bool empty() const {
        return _head == _tail;
    }

    bool full() const {
        return (_head + 1) % _buffer.size() == _tail;
    }

    size_t size() const {
        return (_head >= _tail) ? (_head - _tail) : (_buffer.size() - _tail + _head);
    }

    size_t capacity() const {
        return _buffer.size();
    }

};

template<typename T>
class DeduplicationTable {
    using IdSet = std::set<T>;
    using IdSetIterator = typename IdSet::iterator;

    IdSet _seen;
    RingBuffer<IdSetIterator> _ordering;

    std::mutex _mutex;

public:
    DeduplicationTable(std::size_t capacity = 100): _ordering(capacity) {}

    bool seen(const T& id) const {
        std::scoped_lock l(_mutex); 
        return _seen.find(id) != _seen.end();
    }

    void mark_seen(const T& id) {
        check_seen_and_mark(id);
    }

    bool check_seen_and_mark(const T& id) {
        std::scoped_lock l(_mutex); 
        if (_ordering.full()) {
            _seen.erase(_ordering.pop());
        }

        auto [it, inserted] = _seen.insert(id);
        if (inserted)
            _ordering.push(it);

        return !inserted;
    }
};

} // namespace bricks::disnet::utils

