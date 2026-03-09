#include "fake_platform.hpp"

#include "esp_err.h"
#include "esp_mac.h"
#include "esp_now.h"
#include "esp_random.h"
#include "esp_system.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <random>
#include <thread>
#include <unordered_set>
#include <vector>

namespace {

std::mutex g_tx_mutex;
std::vector<fake_platform::TxFrame> g_tx_frames;

struct Queue {
    std::size_t item_size = 0;
    std::size_t capacity = 0;
    std::mutex mutex;
    std::condition_variable cv;
    std::deque<std::vector<std::uint8_t>> items;
};

std::mutex g_queue_registry_mutex;
std::unordered_set<Queue*> g_live_queues;

std::atomic<std::uint32_t> g_rng{0x12345678};

} // namespace

namespace fake_platform {

void reset() {
    std::scoped_lock l(g_tx_mutex);
    g_tx_frames.clear();
}

std::vector<TxFrame> take_tx_frames() {
    std::scoped_lock l(g_tx_mutex);
    std::vector<TxFrame> out = std::move(g_tx_frames);
    g_tx_frames.clear();
    return out;
}

} // namespace fake_platform

extern "C" const char* esp_err_to_name(esp_err_t err) {
    return err == ESP_OK ? "ESP_OK" : "ESP_FAIL";
}

extern "C" void esp_system_abort(const char* details) {
    (void)details;
    std::abort();
}

extern "C" void esp_read_mac(std::uint8_t* mac, int type) {
    (void)type;
    const std::array<std::uint8_t, 6> addr = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
    std::memcpy(mac, addr.data(), addr.size());
}

extern "C" std::uint32_t esp_random(void) {
    std::uint32_t x = g_rng.load(std::memory_order_relaxed);
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rng.store(x, std::memory_order_relaxed);
    return x;
}

extern "C" esp_err_t esp_now_init(void) {
    return ESP_OK;
}

extern "C" esp_err_t esp_now_deinit(void) {
    return ESP_OK;
}

extern "C" esp_err_t esp_now_add_peer(const esp_now_peer_info_t* peer) {
    (void)peer;
    return ESP_OK;
}

extern "C" esp_err_t esp_now_send(const std::uint8_t* peer_addr, const std::uint8_t* data, int len) {
    if (peer_addr == nullptr || data == nullptr || len < 0) {
        return ESP_FAIL;
    }

    fake_platform::TxFrame frame;
    std::memcpy(frame.peer.data(), peer_addr, frame.peer.size());
    frame.payload.assign(data, data + len);

    std::scoped_lock l(g_tx_mutex);
    g_tx_frames.emplace_back(std::move(frame));
    return ESP_OK;
}

extern "C" QueueHandle_t xQueueCreate(UBaseType_t length, UBaseType_t item_size) {
    if (length == 0 || item_size == 0) {
        return nullptr;
    }

    Queue* q = new Queue();
    q->capacity = length;
    q->item_size = item_size;

    std::scoped_lock l(g_queue_registry_mutex);
    g_live_queues.insert(q);
    return q;
}

extern "C" void vQueueDelete(QueueHandle_t queue) {
    Queue* q = static_cast<Queue*>(queue);
    if (!q) {
        return;
    }

    {
        std::scoped_lock l(g_queue_registry_mutex);
        std::unordered_set<Queue*>::iterator it = g_live_queues.find(q);
        if (it == g_live_queues.end()) {
            return;
        }
        g_live_queues.erase(it);
    }

    delete q;
}

extern "C" BaseType_t xQueueSend(QueueHandle_t queue, const void* item, TickType_t ticks_to_wait) {
    (void)ticks_to_wait;
    Queue* q = static_cast<Queue*>(queue);
    if (!q || !item) {
        return pdFAIL;
    }

    std::unique_lock lk(q->mutex);
    if (q->items.size() >= q->capacity) {
        return pdFAIL;
    }

    std::vector<std::uint8_t> bytes(q->item_size);
    std::memcpy(bytes.data(), item, q->item_size);
    q->items.emplace_back(std::move(bytes));
    lk.unlock();
    q->cv.notify_one();
    return pdPASS;
}

extern "C" BaseType_t xQueueReceive(QueueHandle_t queue, void* out_item, TickType_t ticks_to_wait) {
    Queue* q = static_cast<Queue*>(queue);
    if (!q || !out_item) {
        return pdFAIL;
    }

    std::unique_lock lk(q->mutex);
    if (q->items.empty()) {
        if (ticks_to_wait == 0) {
            return pdFAIL;
        }

        const std::chrono::milliseconds timeout = std::chrono::milliseconds(ticks_to_wait);
        if (!q->cv.wait_for(lk, timeout, [&]() { return !q->items.empty(); })) {
            return pdFAIL;
        }
    }

    std::vector<std::uint8_t> item = std::move(q->items.front());
    q->items.pop_front();
    std::memcpy(out_item, item.data(), q->item_size);
    return pdPASS;
}

extern "C" BaseType_t xTaskCreate(TaskFunction_t fn,
                                    const char* name,
                                    std::uint32_t stack_depth,
                                    void* arg,
                                    UBaseType_t priority,
                                    TaskHandle_t* out_handle) {
    (void)name;
    (void)stack_depth;
    (void)priority;

    if (!fn) {
        return pdFAIL;
    }

    std::shared_ptr<std::thread> th = std::make_shared<std::thread>([fn, arg]() { fn(arg); });
    th->detach();
    if (out_handle) {
        std::shared_ptr<std::thread>* holder = new std::shared_ptr<std::thread>(std::move(th));
        *out_handle = holder;
    }
    return pdPASS;
}

extern "C" void vTaskDelete(TaskHandle_t handle) {
    if (handle) {
        std::shared_ptr<std::thread>* holder = static_cast<std::shared_ptr<std::thread>*>(handle);
        delete holder;
    }
}

extern "C" int mbedtls_sha256(const unsigned char* input,
                               size_t ilen,
                               unsigned char output[32],
                               int is224) {
    (void)is224;

    std::array<std::uint8_t, 32> out{};
    std::uint32_t acc = 0x9E3779B9u;
    for (size_t i = 0; i < ilen; ++i) {
        acc ^= static_cast<std::uint32_t>(input[i]) + 0x9e3779b9u + (acc << 6) + (acc >> 2);
        out[i % out.size()] ^= static_cast<std::uint8_t>(acc & 0xFFu);
    }
    std::memcpy(output, out.data(), out.size());
    return 0;
}
