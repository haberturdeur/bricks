// main.cpp
#include "bricks/exceptions.hpp"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "esp_log.h"

#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <set>
#include <span>
#include <string>
#include <vector>
#include <chrono>
#include <future>

#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"

#include "bricks/disnet.hpp"
#include "bricks/disnet/protocols.hpp"

namespace disnet = bricks::disnet;
using namespace std::chrono_literals;

static const char* TAG = "app";

static std::string mac_to_str(const disnet::MacAddress& m) {
    char b[18];
    std::snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X",
                  m._data[0], m._data[1], m._data[2],
                  m._data[3], m._data[4], m._data[5]);
    return std::string(b);
}

static void clear_nvs_storage() {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ESP_ERROR_CHECK(nvs_flash_init());
}

static void wifi_init() {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE));
    ESP_ERROR_CHECK(esp_wifi_set_protocol(
        WIFI_IF_STA,
        WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N | WIFI_PROTOCOL_LR));
}

static void network_task(void*) {
    for (;;) {
        disnet::process_one(100ms);
    }
}

// --- NEW: small helper to wait for an ACK off the hot path ---
struct AckJob {
    disnet::AckFuture fut;
    disnet::MacAddress target;
    std::string desc; // what we sent (for logging)
};

static void ack_waiter_task(void* arg) {
    std::unique_ptr<AckJob> job(static_cast<AckJob*>(arg)); // take ownership
    // Wait for the ACK (tweak timeout as you like)
    auto status = job->fut.wait_for(2s);
    if (status == std::future_status::ready) {
        // get() to surface any exceptions (even though it's an empty future)
        (void)job->fut.get();
        ESP_LOGI(TAG, "ACK received from %s for: %s",
                 mac_to_str(job->target).c_str(), job->desc.c_str());
    } else {
        ESP_LOGW(TAG, "ACK timeout from %s for: %s",
                 mac_to_str(job->target).c_str(), job->desc.c_str());
    }
    vTaskDelete(nullptr);
}
// ----------------------------------------------------------------

extern "C" void app_main(void) {
    bricks::exceptions::setup_handler();
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        clear_nvs_storage();
    }
    ESP_ERROR_CHECK(ret);

    wifi_init();

    disnet::init();
    ESP_LOGI(TAG, "disnet initialized. My STA MAC: %s",
             mac_to_str(disnet::MacAddress::my_address_sta()).c_str());

    constexpr uint8_t APP_CHAN = 42;
    disnet::activate_channel(APP_CHAN);

    disnet::Channel chan(APP_CHAN, /*starting_ttl*/ 15);

    // Reply RELIABLY to whoever talks to us, and WAIT for the ACK in a tiny task.
    chan.on([&](const disnet::MacAddress& source, std::span<const std::uint8_t> payload) {
        ESP_LOGI(TAG, "RX src=%s size=%u",
                 mac_to_str(source).c_str(),
                 (unsigned)payload.size());

        // Optional: log ASCII payloads for convenience
        bool ascii = true;
        for (auto c : payload) { if (c < 0x20 || c > 0x7E) { ascii = false; break; } }
        if (ascii && !payload.empty()) {
            std::string s(reinterpret_cast<const char*>(payload.data()), payload.size());
            ESP_LOGI(TAG, "Payload: %s", s.c_str());
        }

        // Prepare reply and send reliably
        std::string reply = "ACK: got " + std::to_string(payload.size()) + " bytes";
        std::set<disnet::MacAddress> targets{source};
        disnet::AckFuture fut = chan.send_reliable(
            targets,
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(reply.data()), reply.size()));

        ESP_LOGI(TAG, "TX RELIABLE -> %s", mac_to_str(source).c_str());

        // Hand the future to a short-lived waiter task so we don't block this callback.
        auto* job = new AckJob{ std::move(fut), source, reply };
        // Stack size can be modest; bump if you add heavy logging/formatting.
        xTaskCreate(ack_waiter_task, "ack_waiter", 4096, job, 4, nullptr);
    });

    xTaskCreate(network_task, "net_loop", 4096, nullptr, 5, nullptr);

    // Keep broadcasting RAW messages so others will contact us,
    // which will trigger the reliable replies above.

    std::string txt = "hello from RAW: " + std::to_string(5);
    std::set<disnet::MacAddress> targets{};
    chan.send_raw(
        targets,
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(txt.data()), txt.size()));

    ESP_LOGI(TAG, "TX RAW broadcast");

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1500));
    }
}

