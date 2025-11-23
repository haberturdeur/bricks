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
#include <memory>
#include <optional>
#include <mutex>

#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"

#include "bricks/disnet.hpp"

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
        disnet::process_one(20ms);
    }
}

static std::optional<disnet::MacAddress> read_peer_mac() {
#ifdef CONFIG_DISNET_PEER_MAC
    disnet::MacAddress mac{};
    unsigned int b[6] = {0};
    int parsed = std::sscanf(CONFIG_DISNET_PEER_MAC, "%02x:%02x:%02x:%02x:%02x:%02x",
                             &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]);
    if (parsed != 6) {
        ESP_LOGE(TAG, "Failed to parse CONFIG_DISNET_PEER_MAC='%s'", CONFIG_DISNET_PEER_MAC);
        return std::nullopt;
    }
    for (int i = 0; i < 6; ++i) mac._data[i] = static_cast<std::uint8_t>(b[i]);
    return mac;
#else
    return std::nullopt;
#endif
}

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

    static std::set<disnet::MacAddress> peers;
    static std::mutex peers_mutex;

    chan.on([&](const disnet::MacAddress& source, std::span<const std::uint8_t> payload) {
        ESP_LOGI(TAG, "Received a message on channle 42: src=%s size=%u",
                 mac_to_str(source).c_str(),
                 (unsigned)payload.size());

        if (!payload.empty()) {
            std::string s(reinterpret_cast<const char*>(payload.data()), payload.size());
            ESP_LOGI(TAG, "Payload: %s", s.c_str());
        }

        {
            std::scoped_lock lk(peers_mutex);
            if (peers.insert(source).second) {
                ESP_LOGI(TAG, "Learned peer: %s", mac_to_str(source).c_str());
            }
        }
    });

    xTaskCreate(network_task, "net_loop", 4096, nullptr, 5, nullptr);

    // Allow a short discovery window to collect peers that talk to us.
    ESP_LOGI(TAG, "Discovery window: listening for peers for 5s...");
    const std::string ping = "disnet: discovery ping";
    for (int i = 0; i < 5; ++i) {
        disnet::send_heartbeat(APP_CHAN, /*ttl*/ 5);
        chan.broadcast_raw(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(ping.data()), ping.size()), /*ttl*/ 5);
        vTaskDelay(pdMS_TO_TICKS(1000));
        // Merge neighbours observed via heartbeats.
        auto neigh = disnet::neighbours(APP_CHAN);
        if (!neigh.empty()) {
            std::scoped_lock lk(peers_mutex);
            for (const auto& [mac, _] : neigh) peers.insert(mac);
        }
    }

    std::set<disnet::MacAddress> targets;
    {
        std::scoped_lock lk(peers_mutex);
        targets = peers;
    }
    if (targets.empty()) {
        ESP_LOGW(TAG, "No peers discovered. Aborting segmented send.");
        return;
    }

    std::string banner = "Hello from SEGMENTED broadcast!\n";
    std::vector<uint8_t> big;
    big.reserve(16 * 1024);
    for (int i = 0; i < big.capacity() / banner.size(); ++i) {
        big.insert(big.end(), banner.begin(), banner.end());
    }
    ESP_LOGI(TAG, "Sending segmented (%u bytes) to %zu discovered peer(s)", (unsigned)big.size(), targets.size());
    auto promise = chan.send_segmented(targets, std::span<const uint8_t>(big.data(), big.size()));

    promise.wait();

    ESP_LOGI(TAG, "Sending finished");

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1500));
    }
}
