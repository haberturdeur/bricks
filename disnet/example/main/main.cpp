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

    chan.on([](const disnet::MacAddress& source, std::span<const std::uint8_t> payload) {
        ESP_LOGI(TAG, "Received a message on channle 42: src=%s size=%u",
                 mac_to_str(source).c_str(),
                 (unsigned)payload.size());

        if (!payload.empty()) {
            std::string s(reinterpret_cast<const char*>(payload.data()), payload.size());
            ESP_LOGI(TAG, "Payload: %s", s.c_str());
        }
    });

    xTaskCreate(network_task, "net_loop", 4096, nullptr, 5, nullptr);

    std::string banner = "Hello from SEGMENTED broadcast!\n";
    std::vector<uint8_t> big;
    big.reserve(16 * 1024);
    for (int i = 0; i < big.capacity() / banner.size(); ++i) {
        big.insert(big.end(), banner.begin(), banner.end());
    }
    std::set<disnet::MacAddress> none {{0xEC, 0xDA, 0x3B, 0x5B, 0xAB, 0x64}}; // broadcast
    ESP_LOGI(TAG, "Sending segmented (%u bytes)", (unsigned)big.size());
    auto promise = chan.send_segmented(none, std::span<const uint8_t>(big.data(), big.size()));

    promise.wait();

    ESP_LOGI(TAG, "Sending finished");

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1500));
    }
}

