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

static const char* g_tag = "app";
static disnet::Node* g_node = nullptr;

static std::string mac_to_str(const disnet::MacAddress& m) {
    char b[18];
    const std::uint8_t* bytes = m.data();
    std::snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4],
                  bytes[5]);
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
    ESP_ERROR_CHECK(esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N |
                                                           WIFI_PROTOCOL_LR));
}

static void network_task(void*) {
    for (;;) {
        if (g_node) {
            g_node->process_one(20ms);
        }
    }
}

static void esp_now_recv_cb(const esp_now_recv_info_t* info, const std::uint8_t* data, int len) {
    if (!g_node || !info || !data || len <= 0) {
        return;
    }

    disnet::MacAddress source{};
    std::memcpy(source.data(), info->src_addr, 6);
    g_node->inject_received(source, std::span<const std::uint8_t>(data, static_cast<std::size_t>(len)));
}

extern "C" void app_main(void) {
    bricks::exceptions::setup_handler();
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        clear_nvs_storage();
    }
    ESP_ERROR_CHECK(ret);

    wifi_init();

    disnet::Node node;
    node.init();
    g_node = &node;
    ESP_ERROR_CHECK(esp_now_register_recv_cb(esp_now_recv_cb));
    ESP_LOGI(g_tag, "disnet initialized. My STA MAC: %s", mac_to_str(disnet::MacAddress::my_address_sta()).c_str());

    constexpr std::uint8_t app_chan = 42;
    node.activate_channel(app_chan);

    disnet::Node::Channel chan = node.channel(app_chan);

    chan.on([](const disnet::MacAddress& source, std::span<const std::uint8_t> payload) {
        ESP_LOGI(g_tag, "Received a message on channel 42: src=%s size=%u", mac_to_str(source).c_str(),
                 static_cast<unsigned>(payload.size()));

        if (!payload.empty()) {
            std::string s(reinterpret_cast<const char*>(payload.data()), payload.size());
            ESP_LOGI(g_tag, "Payload: %s", s.c_str());
        }
    });

    xTaskCreate(network_task, "net_loop", 4096, nullptr, 5, nullptr);

    std::string banner = "Hello from SEGMENTED broadcast!\n";
    std::vector<std::uint8_t> big;
    big.reserve(16 * 1024);
    for (int i = 0; i < big.capacity() / banner.size(); ++i) {
        big.insert(big.end(), banner.begin(), banner.end());
    }
    std::set<disnet::MacAddress> none{{0xEC, 0xDA, 0x3B, 0x5B, 0xAB, 0x64}}; // broadcast
    ESP_LOGI(g_tag, "Sending segmented (%u bytes)", static_cast<unsigned>(big.size()));
    disnet::AckFuture promise = chan.send_segmented(none, std::span<const std::uint8_t>(big.data(), big.size()));

    promise.wait();

    ESP_LOGI(g_tag, "Sending finished");

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1500));
    }
}
