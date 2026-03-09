#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_now.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"

#include "bricks/disnet.hpp"
#include "bricks/exceptions.hpp"

#include <cstdint>
#include <chrono>
#include <cstring>
#include <set>
#include <span>
#include <string>
#include <vector>

namespace disnet = bricks::disnet;

static constexpr const char* g_tag = "disnet-test";
static constexpr std::uint8_t TEST_CHANNEL = 42;

static disnet::Node* g_node = nullptr;
static disnet::Node::Channel* g_channel = nullptr;
static bool g_sent_pong = false;
static bool g_sent_pong_rel = false;

static std::vector<std::uint8_t> to_bytes(const char* msg) {
    const auto* begin = reinterpret_cast<const std::uint8_t*>(msg);
    return std::vector<std::uint8_t>(begin, begin + std::strlen(msg));
}

static bool payload_equals(std::span<const std::uint8_t> payload, const char* text) {
    const std::size_t len = std::strlen(text);
    return payload.size() == len && std::memcmp(payload.data(), text, len) == 0;
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
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    wifi_init();

    disnet::Node node;
    node.init();
    g_node = &node;
    ESP_ERROR_CHECK(esp_now_register_recv_cb(esp_now_recv_cb));

    node.activate_channel(TEST_CHANNEL);
    disnet::Node::Channel channel = node.channel(TEST_CHANNEL);
    g_channel = &channel;

    channel.on([&](const disnet::MacAddress& from, std::span<const std::uint8_t> payload) {
        if (payload_equals(payload, "ping")) {
            ESP_LOGI(g_tag, "RX ping");
            if (!g_sent_pong) {
                g_sent_pong = true;
                const std::vector<std::uint8_t> pong = to_bytes("pong");
                g_channel->broadcast_raw(pong);
            }
        } else if (payload_equals(payload, "ping-rel")) {
            ESP_LOGI(g_tag, "RX ping-rel");
            if (!g_sent_pong_rel) {
                g_sent_pong_rel = true;
                const std::vector<std::uint8_t> pong_rel = to_bytes("pong-rel");
                const std::set<disnet::MacAddress> targets{from};
                g_channel->send_reliable(targets, pong_rel);
            }
        }
    });

    ESP_LOGI(g_tag, "READY role=B");

    while (true) {
        node.process_one(std::chrono::milliseconds(20));
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}
