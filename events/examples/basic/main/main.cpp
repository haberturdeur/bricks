#include <chrono>
#include <thread>
#include <iostream>

#include "bricks/events.hpp"
#include "bricks/events/idf.hpp"
#include "bricks/exceptions.hpp"

extern "C" void app_main(void) {
    using namespace std::chrono_literals;
    using namespace bricks::events;
    bricks::exceptions::setup_handler();

    using WiFiLoop = EventLoopManaged<idf::WiFi::Base>;

    WiFiLoop loop = WiFiLoop::create_default();

    auto handle = loop.on<idf::WiFi::StaConnected>([](const auto& ev){
        std::cout << "StaConnected to " << ev.ssid << std::endl;
    });

    loop.post(idf::WiFi::StaConnected{ "mySSID"});

    std::this_thread::sleep_for(1s); 

    loop.off(handle);

    loop.post(idf::WiFi::StaConnected{ "mySSID"});
}

