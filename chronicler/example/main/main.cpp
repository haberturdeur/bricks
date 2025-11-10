#include "bricks/exceptions.hpp"

#include <esp_err.h>

#include <iostream>
#include <stdexcept>

void foo() {
    CHECK_IDF_ERROR(ESP_ERR_INVALID_ARG); 
    throw bricks::exceptions::Exception(std::runtime_error{"test"});
}

void bar() {
    foo();
}

extern "C" void app_main(void) {
    bricks::exceptions::setup_handler();
    bar();
}
