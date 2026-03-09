#pragma once

#include "freertos/FreeRTOS.h"

using TaskHandle_t = void*;
using TaskFunction_t = void (*)(void*);

extern "C" BaseType_t xTaskCreate(TaskFunction_t fn,
                                    const char* name,
                                    std::uint32_t stack_depth,
                                    void* arg,
                                    UBaseType_t priority,
                                    TaskHandle_t* out_handle);
extern "C" void vTaskDelete(TaskHandle_t handle);
