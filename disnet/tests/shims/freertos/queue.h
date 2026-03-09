#pragma once

#include "freertos/FreeRTOS.h"

using QueueHandle_t = void*;

extern "C" QueueHandle_t xQueueCreate(UBaseType_t length, UBaseType_t item_size);
extern "C" void vQueueDelete(QueueHandle_t queue);
extern "C" BaseType_t xQueueSend(QueueHandle_t queue, const void* item, TickType_t ticks_to_wait);
extern "C" BaseType_t xQueueReceive(QueueHandle_t queue, void* out_item, TickType_t ticks_to_wait);
