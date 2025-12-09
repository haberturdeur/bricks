cmake_minimum_required(VERSION 3.16)

idf_component_register(SRCS "chronicler.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES esp_partition spi_flash)
