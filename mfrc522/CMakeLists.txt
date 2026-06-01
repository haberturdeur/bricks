cmake_minimum_required(VERSION 3.16)

if(IDF_TARGET STREQUAL "linux")
    idf_component_register(
        INCLUDE_DIRS "include"
        REQUIRES Arduino_MFRC522v2
    )
else()
    idf_component_register(
        SRCS "src/mfrc522.cpp"
        INCLUDE_DIRS "include"
        REQUIRES driver esp_rom Arduino_MFRC522v2
    )
endif()
