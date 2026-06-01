cmake_minimum_required(VERSION 3.16)

idf_component_register(
    SRCS "src/mfrc522.cpp"
    INCLUDE_DIRS "include"
    REQUIRES driver esp_rom Arduino_MFRC522v2
)
