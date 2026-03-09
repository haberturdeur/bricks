idf_component_register(SRCS "core.cpp"
                            "reliable.cpp"
                            "segmented.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES esp_wifi mbedtls)
