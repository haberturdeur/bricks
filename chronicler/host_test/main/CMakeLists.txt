idf_component_register(SRCS "main.cpp"
                       INCLUDE_DIRS "."
                       PRIV_REQUIRES chronicler rapidcheck esp_partition)

target_compile_definitions(${COMPONENT_LIB} PRIVATE BRICKS_CHRONICLER_TESTING)
