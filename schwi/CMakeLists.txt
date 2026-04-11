cmake_minimum_required(VERSION 3.20)

project(schwi LANGUAGES CXX)

add_library(schwi INTERFACE)
add_library(bricks::schwi ALIAS schwi)

target_compile_features(schwi INTERFACE cxx_std_20)

target_include_directories(schwi INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

if (CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    enable_testing()
    add_executable(schwi_visualization_export
        examples/export_visualization.cpp
    )
    target_link_libraries(schwi_visualization_export PRIVATE schwi)

    add_subdirectory(tests)
endif()
