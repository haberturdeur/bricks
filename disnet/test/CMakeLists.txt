cmake_minimum_required(VERSION 3.20)
project(disnet_host_tests LANGUAGES CXX)

enable_testing()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (NOT TARGET schwi)
    add_subdirectory(../../schwi schwi_build)
endif()

function(add_disnet_host_test target)
    add_executable(${target} ${ARGN})
    target_include_directories(${target} PRIVATE ../include ../../utility/include)
    if (TARGET schwi)
        target_link_libraries(${target} PRIVATE schwi)
    endif()
    if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    add_test(NAME ${target} COMMAND ${target})
endfunction()

add_executable(disnet_esp_now_regression
    esp_now_regression.cpp
)
target_include_directories(disnet_esp_now_regression PRIVATE
    ../include
    ../../utility/include
    shims
)

add_executable(disnet_hwmp_regression
    hwmp_regression.cpp
)
target_include_directories(disnet_hwmp_regression PRIVATE
    ../include
    ../../utility/include
)

add_disnet_host_test(disnet_hwmp_protocol_tests hwmp_protocol_tests.cpp)
add_disnet_host_test(disnet_hwmp_route_lifecycle_tests hwmp_route_lifecycle_tests.cpp)
add_disnet_host_test(disnet_hwmp_error_dedup_tests hwmp_error_dedup_tests.cpp)
add_disnet_host_test(disnet_hwmp_schwi_reactive_tests hwmp_schwi_reactive_tests.cpp)
add_disnet_host_test(disnet_hwmp_schwi_root_tests hwmp_schwi_root_tests.cpp)
add_disnet_host_test(disnet_schwi_router_tests schwi_router_tests.cpp)
add_disnet_host_test(disnet_mux_protocol_tests mux_protocol_tests.cpp)

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(disnet_esp_now_regression PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(disnet_hwmp_regression PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(NAME disnet_esp_now_regression COMMAND disnet_esp_now_regression)
add_test(NAME disnet_hwmp_regression COMMAND disnet_hwmp_regression)
