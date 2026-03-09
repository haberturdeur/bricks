cmake_minimum_required(VERSION 3.20)
project(disnet_host_tests LANGUAGES CXX)

enable_testing()

add_executable(disnet_host_tests
    src/disnet_tests.cpp
    src/fake_platform.cpp
    ../core.cpp
    ../reliable.cpp
    ../segmented.cpp
)

target_compile_features(disnet_host_tests PRIVATE cxx_std_23)
target_compile_definitions(disnet_host_tests PRIVATE BRICKS_DISNET_DIAGNOSTICS=1)

target_include_directories(disnet_host_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/shims
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../exceptions/include
)

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(disnet_host_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

find_package(Threads REQUIRED)
target_link_libraries(disnet_host_tests PRIVATE Threads::Threads)

add_test(NAME disnet_host_tests COMMAND disnet_host_tests)
