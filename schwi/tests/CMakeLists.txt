cmake_minimum_required(VERSION 3.20)
project(schwi_host_tests LANGUAGES CXX)

enable_testing()

if (NOT TARGET schwi)
    add_subdirectory(.. schwi_build)
endif()

add_executable(schwi_host_tests
    src/schwi_tests.cpp
)

target_link_libraries(schwi_host_tests PRIVATE schwi)

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(schwi_host_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(NAME schwi_host_tests COMMAND schwi_host_tests)
