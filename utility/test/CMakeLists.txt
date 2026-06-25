cmake_minimum_required(VERSION 3.20)
project(packed_size_tests LANGUAGES CXX)

enable_testing()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(packed_size_tests packed_size_tests.cpp)
target_include_directories(packed_size_tests PRIVATE ../include)

add_executable(serdes_tests serdes_tests.cpp)
target_include_directories(serdes_tests PRIVATE ../include)

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(packed_size_tests PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(serdes_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(NAME packed_size_tests COMMAND packed_size_tests)
add_test(NAME serdes_tests COMMAND serdes_tests)
