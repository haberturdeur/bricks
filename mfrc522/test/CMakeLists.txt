cmake_minimum_required(VERSION 3.20)
project(mfrc522_host_tests LANGUAGES CXX)

enable_testing()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(mfrc522_state_tests state_tests.cpp)
target_include_directories(mfrc522_state_tests PRIVATE shims ../include)
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(mfrc522_state_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(NAME mfrc522_state_tests COMMAND mfrc522_state_tests)
