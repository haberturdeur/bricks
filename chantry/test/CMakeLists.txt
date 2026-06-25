cmake_minimum_required(VERSION 3.20)
project(chantry_host_tests LANGUAGES CXX)

enable_testing()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(chantry_concept_tests concept_tests.cpp)
target_include_directories(chantry_concept_tests PRIVATE
    ../include
    ../../disnet/include
    ../../utility/include
)

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(chantry_concept_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(NAME chantry_concept_tests COMMAND chantry_concept_tests)
