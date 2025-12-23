cmake_minimum_required(VERSION 3.16)

idf_component_register()

include(FetchContent)

set(RC_ENABLE_GTEST OFF CACHE BOOL "" FORCE)
set(RC_ENABLE_EXAMPLES OFF CACHE BOOL "" FORCE)
set(RC_ENABLE_TESTS OFF CACHE BOOL "" FORCE)
set(RC_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)

FetchContent_Declare(rapidcheck_component URL https://github.com/emil-e/rapidcheck/archive/refs/heads/master.zip)
FetchContent_GetProperties(rapidcheck_component)
if(NOT rapidcheck_component_POPULATED)
    FetchContent_Populate(rapidcheck_component)
endif()

file(GLOB_RECURSE RAPIDCHECK_SOURCES
     CONFIGURE_DEPENDS
     "${rapidcheck_component_SOURCE_DIR}/src/*.cpp"
     "${rapidcheck_component_SOURCE_DIR}/src/*/*.cpp")

add_library(rapidcheck_component STATIC ${RAPIDCHECK_SOURCES})
target_include_directories(rapidcheck_component PUBLIC ${rapidcheck_component_SOURCE_DIR}/include)
target_compile_features(rapidcheck_component PUBLIC cxx_std_11)
set_property(TARGET rapidcheck_component PROPERTY POSITION_INDEPENDENT_CODE ON)
target_compile_options(rapidcheck_component PUBLIC -fexceptions -frtti)
target_link_options(rapidcheck_component PUBLIC -fexceptions -frtti)

target_link_libraries(${COMPONENT_LIB} INTERFACE rapidcheck_component)
