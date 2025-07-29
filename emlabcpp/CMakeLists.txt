# This component demonstrates how to add an existing third-party library as a component
# to ESP-IDF build system.
#
# Since we are wrapping the library inside a component,
# the component has to be registered first:
cmake_minimum_required(VERSION 3.16)

idf_component_register()

include(FetchContent)

FetchContent_Declare(
  emlabcpp
  GIT_REPOSITORY https://github.com/koniarik/emlabcpp
)
FetchContent_MakeAvailable(emlabcpp)

target_include_directories(${COMPONENT_LIB} INTERFACE "${emlabcpp_SOURCE_DIR}/include")
target_link_libraries(${COMPONENT_LIB} INTERFACE emlabcpp::emlabcpp)
