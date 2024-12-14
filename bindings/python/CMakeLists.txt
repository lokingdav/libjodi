
FetchContent_Declare(
  pybind11
  GIT_REPOSITORY https://github.com/pybind/pybind11.git
  GIT_TAG v2.13.0
)

FetchContent_MakeAvailable(pybind11)

pybind11_add_module(libcpexpy ${CMAKE_CURRENT_SOURCE_DIR}/libcpexpy.cpp)
target_link_libraries(libcpexpy PRIVATE libcpex)

if((NOT MSVC) AND (NOT ${CMAKE_SYSTEM_NAME} MATCHES "Darwin"))
  target_link_options(libcpexpy PRIVATE -Wl,-Bsymbolic)
endif()