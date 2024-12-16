
FetchContent_Declare(
  pybind11
  GIT_REPOSITORY https://github.com/pybind/pybind11.git
  GIT_TAG v2.13.0
)

FetchContent_MakeAvailable(pybind11)

pybind11_add_module(pylibcpex ${CMAKE_CURRENT_SOURCE_DIR}/pylibcpex.cpp)
target_link_libraries(pylibcpex PRIVATE libcpex)

if((NOT MSVC) AND (NOT ${CMAKE_SYSTEM_NAME} MATCHES "Darwin"))
  target_link_options(pylibcpex PRIVATE -Wl,-Bsymbolic)
endif()