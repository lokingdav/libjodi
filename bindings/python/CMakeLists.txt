
FetchContent_Declare(
  pybind11
  GIT_REPOSITORY https://github.com/pybind/pybind11.git
  GIT_TAG v2.13.0
)

FetchContent_MakeAvailable(pybind11)

pybind11_add_module(pylibjodi ${CMAKE_CURRENT_SOURCE_DIR}/pylibjodi.cpp)
target_link_libraries(pylibjodi PRIVATE libjodi)

if((NOT MSVC) AND (NOT ${CMAKE_SYSTEM_NAME} MATCHES "Darwin"))
  target_link_options(pylibjodi PRIVATE -Wl,-Bsymbolic)
endif()