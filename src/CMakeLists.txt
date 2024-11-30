file(GLOB HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/*.hpp)
source_group("SrcHeaders" FILES ${HEADERS})

list(APPEND libcpex_sources
  ${HEADERS}
  libcpex.cpp
)

add_compile_options(-fno-builtin)
add_compile_options(-fPIC)
add_compile_options(-Wall)
add_compile_options(-Wextra)

add_library(libcpex ${libcpex_sources})

target_include_directories(libcpex PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
)

if(BUILD_LIBCPEX_BENCHMARKS)
  add_executable(runbench bench.cpp)
  target_link_libraries(runbench PRIVATE libcpex)
endif()

if(BUILD_LIBCPEX_TESTS)
  add_executable(runtest test.cpp)
  target_link_libraries(runtest PRIVATE libcpex)
endif()
