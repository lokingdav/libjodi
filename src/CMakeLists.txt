file(GLOB HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/headers/*.hpp)
source_group("SrcHeaders" FILES ${HEADERS})

file(GLOB SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
source_group("SrcFiles" FILES ${SRC_FILES})

list(APPEND libcpex_sources
  ${HEADERS}
  ${SRC_FILES}
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
