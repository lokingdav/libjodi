file(GLOB HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/*.hpp)
source_group("CPeXSrcHeaders" FILES ${HEADERS})

file(GLOB SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
source_group("CPeXSrcFiles" FILES ${SRC_FILES})

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
  ${bls_SOURCE_DIR}
)

target_link_libraries(libcpex PUBLIC bls)

if(BUILD_LIBCPEX_BENCHMARKS)
  add_executable(cpexbench bench.cpp)
  target_link_libraries(cpexbench PRIVATE libcpex)
endif()

if(BUILD_LIBCPEX_TESTS)
  add_executable(cpextest test.cpp)
  target_link_libraries(cpextest PRIVATE libcpex)
endif()
