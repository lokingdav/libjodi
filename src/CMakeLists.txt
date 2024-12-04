# src/CMakeLists.txt

# Collect all header files
file(GLOB HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/*.hpp)
source_group("CPeXSrcHeaders" FILES ${HEADERS})

# Collect all source files
file(GLOB SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
source_group("CPeXSrcFiles" FILES ${SRC_FILES})

# message(STATUS "SRC Files: ${SRC_FILES}")

# Append sources to the libcpex_sources list
list(APPEND libcpex_sources
  ${HEADERS}
  ${SRC_FILES}
)

# Compiler options
add_compile_options(-fno-builtin)
add_compile_options(-fPIC)
add_compile_options(-Wall)
add_compile_options(-Wextra)

# Create the libcpex library
add_library(libcpex ${libcpex_sources})

# Include directories for libcpex
target_include_directories(libcpex PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${bls_SOURCE_DIR}
)

# Link dependencies for libcpex
target_link_libraries(libcpex PUBLIC bls)

# Benchmark executable (optional)
if(BUILD_LIBCPEX_BENCHMARKS)
  add_executable(cpexbench bench.cpp)
  target_link_libraries(cpexbench PRIVATE libcpex)
endif()

# Test executable
if(BUILD_LIBCPEX_TESTS)
  FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG        v3.4.0
  )
  FetchContent_MakeAvailable(Catch2)
  add_executable(cpextest tests/test.cpp)
  target_link_libraries(cpextest PRIVATE libcpex Catch2::Catch2WithMain)
endif()
