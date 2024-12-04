# Collect all header files for the library
file(GLOB LIB_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/libcpex/includes/*.hpp)
source_group("CPeXSrcHeaders" FILES ${LIB_HEADERS})

# Collect all source files for the library
file(GLOB LIB_SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/libcpex/*.cpp)
source_group("CPeXSrcFiles" FILES ${LIB_SRC_FILES})

# Append library sources to the libcpex_sources list
set(libcpex_sources
  ${LIB_HEADERS}
  ${LIB_SRC_FILES}
)

# Compiler options

# Create the libcpex library
add_library(libcpex STATIC ${libcpex_sources})

# Include directories for libcpex
target_include_directories(libcpex PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/libcpex
  ${bls_SOURCE_DIR}
)

# Link dependencies for libcpex
target_link_libraries(libcpex PUBLIC bls)

# Benchmark executable (optional)
if(BUILD_LIBCPEX_BENCHMARKS)
  # Collect benchmark source files
  file(GLOB BENCH_SRC ${CMAKE_CURRENT_SOURCE_DIR}/bench/*.cpp)
  source_group("BenchSrcFiles" FILES ${BENCH_SRC})

  # Create the benchmark executable
  add_executable(cpexbench ${BENCH_SRC})
  
  # Include directories for benchmark if needed
  target_include_directories(cpexbench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/bench)
  
  # Link with libcpex
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

  # Collect test source files
  file(GLOB TEST_SRC ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp)
  source_group("TestSrcFiles" FILES ${TEST_SRC})

  # Create the test executable
  add_executable(cpextest ${TEST_SRC})

  # Include directories for tests if needed
  target_include_directories(cpextest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)

  # Link with libcpex and Catch2
  target_link_libraries(cpextest PRIVATE libcpex Catch2::Catch2WithMain)
endif()
