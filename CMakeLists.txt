cmake_minimum_required(VERSION 3.14.0 FATAL_ERROR)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)

set(libcpex_VERSION_MAJOR 1)
set(libcpex_VERSION_MINOR 0)
set(libcpex_VERSION_PATCH 0)
set(libcpex_VERSION ${libcpex_VERSION_MAJOR}.${libcpex_VERSION_MINOR}.${libcpex_VERSION_PATCH})

project(libcpex VERSION ${libcpex_VERSION} LANGUAGES C CXX)

include(FetchContent)

set(BUILD_LIBCPEX_TESTS ON CACHE BOOL "Build CPeX Tests" FORCE)
set(BUILD_LIBCPEX_BENCHMARKS ON CACHE BOOL "Build CPeX Benchmarks" FORCE)
set(BUILD_LIBCPEX_PYTHON_BINDINGS OFF CACHE BOOL "Disable building CPeX Python bindings" FORCE)

message(STATUS "BUILD_LIBCPEX_TESTS: ${BUILD_LIBCPEX_TESTS}")
message(STATUS "BUILD_LIBCPEX_BENCHMARKS: ${BUILD_LIBCPEX_BENCHMARKS}")
message(STATUS "BUILD_LIBCPEX_PYTHON_BINDINGS: ${BUILD_LIBCPEX_PYTHON_BINDINGS}")

file(GLOB LIB_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/src/libcpex/includes/*.hpp)
source_group("CPeXSrcHeaders" FILES ${LIB_HEADERS})

file(GLOB LIB_SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/libcpex/*.cpp)
source_group("CPeXSrcFiles" FILES ${LIB_SRC_FILES})

set(libcpex_sources
  ${LIB_HEADERS}
  ${LIB_SRC_FILES}
)

add_library(libcpex STATIC ${libcpex_sources})
target_include_directories(libcpex PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src/libcpex
)

if(BUILD_LIBCPEX_BENCHMARKS)
  file(GLOB BENCH_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/bench/*.cpp)
  source_group("BenchSrcFiles" FILES ${BENCH_SRC})
  add_executable(cpexbench ${BENCH_SRC})
  target_include_directories(cpexbench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/bench)  
  target_link_libraries(cpexbench PRIVATE libcpex sodium)
endif()

if(BUILD_LIBCPEX_TESTS)
  FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG        v3.4.0
  )
  FetchContent_MakeAvailable(Catch2)

  file(GLOB TEST_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/tests/*.cpp)
  source_group("TestSrcFiles" FILES ${TEST_SRC})

  add_executable(cpextest ${TEST_SRC})
  target_include_directories(cpextest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/tests)
  target_link_libraries(cpextest PRIVATE libcpex Catch2::Catch2WithMain sodium)
endif()

if(BUILD_LIBCPEX_PYTHON_BINDINGS)
  add_subdirectory(bindings/python)
endif()
