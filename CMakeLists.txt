cmake_minimum_required(VERSION 3.14.0 FATAL_ERROR)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

project(libcpex VERSION 1.0.0 LANGUAGES C CXX)

message(STATUS "libcpex Version: ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")

include(FetchContent)

set(BUILD_LIBCPEX_TESTS ON CACHE BOOL "Build CPeX Tests" FORCE)
set(BUILD_LIBCPEX_BENCHMARKS ON CACHE BOOL "Build CPeX Benchmarks" FORCE)
set(BUILD_LIBCPEX_PYTHON_BINDINGS ON CACHE BOOL "Disable building CPeX Python bindings" FORCE)

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

FetchContent_Declare(sodium
  GIT_REPOSITORY https://github.com/AmineKhaldi/libsodium-cmake.git
  # Latest commit at the moment this was added here
  # Anchored to libsodium v1.0.18
  GIT_TAG f73a3fe1afdc4e37ac5fe0ddd401bf521f6bba65
)
FetchContent_MakeAvailable(sodium)

FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)
FetchContent_MakeAvailable(json)

target_compile_definitions(libcpex PRIVATE __BLST_PORTABLE__ BLSALLOC_SODIUM=1)
target_link_libraries(libcpex PUBLIC sodium curl nlohmann_json::nlohmann_json)

if(BUILD_LIBCPEX_BENCHMARKS)
  file(GLOB BENCH_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/bench/*.cpp)
  source_group("BenchSrcFiles" FILES ${BENCH_SRC})
  add_executable(cpexbench ${BENCH_SRC})
  target_include_directories(cpexbench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/bench)  
  target_link_libraries(cpexbench PRIVATE libcpex)
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
  target_link_libraries(cpextest PRIVATE libcpex Catch2::Catch2WithMain)
endif()

if(BUILD_LIBCPEX_PYTHON_BINDINGS)
  add_subdirectory(bindings/python)
endif()

target_compile_options(libcpex PRIVATE -fPIC)

