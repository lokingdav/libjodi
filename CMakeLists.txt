cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

# -----------------------------
# Project definition
# -----------------------------
project(
  libcpex
  VERSION 1.0.0
  DESCRIPTION "LibCPeX library"
  LANGUAGES C CXX
)

# -----------------------------
# General settings
# -----------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# (Optional) new policy for controlling option() default values
if(POLICY CMP0077)
  cmake_policy(SET CMP0077 NEW)
endif()

message(STATUS "Building libcpex Version: ${PROJECT_VERSION}")

# -----------------------------
# Options
# -----------------------------
option(BUILD_LIBCPEX_TESTS           "Build CPeX Tests"              ON)
option(BUILD_LIBCPEX_BENCHMARKS      "Build CPeX Benchmarks"         ON)
option(BUILD_LIBCPEX_PYTHON_BINDINGS "Build CPeX Python bindings"    ON)
option(ENABLE_SANITIZERS             "Enable ASan/UBSan"             OFF)

message(STATUS "BUILD_LIBCPEX_TESTS:           ${BUILD_LIBCPEX_TESTS}")
message(STATUS "BUILD_LIBCPEX_BENCHMARKS:      ${BUILD_LIBCPEX_BENCHMARKS}")
message(STATUS "BUILD_LIBCPEX_PYTHON_BINDINGS: ${BUILD_LIBCPEX_PYTHON_BINDINGS}")
message(STATUS "ENABLE_SANITIZERS:             ${ENABLE_SANITIZERS}")

# -----------------------------
# Optional: enable sanitizers
# -----------------------------
if(ENABLE_SANITIZERS)
  message(STATUS "Enabling AddressSanitizer and UndefinedBehaviorSanitizer.")
  set(SANITIZE_FLAGS "-fsanitize=address -fsanitize=undefined -g")

  set(CMAKE_CXX_FLAGS             "${CMAKE_CXX_FLAGS} ${SANITIZE_FLAGS}")
  set(CMAKE_C_FLAGS               "${CMAKE_C_FLAGS} ${SANITIZE_FLAGS}")
  set(CMAKE_EXE_LINKER_FLAGS      "${CMAKE_EXE_LINKER_FLAGS} ${SANITIZE_FLAGS}")
  set(CMAKE_SHARED_LINKER_FLAGS   "${CMAKE_SHARED_LINKER_FLAGS} ${SANITIZE_FLAGS}")
endif()

# -----------------------------
# Dependencies
# -----------------------------
include(FetchContent)

# nlohmann/json (remove if you don't need JSON parsing)
FetchContent_Declare(
  json
  GIT_REPOSITORY https://github.com/nlohmann/json
  GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(json)

# Find mcl
FetchContent_Declare(
  mcl
  GIT_REPOSITORY https://github.com/herumi/mcl.git
  GIT_TAG v2.14
)
FetchContent_MakeAvailable(mcl)

# libcurl (remove if you don't need it)
find_package(CURL REQUIRED)

# libsodium (system library)
find_library(SODIUM_LIBRARY NAMES sodium REQUIRED)
if(NOT SODIUM_LIBRARY)
  message(FATAL_ERROR "libsodium not found. Please install it (e.g. libsodium-dev).")
endif()

# Threads
find_package(Threads REQUIRED)

# -----------------------------
# Sources for main libcpex library
# -----------------------------
file(GLOB LIB_HEADERS
  "${CMAKE_CURRENT_SOURCE_DIR}/src/libcpex/includes/*.hpp"
)
file(GLOB LIB_SRC_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/src/libcpex/*.cpp"
)

# -----------------------------
# Define the libcpex library
# -----------------------------
add_library(libcpex STATIC
  ${LIB_HEADERS}
  ${LIB_SRC_FILES}
)

# Make sure we have -fPIC even for static libs
target_compile_options(libcpex PRIVATE -fPIC)

# Public headers so consumers can do target_link_libraries and see them
target_include_directories(libcpex PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/src/libcpex"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/libcpex/includes"
)

# Link with any needed deps
target_link_libraries(libcpex
  PUBLIC
    nlohmann_json::nlohmann_json
    CURL::libcurl
    ${SODIUM_LIBRARY}
    mcl
  PRIVATE
    Threads::Threads
)

# -----------------------------
# Benchmarks
# -----------------------------
if(BUILD_LIBCPEX_BENCHMARKS)
  file(GLOB BENCH_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/bench/*.cpp")
  add_executable(cpexbench ${BENCH_SRC})
  target_include_directories(cpexbench PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/bench")
  target_link_libraries(cpexbench PRIVATE libcpex)
endif()

# -----------------------------
# Tests (using Catch2)
# -----------------------------
if(BUILD_LIBCPEX_TESTS)
  FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG        v3.4.0
  )
  FetchContent_MakeAvailable(Catch2)

  file(GLOB TEST_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/tests/*.cpp")
  add_executable(cpextest ${TEST_SRC})
  target_include_directories(cpextest PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/tests")
  target_link_libraries(cpextest PRIVATE libcpex Catch2::Catch2WithMain)
endif()

# -----------------------------
# Python bindings
# -----------------------------
if(BUILD_LIBCPEX_PYTHON_BINDINGS)
  add_subdirectory(bindings/python)
endif()
