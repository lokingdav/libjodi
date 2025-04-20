cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

# -----------------------------
# Project definition
# -----------------------------
project(
  libjodi
  VERSION 1.0.0
  DESCRIPTION "LibJodi library"
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

message(STATUS "Building libjodi Version: ${PROJECT_VERSION}")

# -----------------------------
# Options
# -----------------------------
option(BUILD_LIBJODI_TESTS           "Build Jodi Tests"              ON)
option(BUILD_LIBJODI_BENCHMARKS      "Build Jodi Benchmarks"         ON)
option(BUILD_LIBJODI_PYTHON_BINDINGS "Build Jodi Python bindings"    ON)
option(ENABLE_SANITIZERS             "Enable ASan/UBSan"             OFF)

message(STATUS "BUILD_LIBJODI_TESTS:           ${BUILD_LIBJODI_TESTS}")
message(STATUS "BUILD_LIBJODI_BENCHMARKS:      ${BUILD_LIBJODI_BENCHMARKS}")
message(STATUS "BUILD_LIBJODI_PYTHON_BINDINGS: ${BUILD_LIBJODI_PYTHON_BINDINGS}")
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

find_package(CURL REQUIRED)

# libsodium (system library)
find_library(SODIUM_LIBRARY NAMES sodium REQUIRED)
if(NOT SODIUM_LIBRARY)
  message(FATAL_ERROR "libsodium not found. Please install it (e.g. libsodium-dev).")
endif()

# Threads
find_package(Threads REQUIRED)

# -----------------------------
# Sources for main libjodi library
# -----------------------------
file(GLOB LIB_HEADERS
  "${CMAKE_CURRENT_SOURCE_DIR}/src/libjodi/includes/*.hpp"
)
file(GLOB LIB_SRC_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/src/libjodi/*.cpp"
)

# -----------------------------
# Define the libjodi library
# -----------------------------
add_library(libjodi STATIC
  ${LIB_HEADERS}
  ${LIB_SRC_FILES}
)

# Make sure we have -fPIC even for static libs
target_compile_options(libjodi PRIVATE -fPIC)

# Public headers so consumers can do target_link_libraries and see them
target_include_directories(libjodi PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/src/libjodi"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/libjodi/includes"
)

# Link with any needed deps
target_link_libraries(libjodi
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
if(BUILD_LIBJODI_BENCHMARKS)
  file(GLOB BENCH_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/bench/*.cpp")
  add_executable(jodibench ${BENCH_SRC})
  target_include_directories(jodibench PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/bench")
  target_link_libraries(jodibench PRIVATE libjodi)
endif()

# -----------------------------
# Tests (using Catch2)
# -----------------------------
if(BUILD_LIBJODI_TESTS)
  FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG        v3.4.0
  )
  FetchContent_MakeAvailable(Catch2)

  file(GLOB TEST_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/tests/*.cpp")
  add_executable(joditest ${TEST_SRC})
  target_include_directories(joditest PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/tests")
  target_link_libraries(joditest PRIVATE libjodi Catch2::Catch2WithMain)
endif()

# -----------------------------
# Python bindings
# -----------------------------
if(BUILD_LIBJODI_PYTHON_BINDINGS)
  add_subdirectory(bindings/python)
endif()
