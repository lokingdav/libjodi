cmake_minimum_required(VERSION 3.14.0 FATAL_ERROR)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)

set(libcpex_VERSION_MAJOR 1)
set(libcpex_VERSION_MINOR 0)
set(libcpex_VERSION_PATCH 0)
set(libcpex_VERSION ${libcpex_VERSION_MAJOR}.${libcpex_VERSION_MINOR}.${libcpex_VERSION_PATCH})

project(libcpex VERSION ${libcpex_VERSION} LANGUAGES C CXX)

set(BUILD_LIBCPEX_TESTS ON CACHE BOOL OFF)
set(BUILD_LIBCPEX_BENCHMARKS ON CACHE BOOL OFF)
set(BUILD_LIBCPEX_PYTHON_BINDINGS OFF CACHE BOOL OFF)

include_directories($ENV{OPENSSL_INCLUDE_DIR})

include(FetchContent)

set(BLS_GIT_TAG "origin/main")
set(BLS_REPOSITORY "https://github.com/Chia-Network/bls-signatures.git")
message(STATUS "bls will be built from: ${BLS_GIT_TAG} and repository ${BLS_REPOSITORY}")

FetchContent_Declare(
  bls
  GIT_REPOSITORY ${BLS_REPOSITORY}
  GIT_TAG ${BLS_GIT_TAG}
)

set(BUILD_BLS_PYTHON_BINDINGS OFF CACHE BOOL "Disable building BLS Python bindings" FORCE)
set(BUILD_BLS_TESTS OFF CACHE BOOL "Disable building BLS Package tests" FORCE)
set(BUILD_BLS_BENCHMARKS OFF CACHE BOOL "Disable building BLS package benchmarks" FORCE)

FetchContent_MakeAvailable(bls)

add_subdirectory(src)

if(BUILD_LIBCPEX_PYTHON_BINDINGS)
  add_subdirectory(bindings/python)
endif()
