#######################################################################################################################
### Copyright (c) 2026 Advanced Micro Devices, Inc. All rights reserved.
### @author AMD Developer Tools Team
#######################################################################################################################

cmake_minimum_required(VERSION 3.25)

project(SdlUtils)

# Define version information
set(SDL_UTILS_MAJOR_VERSION 1)
set(SDL_UTILS_MINOR_VERSION 0)

if (NOT SDL_UTILS_PATCH_NUMBER)
    set(SDL_UTILS_PATCH_NUMBER 0)
endif ()

if (NOT SDL_UTILS_BUILD_NUMBER)
    set(SDL_UTILS_BUILD_NUMBER 0)
endif ()

string(TIMESTAMP DATE "\"%m/%d/%Y\"")
string(TIMESTAMP YEAR "\"%Y\"")

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/Buildinfo.properties.in" "${CMAKE_CURRENT_SOURCE_DIR}/Buildinfo.properties")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

if (PROJECT_IS_TOP_LEVEL)
    include(dev_tools)
endif ()

# Safe CRT component (Linux only)
if (LINUX)
    add_library(sdl_utils_safe_crt STATIC)
    add_library(AMD::sdl_utils::safe_crt ALIAS sdl_utils_safe_crt)
    target_sources(sdl_utils_safe_crt
        PRIVATE "source/linux/safe_crt.cpp"
        PUBLIC
            FILE_SET HEADERS
            BASE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include"
            FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/linux/safe_crt.h")
    set_property(TARGET sdl_utils_safe_crt PROPERTY POSITION_INDEPENDENT_CODE ON)
    devtools_target_options(sdl_utils_safe_crt)
endif ()

# Binary Security component (Windows only)
if (WIN32)
    add_library(sdl_utils_binary_security INTERFACE)
    add_library(AMD::sdl_utils::binary_security ALIAS sdl_utils_binary_security)
    target_sources(sdl_utils_binary_security
        INTERFACE
            FILE_SET HEADERS
            BASE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include"
            FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/binary_security_check.h")
    # Link Windows libraries required by binary_security_check.h
    target_link_libraries(sdl_utils_binary_security INTERFACE wintrust crypt32 user32)
endif ()

# Unit tests (default to ON when top-level project, OFF when subproject).
option(SDL_UTILS_BUILD_TESTS "Build sdl_utils unit tests" ${PROJECT_IS_TOP_LEVEL})

if (SDL_UTILS_BUILD_TESTS)
    add_subdirectory(test/source)
endif ()
