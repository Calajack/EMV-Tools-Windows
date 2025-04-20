cmake_minimum_required(VERSION 3.16)
project(EMVToolsWindows LANGUAGES C)

# Default to static runtime on MSVC
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# Set output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Static OpenSSL support
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

# Global include path for shared headers
include_directories(${CMAKE_SOURCE_DIR}/include)

# Add libraries
add_subdirectory(Libraries/libscard)
add_subdirectory(Libraries/libcrypto)
add_subdirectory(Libraries/libcore)

# Add tools
add_subdirectory(TOOLS/emv_cap)
add_subdirectory(TOOLS/emv_dump)
add_subdirectory(TOOLS/emv_dda)
add_subdirectory(TOOLS/emv_sda)
add_subdirectory(TOOLS/emv_cl_cda)
add_subdirectory(TOOLS/emv_pse)

# Add unified CLI dispatcher later
# add_subdirectory(TOOLS/emv-tools)
