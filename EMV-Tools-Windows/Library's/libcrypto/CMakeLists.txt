cmake_minimum_required(VERSION 3.15)
project(emv_crypto LANGUAGES C)

find_package(OpenSSL REQUIRED)

add_library(emv_crypto STATIC
    crypto_windows.c
)

target_include_directories(emv_crypto PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(emv_crypto PRIVATE
    OpenSSL::Crypto
)

# Installation (optional)
install(TARGETS emv_crypto
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

add_library(emv_crypto STATIC
    crypto_windows.c
    emv_pk.c
)