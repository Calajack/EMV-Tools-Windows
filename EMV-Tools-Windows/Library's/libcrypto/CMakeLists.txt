cmake_minimum_required(VERSION 3.15)
project(emv_crypto LANGUAGES C)

find_package(OpenSSL REQUIRED)

add_library(libcrypto STATIC
    crypto_windows.c
    emv_pk.c
    emv_pki_priv.c
)

target_include_directories(libcrypto PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(libcrypto PUBLIC
    OpenSSL::Crypto
)
