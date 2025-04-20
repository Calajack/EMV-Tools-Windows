# libscard/CMakeLists.txt

add_library(libscard STATIC
    apdu_processing.c
    winscard_impl.c
)

target_include_directories(libscard PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(libscard PUBLIC
    Winscard
)
