# libscard/CMakeLists.txt
add_library(libscard STATIC 
    winscard_impl.c 
    apdu_processing.c
)
target_link_libraries(libscard PRIVATE WinSCard)