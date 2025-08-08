cmake_minimum_required(VERSION 3.28)

add_library(application
        application.cpp
        application.h
)

target_include_directories(application
    PUBLIC
        ${CMAKE_SOURCE_DIR}
)

target_link_libraries(application
    PUBLIC
        cp2p_crypto
        cp2p_network
        util
)

target_compile_features(application PRIVATE cxx_std_20)
