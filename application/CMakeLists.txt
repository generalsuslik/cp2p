cmake_minimum_required(VERSION 3.28)

set(TARGET cp2p_application)

add_library(cp2p_application
        application.cpp
        application.hpp
)

target_include_directories(${TARGET}
    PUBLIC
        ${CMAKE_SOURCE_DIR}
)

target_link_libraries(${TARGET}
    PUBLIC
        cp2p_crypto
        cp2p_network
        util
)

target_compile_features(${TARGET} PRIVATE cxx_std_20)