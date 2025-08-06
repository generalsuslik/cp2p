cmake_minimum_required(VERSION 3.28)

set(TARGET util)

set(SOURCES
        ${CMAKE_SOURCE_DIR}/util/util.cpp
        ${CMAKE_SOURCE_DIR}/util/util.hpp
)

add_library(util
        ${SOURCES}
)

target_include_directories(${TARGET}
    PRIVATE
        ${CMAKE_SOURCE_DIR}
)

target_compile_features(${TARGET} PRIVATE cxx_std_20)