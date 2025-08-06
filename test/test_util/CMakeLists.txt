cmake_minimum_required(VERSION 3.28)

set(TARGET test_util)

add_library(test_util
        ${CMAKE_SOURCE_DIR}/test/test_util/test_util.cpp
        ${CMAKE_SOURCE_DIR}/test/test_util/test_util.hpp

)

target_include_directories(${TARGET}
    PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/test
)

target_compile_features(${TARGET} PRIVATE cxx_std_20)