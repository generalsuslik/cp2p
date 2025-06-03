find_package(GTest REQUIRED)
include(GoogleTest)

find_package(fmt REQUIRED)

enable_testing()

set(TESTS tests)

add_executable(${TESTS}
        ${SOURCES}

        ${CMAKE_SOURCE_DIR}/test/main.cpp
        ${CMAKE_SOURCE_DIR}/test/crypto/test_aes.cpp
        ${CMAKE_SOURCE_DIR}/test/crypto/test_aes_rsa_integrity.cpp
        ${CMAKE_SOURCE_DIR}/test/test_util/test_util.cpp
        ${CMAKE_SOURCE_DIR}/test/test_util/test_util.hpp
        ${CMAKE_SOURCE_DIR}/test/network/test_message.cpp
        ${CMAKE_SOURCE_DIR}/test/crypto/test_rsa.cpp
        ${CMAKE_SOURCE_DIR}/test/crypto/test_util.cpp
)

target_include_directories(${TESTS}
    PRIVATE
        ${INCLUDE_DIRS}
)

target_link_libraries(${TESTS}
    PRIVATE
        GTest::GTest
        GTest::Main
        OpenSSL::SSL
        OpenSSL::Crypto
        fmt::fmt
)

target_compile_options(${TESTS} PRIVATE -g)

gtest_discover_tests(${TESTS})
