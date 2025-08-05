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
        ${CMAKE_SOURCE_DIR}/test/message/test_message.cpp
        ${CMAKE_SOURCE_DIR}/test/crypto/test_rsa.cpp
)

target_include_directories(${TESTS}
    PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/test
)

add_subdirectory(test_util)

target_link_libraries(${TESTS}
    PRIVATE
        GTest::GTest
        GTest::Main
        OpenSSL::SSL
        OpenSSL::Crypto
        fmt::fmt

        test_util

        cp2p_crypto
#        cp2p_network
)

target_compile_options(${TESTS} PRIVATE -g)

gtest_discover_tests(${TESTS})
