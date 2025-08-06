add_library(cp2p_crypto
        ${CMAKE_SOURCE_DIR}/crypto/aes.hpp
        ${CMAKE_SOURCE_DIR}/crypto/aes.cpp
        ${CMAKE_SOURCE_DIR}/crypto/rsa.hpp
        ${CMAKE_SOURCE_DIR}/crypto/rsa.cpp
        ${CMAKE_SOURCE_DIR}/crypto/util.hpp
        ${CMAKE_SOURCE_DIR}/crypto/util.cpp
)

target_include_directories(cp2p_crypto
    PUBLIC
        ${CMAKE_SOURCE_DIR}
        ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(cp2p_crypto
        PUBLIC
        OpenSSL::Crypto

        util
)

include_directories(
        /usr/include
        /usr/include/openssl
)

target_compile_features(cp2p_crypto PRIVATE cxx_std_20)