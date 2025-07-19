add_library(cp2p_crypto
        inc/aes.hpp
        src/aes.cpp
        inc/rsa.hpp
        src/rsa.cpp
        inc/util.hpp
        src/util.cpp
)

target_include_directories(cp2p_crypto
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${OPENSSL_INCLUDE_DIR})

target_link_libraries(cp2p_crypto
        PUBLIC
        OpenSSL::Crypto)

target_compile_features(cp2p_crypto PRIVATE cxx_std_20)