//
// Created by generalsuslik on 11.03.25.
//

#include <gtest/gtest.h>
#include <openssl/evp.h>

#include "../../crypto/inc/rsa.hpp"

TEST(RSAConvertions, test_public_key_convertion) {
    const auto& [public_key_str, _] = cp2p::rsa::generate_rsa_keys();

    const EVP_PKEY* public_key = cp2p::rsa::to_public_key(public_key_str);
    const std::string converted_public_key_str = cp2p::rsa::to_public_string(public_key);
    const EVP_PKEY* converted_public_key = cp2p::rsa::to_public_key(converted_public_key_str);
    const std::string converted_x2_public_key_str = cp2p::rsa::to_public_string(converted_public_key);

    assert(public_key_str == converted_public_key_str);
    assert(public_key_str == converted_x2_public_key_str);
    assert(public_key && converted_public_key && cp2p::rsa::to_public_key(converted_x2_public_key_str));
    assert(EVP_PKEY_eq(public_key, converted_public_key) == 1);
    assert(EVP_PKEY_eq(public_key, cp2p::rsa::to_public_key(converted_x2_public_key_str)));
}

TEST(RSAConvertions, test_private_key_convertion) {
    const auto& [_, private_key_str] = cp2p::rsa::generate_rsa_keys();

    const EVP_PKEY* private_key = cp2p::rsa::to_private_key(private_key_str);
    const std::string converted_private_key_str = cp2p::rsa::to_private_string(private_key);
    const EVP_PKEY* converted_private_key = cp2p::rsa::to_private_key(converted_private_key_str);
    const std::string converted_x2_private_key_str = cp2p::rsa::to_private_string(converted_private_key);

    assert(private_key && converted_private_key && cp2p::rsa::to_private_key(converted_x2_private_key_str));
    assert(EVP_PKEY_eq(private_key, converted_private_key) == 1);
    assert(EVP_PKEY_eq(private_key, cp2p::rsa::to_private_key(converted_x2_private_key_str)));
}

TEST(RSAConvertions, test_public_private_key_conversion_integrity) {
    const auto& [public_key_str, private_key_str] = cp2p::rsa::generate_rsa_keys();

    const EVP_PKEY* public_key = cp2p::rsa::to_public_key(public_key_str);
    const EVP_PKEY* private_key = cp2p::rsa::to_private_key(private_key_str);

    const std::string converted_public_key_str = cp2p::rsa::to_public_string(public_key);
    const std::string converted_private_key_str = cp2p::rsa::to_private_string(private_key);

    assert(public_key && cp2p::rsa::to_public_key(converted_public_key_str));
    assert(EVP_PKEY_eq(public_key, cp2p::rsa::to_public_key(converted_public_key_str)) == 1);

    assert(private_key && cp2p::rsa::to_private_key(converted_private_key_str));
    assert(EVP_PKEY_eq(private_key, cp2p::rsa::to_private_key(converted_private_key_str)) == 1);
}

