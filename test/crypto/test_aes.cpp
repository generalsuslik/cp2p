//
// Created by generalsuslik on 11.03.25.
//

#include <gtest/gtest.h>

#include "../../crypto/inc/aes.hpp"

#include "../test_util/test_util.hpp"

TEST(AES, test_encryption_decryption) {
    const auto& [aes_key, aes_iv] = cp2p::aes::generate_aes_key_iv();

    const std::string plaintext = random_string();

    const std::vector<unsigned char> ciphertext = cp2p::aes::aes_encrypt(plaintext, aes_key, aes_iv);
    const std::string decrypted = cp2p::aes::aes_decrypt(ciphertext, aes_key, aes_iv);

    assert(plaintext == decrypted);
}

