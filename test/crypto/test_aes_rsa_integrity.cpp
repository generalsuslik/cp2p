//
// Created by generalsuslik on 11.03.25.
//

#include <gtest/gtest.h>

#include "crypto/aes.hpp"
#include "crypto/rsa.hpp"
#include "test_util/test_util.hpp"

TEST(AES_RSA, aes_rsa_integrity) {
    using namespace cp2p;

    constexpr std::uint8_t DELIMITER = '\t';

    rsa::RSAKeyPair rsa;
    const auto& [aes_key, aes_iv] = aes::generate_aes_key_iv();
    const std::string plaintext = random_string() + "a";

    // Encrypting random plain text
    const std::vector<std::uint8_t> ciphertext = aes::aes_encrypt(plaintext, aes_key, aes_iv);

    // Creating an array to store and forward aes data
    std::vector<std::uint8_t> aes;
    for (const auto& byte : aes_key) {
        aes.push_back(byte);
    }
    aes.push_back(DELIMITER);
    for (const auto& byte : aes_iv) {
        aes.push_back(byte);
    }

    // Encrypting AES
    const std::vector<std::uint8_t> encrypted_aes = rsa::RSAKeyPair::encrypt(aes.begin(), aes.end(), rsa.get());

    // ... Imagine AES and ciphertext are being sent (and received) through the network

    // Decrypting AES
    const std::vector<std::uint8_t> decrypted_aes = rsa.decrypt(encrypted_aes.begin(), encrypted_aes.end());

    // Deserializing AES for the decryption
    const auto it = std::ranges::find(decrypted_aes, DELIMITER);
    const std::vector<std::uint8_t> decrypted_aes_key(decrypted_aes.begin(), it);
    const std::vector<std::uint8_t> decrypted_aes_iv(it + 1, decrypted_aes.end());

    ASSERT_TRUE(aes_key.size() == decrypted_aes_key.size());
    ASSERT_TRUE(aes_key == decrypted_aes_key);
    ASSERT_TRUE(aes_iv.size() == decrypted_aes_iv.size());
    ASSERT_TRUE(aes_iv == decrypted_aes_iv);

    const std::string decrypted_plaintext = aes::aes_decrypt(ciphertext, decrypted_aes_key, decrypted_aes_iv);

    ASSERT_FALSE(decrypted_aes.empty());
    ASSERT_TRUE(decrypted_plaintext == plaintext);
}
