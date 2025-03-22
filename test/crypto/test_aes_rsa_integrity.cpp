//
// Created by generalsuslik on 11.03.25.
//

#include <gtest/gtest.h>

#include "../../crypto/inc/aes.hpp"
#include "../../crypto/inc/rsa.hpp"
#include "../test_util/test_util.hpp"

TEST(AES_RSA, aes_rsa_integrity) {
    using namespace cp2p;

    const std::string plaintext = random_string();

    const auto& [aes_key, aes_iv] = aes::generate_aes_key_iv();
    const auto& [public_rsa, private_rsa] = rsa::generate_rsa_keys();

    // Encrypting plaintext with AES
    const std::vector<unsigned char> ciphertext = aes::aes_encrypt(plaintext, aes_key, aes_iv);

    // Serializing AES for the encryption
    std::vector<unsigned char> aes;
    for (const auto ch : aes_key) {
        aes.push_back(ch);
    }
    aes.push_back(' ');
    for (const auto ch : aes_iv) {
        aes.push_back(ch);
    }

    // Encrypting AES
    const std::vector<unsigned char> encrypted_aes = rsa::rsa_encrypt(rsa::to_public_key(public_rsa), aes);

    // ... Imagine AES and ciphertext are being sent through the network

    // Decrypting AES
    const std::vector<unsigned char> decrypted_aes = rsa::rsa_decrypt(rsa::to_private_key(private_rsa), encrypted_aes);

    // Deserializing AES for the decryption
    const auto it = std::ranges::find(decrypted_aes, ' ');
    const std::vector<unsigned char> encrypted_aes_key(decrypted_aes.begin(), it);
    const std::vector<unsigned char> decrypted_aes_iv(it + 1, decrypted_aes.end());

    const std::string decrypted_text = aes::aes_decrypt(ciphertext, encrypted_aes_key, decrypted_aes_iv);

    assert(decrypted_text == plaintext);
}
