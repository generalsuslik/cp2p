//
// Created by generalsuslik on 28.01.25.
//

#include "aes.hpp"

#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdexcept>

namespace cp2p::aes {


    std::pair<std::vector<unsigned char>, std::vector<unsigned char>> generate_aes_key_iv() {

        std::vector<unsigned char> key(key_length);
        std::vector<unsigned char> iv(iv_length);

        // Generate random key
        if (RAND_bytes(key.data(), key_length) != 1) {
            throw std::runtime_error("Error generating AES key.");
        }

        // Generate random IV
        if (RAND_bytes(iv.data(), iv_length) != 1) {
            throw std::runtime_error("Error generating AES IV.");
        }

        return { key, iv };
    }

    std::vector<unsigned char> aes_encrypt(
        const std::string& plaintext,
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& iv
    ) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create EVP_CIPHER_CTX: "
                + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize AES encryption: "
                + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        const int block_size = EVP_CIPHER_block_size(EVP_aes_256_cbc());
        std::vector<unsigned char> ciphertext(plaintext.size() + block_size);
        int len = 0;
        int ciphertext_len = 0;

        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                reinterpret_cast<const unsigned char*>(plaintext.data()),
                static_cast<int>(plaintext.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AES encryption failed: "
                + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }
        ciphertext_len = len;

        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AES encryption finalization failed: "
                + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }
        ciphertext_len += len;
        ciphertext.resize(ciphertext_len);

        EVP_CIPHER_CTX_free(ctx);
        return ciphertext;
    }

    std::vector<unsigned char> aes_decrypt(
        const std::vector<unsigned char>& ciphertext,
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& iv
    ) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create EVP_CIPHER_CTX: "
                + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize AES decryption: "
                + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        std::vector<unsigned char> plaintext(ciphertext.size());
        int len = 0;
        int plaintext_len = 0;

        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                ciphertext.data(),
                static_cast<int>(ciphertext.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AES decryption failed: "
                + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }
        plaintext_len = len;

        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AES decryption finalization failed: "
                + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }
        plaintext_len += len;
        plaintext.resize(plaintext_len);

        EVP_CIPHER_CTX_free(ctx);
        return plaintext;
    }


} // cp2p
