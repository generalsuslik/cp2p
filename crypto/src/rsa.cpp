//
// Created by generalsuslik on 25.01.25.
//

#include "../inc/rsa.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <stdexcept>
#include <vector>

namespace cp2p::rsa {
    /*
     * generates [ PUBLIC_KEY, PRIVATE_KEY ] pair
     */
    std::pair<std::string, std::string> generate_rsa_keys() {
        EVP_PKEY* rsa_key = EVP_RSA_gen(k_bits);
        if (!rsa_key) {
            throw std::runtime_error("Failed to generate RSA key");
        }

        BIO* bio_private = BIO_new(BIO_s_mem());
        EVP_PKEY_print_public(bio_private, rsa_key, 4, nullptr);
        if (!bio_private) {
            EVP_PKEY_free(rsa_key);
            throw std::runtime_error("Failed to create BIO for private key");
        }

        if (PEM_write_bio_PrivateKey(bio_private, rsa_key,
                nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            BIO_free(bio_private);
            EVP_PKEY_free(rsa_key);
            throw std::runtime_error("Failed to write private key to BIO");
                }

        BIO* bio_public = BIO_new(BIO_s_mem());
        if (!bio_public) {
            BIO_free(bio_private);
            EVP_PKEY_free(rsa_key);
            throw std::runtime_error("Failed to create BIO for public key");
        }

        if (PEM_write_bio_PUBKEY(bio_public, rsa_key) != 1) {
            BIO_free_all(bio_public);
            BIO_free(bio_private);
            EVP_PKEY_free(rsa_key);
            throw std::runtime_error("Failed to write public key to BIO");
        }

        BUF_MEM* private_buf;
        BIO_get_mem_ptr(bio_private, &private_buf);
        std::string private_key(private_buf->data, private_buf->length);

        BUF_MEM* public_buf;
        BIO_get_mem_ptr(bio_public, &public_buf);
        std::string public_key(public_buf->data, public_buf->length);

        BIO_free(bio_private);
        BIO_free(bio_public);
        EVP_PKEY_free(rsa_key);

        return { std::move(public_key), std::move(private_key) };
    }

    std::vector<unsigned char> rsa_encrypt(EVP_PKEY* public_key, const std::string& plaintext) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(public_key, nullptr);
        if (!ctx) {
            throw std::runtime_error("Failed to create EVP_PKEY_CTX: "
                + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize encryption: "
                + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        std::size_t len;
        if (EVP_PKEY_encrypt(ctx, nullptr, &len,
                reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.length()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to determine encrypted size: "
                + std::string(ERR_error_string(ERR_get_error(), nullptr)));
                }

        std::vector<unsigned char> encrypted(len);
        if (EVP_PKEY_encrypt(ctx, encrypted.data(), &len,
                reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.length()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Encryption failed: "
                + std::string(ERR_error_string(ERR_get_error(), nullptr)));
                }

        EVP_PKEY_CTX_free(ctx);
        encrypted.resize(len);
        return encrypted;
    }

    std::vector<unsigned char> rsa_encrypt(EVP_PKEY* public_key, const std::vector<unsigned char>& plaintext) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(public_key, nullptr);
        if (!ctx) {
            throw std::runtime_error("Failed to create EVP_PKEY_CTX: "
                + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize encryption: "
                + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        std::size_t len;
        if (EVP_PKEY_encrypt(ctx, nullptr, &len,
                plaintext.data(), plaintext.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to determine encrypted size: "
                + std::string(ERR_error_string(ERR_get_error(), nullptr)));
                }

        std::vector<unsigned char> encrypted(len);
        if (EVP_PKEY_encrypt(ctx, encrypted.data(), &len,
                plaintext.data(), plaintext.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Encryption failed: "
                + std::string(ERR_error_string(ERR_get_error(), nullptr)));
                }

        EVP_PKEY_CTX_free(ctx);
        encrypted.resize(len);
        return encrypted;
    }

    std::vector<unsigned char> rsa_decrypt(EVP_PKEY* private_key, const std::vector<unsigned char>& ciphertext) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, nullptr);
        if (!ctx) {
            throw std::runtime_error("Failed to create EVP_PKEY_CTX: "
                + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        if (EVP_PKEY_decrypt_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize decryption: "
                + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        std::size_t len;
        if (EVP_PKEY_decrypt(ctx, nullptr, &len, ciphertext.data(), ciphertext.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to determine decrypted size: "
                + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        std::vector<unsigned char> decrypted(len);
        if (EVP_PKEY_decrypt(ctx, decrypted.data(), &len, ciphertext.data(), ciphertext.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("[rsa::rsa_decrypt] Decryption failed: "
                + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        EVP_PKEY_CTX_free(ctx);
        return decrypted;
    }

    EVP_PKEY* get_public_key(const std::string& str) {
        BIO* bio = BIO_new_mem_buf(str.c_str(), static_cast<int>(str.size()));
        if (!bio) {
            throw std::runtime_error("Failed to create BIO for public key: "
                + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        EVP_PKEY* public_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!public_key) {
            throw std::runtime_error("Failed to read public key: "
                + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        return public_key;
    }

    EVP_PKEY* get_private_key(const std::string& str) {
        BIO* bio = BIO_new_mem_buf(str.c_str(), static_cast<int>(str.size()));
        if (!bio) {
            throw std::runtime_error("Failed to create BIO for private key: "
                + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!pkey) {
            throw std::runtime_error("Failed to read private key: "
                + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        return pkey;
    }


} // cp2p::rsa
