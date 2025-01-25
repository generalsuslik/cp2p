//
// Created by generalsuslik on 25.01.25.
//

#include "../inc/crypto.hpp"

#include <iostream>
#include <ostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <stdexcept>

constexpr int k_bits = 2048;

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

    if (PEM_write_bio_PrivateKey(bio_private, rsa_key, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
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

    return { private_key, public_key };
}
