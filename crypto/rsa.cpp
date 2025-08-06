//
// Created by generalsuslik on 25.01.25.
//

#include "rsa.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <stdexcept>

namespace cp2p::rsa {

    RSAKeyPair::RSAKeyPair(const int bits) {
        generate_pair(bits);
    }

    RSAKeyPair::RSAKeyPair(RSAKeyPair&&) noexcept = default;
    RSAKeyPair& RSAKeyPair::operator=(RSAKeyPair&&) noexcept = default;

    RSAKeyPair::~RSAKeyPair() = default; // because we already have unique_ptr wrappers

    EVP_PKEY* RSAKeyPair::get() const {
        return pkey_.get();
    }

    /*
     * RSAKeyPair::encrypt and RSAKeyPair::decrypt functions are defined in the
     * .hpp file because of the templates
     */

    std::string RSAKeyPair::to_public_string() const {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            throw std::runtime_error("[rsa::to_public_string] Failed to create BIO for public key");
        }

        if (PEM_write_bio_PUBKEY(bio, pkey_.get()) != 1) {
            BIO_free(bio);
            throw std::runtime_error("[rsa::to_public_string] Failed to write public key to BIO");
        }

        BIO_flush(bio);
        BUF_MEM* buf;
        BIO_get_mem_ptr(bio, &buf);

        std::string key(buf->data, buf->length);

        BIO_free(bio);

        return key;
    }

    std::string RSAKeyPair::to_private_string() const {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            throw std::runtime_error("[rsa::to_private_string] Failed to create BIO for private key");
        }

        if (PEM_write_bio_PrivateKey(bio, pkey_.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            BIO_free(bio);
            throw std::runtime_error("[rsa::to_private_string] Failed to write private key to BIO");
        }

        BIO_flush(bio);
        BUF_MEM* buf;
        BIO_get_mem_ptr(bio, &buf);

        std::string key(buf->data, buf->length);

        BIO_free(bio);

        return key;
    }

    void RSAKeyPair::generate_pair(const int bits) {
        const EVP_CTX_ptr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr), EVP_PKEY_CTX_free);
        if (!ctx) {
            throw std::runtime_error("Failed to create EVP_PKEY_CTX");
        }

        if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
            throw std::runtime_error("EVP_PKEY_keygen_init failed");
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) <= 0) {
            throw std::runtime_error("Failed to set RSA key bits");
        }

        EVP_PKEY* raw_pkey = nullptr;
        if (EVP_PKEY_generate(ctx.get(), &raw_pkey) <= 0) {
            throw std::runtime_error("RSA key generation failed");
        }

        pkey_.reset(raw_pkey);
    }


} // cp2p::rsa
