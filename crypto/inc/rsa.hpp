//
// Created by generalsuslik on 25.01.25.
//

#ifndef RSA_HPP
#define RSA_HPP

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/types.h>

#include <memory>
#include <string>
#include <vector>

namespace cp2p::rsa {


    constexpr int k_bits = 2048;
    constexpr int k_bytes = k_bits / 8;

    class RSAKeyPair {
    public:
        explicit RSAKeyPair(int bits = k_bits);

        RSAKeyPair(const RSAKeyPair&) = delete;
        RSAKeyPair& operator=(const RSAKeyPair&) = delete;

        RSAKeyPair(RSAKeyPair&&) noexcept;
        RSAKeyPair& operator=(RSAKeyPair&&) noexcept;

        ~RSAKeyPair();

        [[nodiscard]]
        EVP_PKEY* get() const;

        template <std::random_access_iterator It>
        std::vector<std::uint8_t> encrypt(It begin, It end) {
            const std::size_t plaintext_len = std::distance(begin, end);
            const auto* data = reinterpret_cast<const std::uint8_t*>(&*begin);

            // Get the key size and calculate the maximum plaintext length
            const int key_size = EVP_PKEY_size(pkey_.get());
            const int max_plaintext_len = key_size - 42; // 42 bytes is the overhead for OAEP padding

            if (plaintext_len > static_cast<std::size_t>(max_plaintext_len)) {
                throw std::runtime_error("Input data too large for RSA encryption with current key size");
            }

            const EVP_CTX_ptr ctx(EVP_PKEY_CTX_new(pkey_.get(), nullptr), EVP_PKEY_CTX_free);
            if (!ctx) throw std::runtime_error("Failed to create encryption context");

            if (EVP_PKEY_encrypt_init(ctx.get()) <= 0)
                throw std::runtime_error("EVP_PKEY_encrypt_init failed");

            std::size_t len;
            if (EVP_PKEY_encrypt(ctx.get(), nullptr, &len, data, plaintext_len) <= 0)
                throw std::runtime_error("Failed to determine encrypted size");

            if (EVP_PKEY_base_id(pkey_.get()) != EVP_PKEY_RSA) {
                throw std::runtime_error("Not an RSA key");
            }

            std::vector<std::uint8_t> encrypted(len);
            if (EVP_PKEY_encrypt(ctx.get(), encrypted.data(), &len, data, plaintext_len) <= 0)
                throw std::runtime_error("RSA encryption failed");

            encrypted.resize(len);
            return encrypted;
        }

        template <std::contiguous_iterator It>
        std::vector<std::uint8_t> decrypt(It begin, It end) {
            const std::size_t ciphertext_len = std::distance(begin, end);
            const auto* data = reinterpret_cast<const std::uint8_t*>(&*begin);

            const EVP_CTX_ptr ctx(EVP_PKEY_CTX_new(pkey_.get(), nullptr), EVP_PKEY_CTX_free);
            if (!ctx) throw std::runtime_error("Failed to create decryption context");

            if (EVP_PKEY_decrypt_init(ctx.get()) <= 0)
                throw std::runtime_error("EVP_PKEY_decrypt_init failed");

            std::size_t len;
            if (EVP_PKEY_decrypt(ctx.get(), nullptr, &len, data, ciphertext_len) <= 0)
                throw std::runtime_error("Failed to determine decrypted size");

            std::vector<std::uint8_t> decrypted(len);
            if (EVP_PKEY_decrypt(ctx.get(), decrypted.data(), &len, data, ciphertext_len) <= 0)
                throw std::runtime_error("RSA decryption failed");

            decrypted.resize(len);
            return decrypted;
        }

        [[nodiscard]]
        std::string to_public_string() const;

        [[nodiscard]]
        std::string to_private_string() const;

    private:
        void generate_pair(int bits);

    private:
        using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
        using EVP_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

        EVP_PKEY_ptr pkey_{nullptr, EVP_PKEY_free};
    };

} // cp2p::rsa


#endif //RSA_HPP
