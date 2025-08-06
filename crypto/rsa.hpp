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

    /**
     * @class RSAKeyPair
     * @brief Represents an RSA key pair consisting of a public and private key for cryptographic purposes.
     *
     * The RSAKeyPair class provides functionality to generate RSA key pairs, retrieve the public and private keys,
     * and perform basic key-related operations.
     */
    class RSAKeyPair {
    public:
        explicit RSAKeyPair(int bits = k_bits);

        RSAKeyPair(const RSAKeyPair&) = delete;
        RSAKeyPair& operator=(const RSAKeyPair&) = delete;

        RSAKeyPair(RSAKeyPair&&) noexcept;
        RSAKeyPair& operator=(RSAKeyPair&&) noexcept;

        ~RSAKeyPair();

        /**
         * @brief
         *
         * @return raw pointer to the key
         */
        [[nodiscard]]
        EVP_PKEY* get() const;

        /*
         * RSAKeyPair::encrypt and RSAKeyPair::decrypt functions are defined right there, in the
         * .hpp file because of the templates
         */

        /**
         * @brief Encrypts the collection from begin to end.
         *
         * Note that a collection must support contiguous iterators
         *
         * @tparam It contiguous iterator for the collection to encrypt (std::vector or std::string)
         * @param begin begin iterator of the collection to encrypt
         * @param end end iterator of the collection to encrypt
         * @param public_key receiver's public key
         * @return vector of 1-byte symbols; contains cyphertext
         */
        template <std::contiguous_iterator It>
        static std::vector<std::uint8_t> encrypt(It begin, It end, EVP_PKEY* public_key) {
            const std::size_t plaintext_len = std::distance(begin, end);
            const auto* data = reinterpret_cast<const std::uint8_t*>(&*begin);

            // Get the key size and calculate the maximum plaintext length
            const int key_size = EVP_PKEY_size(public_key);
            const int max_plaintext_len = key_size - 42; // 42 bytes is the overhead for OAEP padding

            if (plaintext_len > static_cast<std::size_t>(max_plaintext_len)) {
                throw std::runtime_error("Input data too large for RSA encryption with current key size");
            }

            const EVP_CTX_ptr ctx(EVP_PKEY_CTX_new(public_key, nullptr), EVP_PKEY_CTX_free);
            if (!ctx) throw std::runtime_error("Failed to create encryption context");

            if (EVP_PKEY_encrypt_init(ctx.get()) <= 0)
                throw std::runtime_error("EVP_PKEY_encrypt_init failed");

            std::size_t len;
            if (EVP_PKEY_encrypt(ctx.get(), nullptr, &len, data, plaintext_len) <= 0)
                throw std::runtime_error("Failed to determine encrypted size");

            if (EVP_PKEY_base_id(public_key) != EVP_PKEY_RSA) {
                throw std::runtime_error("Not an RSA key");
            }

            std::vector<std::uint8_t> encrypted(len);
            if (EVP_PKEY_encrypt(ctx.get(), encrypted.data(), &len, data, plaintext_len) <= 0)
                throw std::runtime_error("RSA encryption failed");

            encrypted.resize(len);
            return encrypted;
        }

        /**
         * @brief Decrypts the collection from begin to end.
         *
         * Note that a collection must support contiguous iterators
         *
         * @tparam It contiguous iterator for the collection to decrypt (std::vector or std::string)
         * @param begin begin iterator of the collection to decrypt
         * @param end end iterator of the collection to decrypt
         * @return vector of 1-byte symbols; contains plaintext
         */
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

        /**
         * @brief Gets public key from EVP_PKEY* and converts it to std::string
         *
         * @return public RSA key as a string
         */
        [[nodiscard]]
        std::string to_public_string() const;

        /**
         * @brief Gets private key from EVP_PKEY* and converts it to std::string
         *
         * @return private RSA key as a string
         */
        [[nodiscard]]
        std::string to_private_string() const;

    private:
        /**
         * @brief Generates an RSA key pair and sets it to pkey
         *
         * @param bits sizeof keygen rsa key
         */
        void generate_pair(int bits);

    private:
        using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
        using EVP_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

        EVP_PKEY_ptr pkey_{nullptr, EVP_PKEY_free};
    };

} // cp2p::rsa


#endif //RSA_HPP
