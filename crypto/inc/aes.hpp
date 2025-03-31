//
// Created by generalsuslik on 28.01.25.
//

#ifndef AES_HPP
#define AES_HPP

#include <string>
#include <vector>

namespace cp2p::aes {

    constexpr size_t key_length = 32; // 256 bits for AES-256
    constexpr size_t iv_length  = 16; // 128-bit IV (initialization vector)

    /**
     * @brief Generates a random AES-256 key and a 128-bit IV.
     *
     * @return A std::pair where:
     *         - first  : A vector of unsigned char containing a 32-byte AES key.
     *         - second : A vector of unsigned char containing a 16-byte IV.
     *
     * @throws std::runtime_error if key or IV generation fails.
     */
    std::pair<std::vector<unsigned char>, std::vector<unsigned char>> generate_aes_key_iv();

    /**
     * Encrypts given plaintext using AES-256-CBC.
     *
     * @param plaintext The text to encrypt.
     * @param key A 32-byte (256-bit) key.
     * @param iv A 16-byte (128-bit) initialization vector.
     * @return A vector of unsigned char containing the ciphertext.
     *
     * @throws std::runtime_error on failure.
     */
    std::vector<unsigned char> aes_encrypt(const std::string& plaintext,
                                           const std::vector<unsigned char>& key,
                                           const std::vector<unsigned char>& iv);

    /**
     * Decrypts given ciphertext using AES-256-CBC.
     *
     * @param ciphertext A vector of unsigned char containing the ciphertext.
     * @param key A 32-byte (256-bit) key.
     * @param iv A 16-byte (128-bit) initialization vector.
     * @return The decrypted plaintext as a string.
     *
     * @throws std::runtime_error on failure.
     */
    std::string aes_decrypt(const std::vector<unsigned char>& ciphertext,
                            const std::vector<unsigned char>& key,
                            const std::vector<unsigned char>& iv);


} // cp2p


#endif //AES_HPP
