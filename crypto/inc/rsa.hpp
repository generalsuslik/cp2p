//
// Created by generalsuslik on 25.01.25.
//

#ifndef RSA_HPP
#define RSA_HPP

#include <openssl/types.h>

#include <string>
#include <utility>
#include <vector>

namespace cp2p::rsa {


    constexpr int k_bits = 2048;
    constexpr int k_bytes = k_bits / 8;

    /**
     * @brief generate a pair of rsa keys for peer
     *
     * @return std::pair<PUBLIC_KEY, PRIVATE_KEY> (check the order)
     */
    std::pair<std::string, std::string> generate_rsa_keys();

    std::vector<unsigned char> rsa_encrypt(EVP_PKEY* public_key, const std::string& plaintext);

    std::vector<unsigned char> rsa_encrypt(EVP_PKEY* public_key, const std::vector<unsigned char>& plaintext);

    std::vector<unsigned char> rsa_decrypt(EVP_PKEY* private_key, const std::vector<unsigned char>& ciphertext);

    EVP_PKEY* to_public_key(const std::string& str);

    EVP_PKEY* to_private_key(const std::string& str);

    std::string to_public_string(const EVP_PKEY* public_key);

    std::string to_private_string(const EVP_PKEY* private_key);


} // cp2p::rsa


#endif //RSA_HPP
