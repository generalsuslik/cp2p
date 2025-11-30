//
// Created by generalsuslik on 25.04.25.
//

#ifndef CRYPTO_UTIL_HPP
#define CRYPTO_UTIL_HPP

#include <string>

namespace crypto {
    constexpr int digest_length = 16;

    std::string md5_hash(const std::string& input);
} // namespace crypto

#endif //CRYPTO_UTIL_HPP
