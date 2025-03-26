//
// Created by generalsuslik on 25.03.25.
//

#include "../inc/common.hpp"

#include <openssl/sha.h>

#include <cstdint>

namespace cp2p::crypto {


    std::string sha1(const std::string& input) {
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const std::uint8_t*>(input.c_str()), input.size(), hash);
        return { reinterpret_cast<char*>(hash), SHA_DIGEST_LENGTH };
    }


} // namespace crypto
