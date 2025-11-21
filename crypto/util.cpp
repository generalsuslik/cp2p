//
// Created by generalsuslik on 25.04.25.
//

#include "util.hpp"

#include <openssl/evp.h>

#include <iomanip>
#include <sstream>
#include <string>

namespace crypto {

    std::string md5_hash(const std::string& input) {
        unsigned char digest[digest_length];
        const int err = !EVP_Q_digest(nullptr, "MD5", nullptr, input.c_str(), input.size(), digest, nullptr);
        if (err) {
            throw std::runtime_error("Failed to generate md5 hash");
        }

        std::stringstream ss;
        for (int i = 0; i < digest_length / 2; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[i]);
        }

        return ss.str();
    }

} // namespace crypto
