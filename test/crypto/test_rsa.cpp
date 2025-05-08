//
// Created by generalsuslik on 11.03.25.
//

#include <gtest/gtest.h>

#include "../../crypto/inc/rsa.hpp"
#include "../test_util/test_util.hpp"

TEST(RSA, test_rsa_encoding) {
    using namespace cp2p;

    rsa::RSAKeyPair rsa;
    const std::string random_string = ::random_string(214);

    std::vector<unsigned char> encrypted = rsa.encrypt(random_string.begin(), random_string.end());
    std::vector<unsigned char> decrypted = rsa.decrypt(encrypted.begin(), encrypted.end());
    const std::string decrypted_str(decrypted.begin(), decrypted.end());

    ASSERT_FALSE(decrypted_str.empty());
    ASSERT_TRUE(decrypted_str == random_string);
}


