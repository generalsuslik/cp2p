//
// Created by generalsuslik on 25.04.25.
//

#include <gtest/gtest.h>

#include "../test_util/test_util.hpp"

#include "../../crypto/inc/util.hpp"

TEST(CRYPTO_UTIL_TEST, util_test) {
    const std::string input = random_string();
    const std::string hash = crypto::md5_hash(input);

    assert(hash.length() == crypto::digest_length);
}
