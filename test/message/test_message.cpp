//
// Created by generalsuslik on 02.08.25.
//

#include <gtest/gtest.h>

#include <cstdint>

#include "network/message.hpp"

#include "test_util/test_util.hpp"

TEST(TestMessage, test_str_message) {
    using namespace cp2p;

    const std::string message_str = random_string();

    Message message(message_str);

    ASSERT_EQ(1, 1);
}

TEST(TestMessage, test_vec_message) {
    ASSERT_TRUE(true);
}
