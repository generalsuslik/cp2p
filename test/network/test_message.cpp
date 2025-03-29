//
// Created by generalsuslik on 13.03.25.
//

#include <gtest/gtest.h>

#include "../../network/inc/message.hpp"

#include "../test_util/test_util.hpp"

TEST(TestMessage, test_message_creation) {
    using namespace cp2p;

    const std::string message_str = random_string();
    const Message message(message_str);

    assert(message.header().message_length == message.length());
    assert(message.length() == message_str.length());
    assert(message.type() == MessageType::TEXT);
    assert(message.body() == message_str);
}

TEST(TestMessage, test_serialization_deserialization) {
    using namespace cp2p;

    const std::string message_str = random_string();
    Message message(message_str);

    const std::string message_body = message.body();
    const std::size_t message_length = message.length();
    const std::size_t message_size = message.size();
    const MessageType message_type = message.type();

    message.decode_header();

    assert(message.body() == message_body);
    assert(message.length() == message_length);
    assert(message.size() == message_size);
    assert(message.type() == message_type);
}
