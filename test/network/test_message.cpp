//
// Created by generalsuslik on 13.03.25.
//

#include <gtest/gtest.h>

#include "crypto/aes.hpp"
#include "network/message.hpp"
#include "util/util.hpp"

#include "test_util/test_util.hpp"

TEST(TestMessage, test_message_creation) {
    using namespace cp2p;

    const std::string message_str = random_string();

    const Message message(message_str);

    const std::uint64_t len = message.size();
    ASSERT_EQ(len, message_str.size());

    const std::string deserialized_str = message.get_message();
    ASSERT_EQ(len, deserialized_str.size());
    ASSERT_EQ(deserialized_str, message_str);
}

TEST(TestMessage, test_encrypt_decrypt_message) {
    using namespace cp2p;

    const auto& [aes_key, aes_iv] = aes::generate_aes_key_iv();
    const std::string message_str = random_string();

    const auto& encrypted_message = aes::aes_encrypt(message_str, aes_key, aes_iv);
    const std::string encrypted_serialized(reinterpret_cast<const char*>(encrypted_message.data()), encrypted_message.size());

    TEncryptedMessage message;

    TEncryptedMessage_TMessageHeader* header = message.mutable_message_header();
    header->set_message_type(TEncryptedMessage_TMessageHeader_EMessageType_HANDSHAKE);
    header->set_message_length(encrypted_message.size());

    TEncryptedMessage_TAes* aes = message.mutable_aes();
    aes->set_aes(aes_key.data(), aes_key.size());
    aes->set_aes_len(aes_key.size());
    aes->set_iv(aes_iv.data(), aes_iv.size());
    aes->set_iv_len(aes_iv.size());

    message.set_message(encrypted_message.data(), encrypted_serialized.size());

    const std::uint64_t encrypted_len = message.message_header().message_length();
    ASSERT_EQ(encrypted_len, encrypted_message.size());

    const auto* data = reinterpret_cast<const std::uint8_t*>(message.message().data());
    const std::vector<std::uint8_t> encrypted_serialized_vector(data, data + message.message_header().message_length());
    ASSERT_EQ(encrypted_len, encrypted_serialized.size());
    ASSERT_EQ(encrypted_serialized_vector, encrypted_message);

    const TEncryptedMessage_TAes* aes2 = message.mutable_aes();
    const auto* aes_data = reinterpret_cast<const std::uint8_t*>(aes2->aes().data());
    const std::vector<std::uint8_t> decrypted_aes(aes_data, aes_data + aes2->aes_len());
    ASSERT_EQ(decrypted_aes.size(), aes_key.size());
    ASSERT_EQ(decrypted_aes, aes_key);

    const auto* iv_data = reinterpret_cast<const std::uint8_t*>(aes2->iv().data());
    const std::vector<std::uint8_t> decrypted_iv(iv_data, iv_data + aes2->iv().size());
    ASSERT_EQ(decrypted_iv.size(), aes_iv.size());
    ASSERT_EQ(decrypted_iv, aes_iv);

    const auto& decrypted_message = aes::aes_decrypt(
        encrypted_serialized_vector,
        decrypted_aes,
        decrypted_iv
    );
    ASSERT_EQ(decrypted_message.size(), message_str.size());
    ASSERT_EQ(decrypted_message, message_str);
}
