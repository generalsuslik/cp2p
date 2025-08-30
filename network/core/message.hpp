//
// Created by generalsuslik on 24.02.25.
//

#ifndef MESSAGE_HPP
#define MESSAGE_HPP

#include <nlohmann/json.hpp>

#include "cmake-build-debug/network/core/proto/message.pb.h"

#include "crypto/aes.hpp"
#include "util/util.hpp"

namespace cp2p {

    enum class MessageType : uint32_t {
        ACCEPT,
        DISCONNECT,
        HANDSHAKE,
        SEARCH,
        SEARCH_RESPONSE,
        TEXT,
    };

    /**
     * @class Message
     * @brief The Message class is a representation of a communication or notification.
     */
    template <CMessageContainer MessageContainer>
    class Message {
    public:
        using value_type = std::uint8_t;

    public:
        Message() = default;

        explicit Message(const MessageContainer& message, const MessageType type = MessageType::TEXT)
            : type_(type)
        {
            set_message_type(type);
            set_message(message);
        }

        void encrypt() {
            if (message_.has_aes()) {
                throw std::runtime_error("Message is already encrypted");
            }

            const auto& [aes_key, aes_iv] = aes::generate_aes_key_iv();

            set_aes(aes_key, aes_iv);
            do_encrypt();
            is_encrypted_ = true;
        }

        void decrypt() {
            const auto& aes_key = get_aes_key();
            const auto& aes_iv = get_aes_iv();
            assert(aes_key.size() == aes::key_length);
            assert(aes_iv.size() == aes::iv_length);

            const auto& message = get_vec_message();
            const auto& decrypted_message = aes::aes_decrypt(message, aes_key, aes_iv);

            set_message(decrypted_message);
            is_encrypted_ = false;
        }

        [[nodiscard]]
        TEncryptedMessage get() const {
            return message_;
        }

        [[nodiscard]]
        std::string serialize_to_string() const {
            return message_.SerializeAsString();
        }

        void parse_from_array(const char* ptr, const std::size_t size) {
            message_.ParseFromArray(ptr, size);
        }

        TEncryptedMessage_TMessageHeader* get_mut_header() {
            return message_.mutable_message_header();
        }

        [[nodiscard]]
        TEncryptedMessage_TMessageHeader get_header() const {
            return message_.message_header();
        }

        [[nodiscard]]
        MessageContainer get_message() const {
            std::string message_str(message_.message().data(), message_.message().size());
            return MessageContainer(message_str.begin(), message_str.end());
        }

        [[nodiscard]]
        std::vector<std::uint8_t> get_aes_key() const {
            const TEncryptedMessage_TAes* aes = &message_.aes();

            const auto* data = reinterpret_cast<const std::uint8_t*>(aes->aes().data());
            std::vector<std::uint8_t> aes_key(data, data + aes->aes_len());
            return aes_key;
        }

        [[nodiscard]]
        std::vector<std::uint8_t> get_aes_iv() const {
            const TEncryptedMessage_TAes* aes = &message_.aes();

            const auto* data = reinterpret_cast<const std::uint8_t*>(aes->iv().data());
            std::vector<std::uint8_t> aes_iv(data, data + aes->iv_len());
            return aes_iv;
        }

        void set_aes(const std::vector<std::uint8_t>& aes_key, const std::vector<std::uint8_t>& aes_iv) {
            TEncryptedMessage_TAes* aes = message_.mutable_aes();

            aes->set_aes(aes_key.data(), aes_key.size());
            aes->set_aes_len(aes_key.size());

            aes->set_iv(aes_iv.data(), aes_iv.size());
            aes->set_iv_len(aes_iv.size());
        }

        [[nodiscard]]
        std::uint64_t size() const {
            const auto header = get_header();
            return header.message_length();
        }

        [[nodiscard]]
        const char* data() const {
            return message_.message().data();
        }

        char* data() {
            return message_.mutable_message()->data();
        }

        [[nodiscard]]
        MessageType get_type() const {
            const auto header = get_header();
            return static_cast<MessageType>(header.message_type());
        }

        [[nodiscard]]
        bool is_encrypted() const {
            return is_encrypted_;
        }

    private:
        void do_encrypt() {
            const auto& aes_key = get_aes_key();
            const auto& aes_iv = get_aes_iv();

            const auto& encrypted_message = aes::aes_encrypt(
                message_.message(),
                aes_key,
                aes_iv
            );
            set_message(encrypted_message);
        }

        [[nodiscard]]
        std::vector<std::uint8_t> get_vec_message() const {
            const std::string& message = message_.message();

            const auto& message_vec = get_container_from_string(message);
            return message_vec;
        }

        void set_message(const MessageContainer& message) {
            TEncryptedMessage_TMessageHeader* header = get_mut_header();
            header->set_message_length(message.size());

            message_.set_message(message.data(), message.size());
        }

        void set_message_type(const MessageType type) {
            TEncryptedMessage_TMessageHeader* header = get_mut_header();

            switch (type) {
                case MessageType::ACCEPT:
                    header->set_message_type(TEncryptedMessage_TMessageHeader_EMessageType_ACCEPT);
                    break;
                case MessageType::DISCONNECT:
                    header->set_message_type(TEncryptedMessage_TMessageHeader_EMessageType_DISCONNECT);
                    break;
                case MessageType::HANDSHAKE:
                    header->set_message_type(TEncryptedMessage_TMessageHeader_EMessageType_HANDSHAKE);
                    break;
                case MessageType::SEARCH:
                    header->set_message_type(TEncryptedMessage_TMessageHeader_EMessageType_SEARCH);
                    break;
                case MessageType::SEARCH_RESPONSE:
                    header->set_message_type(TEncryptedMessage_TMessageHeader_EMessageType_SEARCH_RESPONSE);
                    break;
                default:
                    header->set_message_type(TEncryptedMessage_TMessageHeader_EMessageType_TEXT);
                    break;
            }
        }

        template <CMessageContainer Container>
        friend std::ostream& operator<<(std::ostream& os, const Message<Container>& message);

    private:
        TEncryptedMessage message_;
        MessageType type_ = MessageType::TEXT;
        bool is_encrypted_ = false;
    };

    template <CMessageContainer MessageContainer>
    std::ostream& operator<<(std::ostream& os, const Message<MessageContainer>& message) {
        for (const auto& byte : message.get_message()) {
            os << byte;
        }
        return os;
    }


} // cp2p


#endif //MESSAGE_HPP
