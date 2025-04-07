//
// Created by generalsuslik on 24.02.25.
//

#ifndef MESSAGE_HPP
#define MESSAGE_HPP

#include <nlohmann/json.hpp>

#include <cstdint>
#include <memory>

namespace cp2p {

    enum class MessageType : uint32_t {
        HANDSHAKE,
        ACCEPT,
        DISCONNECT,
        TEXT,
        FILE, // yet not supported
    };

    class Message {
    public:
        struct message_header {
            std::uint32_t message_length = 0;
            MessageType message_type = MessageType::TEXT;
        };

        enum : uint32_t {
            HEADER_LENGTH = sizeof(message_header),
            MAX_BODY_LENGTH = 1024,
        };

        Message();

        explicit Message(const std::string& message, MessageType type = MessageType::TEXT);

        explicit Message(const nlohmann::json& json, MessageType type = MessageType::TEXT);

        void encrypt();

        void decrypt();

        [[nodiscard]]
        nlohmann::json to_json() const;

        [[nodiscard]]
        const char* data() const;

        char* data();

        [[nodiscard]]
        message_header header() const;

        [[nodiscard]]
        MessageType type() const;

        [[nodiscard]]
        std::size_t length() const;

        [[nodiscard]]
        std::size_t size() const;

        [[nodiscard]]
        const char* body() const;

        char* body();

        [[nodiscard]]
        std::size_t body_length() const;

        void set_body_length(std::size_t length);

        bool decode_header();

        void encode_header();

        [[nodiscard]]
        bool empty() const;

        friend std::ostream& operator<<(std::ostream& os, const Message& message);

    private:
        char data_[HEADER_LENGTH + MAX_BODY_LENGTH];
        std::string body_;
        std::size_t body_length_;
        message_header header_;
    };


} // cp2p


#endif //MESSAGE_HPP
