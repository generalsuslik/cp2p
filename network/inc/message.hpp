//
// Created by generalsuslik on 24.02.25.
//

#ifndef MESSAGE_HPP
#define MESSAGE_HPP

#include <cstdint>
#include <cstring>
#include <memory>

namespace cp2p {

    enum class MessageType : uint32_t {
        HANDSHAKE,
        TEXT,
        FILE, // yet not supported
    };

    class Message {
    public:
        struct message_header {
            std::size_t message_length = 0;
            MessageType message_type = MessageType::TEXT;
        };

        enum : uint32_t {
            HEADER_LENGTH = sizeof(message_header),
            MAX_BODY_LENGTH = 512,
        };

        Message();

        explicit Message(const std::string& message, MessageType type = MessageType::TEXT);

        [[nodiscard]]
        const char* data() const;

        char* data();

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
