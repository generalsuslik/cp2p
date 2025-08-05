//
// Created by generalsuslik on 24.02.25.
//

#ifndef MESSAGE_HPP
#define MESSAGE_HPP

#include <nlohmann/json.hpp>

#include <cstdint>

namespace cp2p {

    enum class MessageType : uint32_t {
        ACCEPT,
        DISCONNECT,
        FILE, // yet not supported
        HANDSHAKE,
        SEARCH,
        SEARCH_RESPONSE,
        TEXT,
    };

    /**
     * @class Message
     * @brief The Message class is a representation of a communication or notification.
     */
    class Message {
    public:
        using data_type = std::uint8_t;

    public:
        struct message_header {
            std::uint32_t message_length = 0;
            MessageType message_type = MessageType::TEXT;
            std::chrono::system_clock::time_point timestamp = std::chrono::system_clock::now();
        };

        enum : uint32_t {
            HEADER_LENGTH = sizeof(message_header),
            MAX_BODY_LENGTH = 1024,
        };

    public:
        Message();

        explicit Message(const std::string& message, MessageType type = MessageType::TEXT);

        // template <MessageContainer Container>
        explicit Message(const std::vector<std::uint8_t>& message_data, MessageType type = MessageType::TEXT);

        template<std::contiguous_iterator It>
        Message(
            It begin,
            It end,
            MessageType type = MessageType::TEXT
        );

        explicit Message(const nlohmann::json& json, MessageType type = MessageType::TEXT);

        void encrypt();

        void decrypt();

        [[nodiscard]]
        nlohmann::json to_json() const;

        [[nodiscard]]
        const data_type* data() const;

        data_type* data();

        [[nodiscard]]
        const std::vector<data_type>& data_vector() const;

        std::vector<data_type>& data_vector();

        [[nodiscard]]
        message_header header() const;

        [[nodiscard]]
        MessageType type() const;

        [[nodiscard]]
        std::size_t length() const;

        [[nodiscard]]
        std::size_t size() const;

        [[nodiscard]]
        const std::vector<std::uint8_t>& body() const;

        data_type* body_data();

        [[nodiscard]]
        std::size_t body_length() const;

        void set_body_length(std::size_t length);

        bool decode_header();

        void encode_header();

        [[nodiscard]]
        bool empty() const;

        friend std::ostream& operator<<(std::ostream& os, const Message& message);

    private:
        std::vector<data_type> data_;
        const std::vector<data_type> body_;
        std::size_t body_length_;
        message_header header_;
    };


} // cp2p


#endif //MESSAGE_HPP
