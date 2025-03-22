//
// Created by generalsuslik on 03.03.25.
//

#include "../inc/message.hpp"

#include <iomanip>
#include <iostream>

namespace cp2p {


    Message::Message()
        : data_()
        , body_length_(0) {}

    Message::Message(const std::string& message, const MessageType type)
            : data_()
            , body_(message)
            , body_length_(message.length())
            , header_(message.length(), type) {
        std::strcpy(data_ + HEADER_LENGTH, message.c_str());
        encode_header();
    }

    const char* Message::data() const {
        return data_;
    }

    char* Message::data() {
        return data_;
    }

    MessageType Message::type() const {
        return header_.message_type;
    }

    std::size_t Message::length() const {
        return HEADER_LENGTH + body_length_;
    }

    std::size_t Message::size() const {
        return HEADER_LENGTH + body_length_;
    }

    const char* Message::body() const {
        return data_ + HEADER_LENGTH;
    }

    char* Message::body() {
        return data_ + HEADER_LENGTH;
    }

    std::size_t Message::body_length() const {
        return body_length_;
    }

    void Message::set_body_length(const std::size_t length) {
        body_length_ = length;
        if (body_length_ > MAX_BODY_LENGTH) {
            body_length_ = MAX_BODY_LENGTH;
        }
    }

    bool Message::decode_header() {
        std::istringstream iss(data_);

        std::string message_length_str(sizeof(header_.message_length), '0');
        iss.read(&message_length_str[0], sizeof(header_.message_length));
        header_.message_length = std::stoull(message_length_str);

        std::string message_type_str(sizeof(std::underlying_type_t<MessageType>), '0');
        iss.read(&message_type_str[0], sizeof(std::underlying_type_t<MessageType>));
        header_.message_type = static_cast<MessageType>(std::stoul(message_type_str));

        body_length_ = header_.message_length;
        if (body_length_ > MAX_BODY_LENGTH) {
            body_length_ = 0;
            header_.message_length = 0;
            return false;
        }

        return true;
    }

    void Message::encode_header() {
        std::ostringstream oss;

        oss << std::setw(sizeof(header_.message_length)) << std::setfill('0') << header_.message_length;
        oss << std::setw(sizeof(std::underlying_type_t<MessageType>))
                << std::setfill('0') << static_cast<std::underlying_type_t<MessageType>>(header_.message_type);

        std::memcpy(data_, oss.str().c_str(), HEADER_LENGTH);
    }

    bool Message::empty() const {
        return header_.message_length == 0;
    }

    std::ostream& operator<<(std::ostream& os, const Message& message) {
        os << message.data();

        return os;
    }


} // namespace cp2p
