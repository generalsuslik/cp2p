// //
// // Created by generalsuslik on 03.03.25.
// //
//
// #include "../inc/message.hpp"
//
// #include <iomanip>
// #include <iostream>
// #include <sstream>
// #include <utility>
//
// namespace cp2p {
//
//
//     Message::Message() = default;
//
//     Message::Message(const std::vector<unsigned char>& data)
//             : data_(data.begin(), data.end())
//             , header_() {
//         deserialize();
//     }
//
//     Message::Message(std::string message, const MessageType type)
//             : message_(std::move(message))
//             , header_(message_.length(), type) {
//         serialize();
//     }
//
//     void Message::serialize() {
//         std::ostringstream oss;
//
//         oss << std::setw(sizeof(header_.message_length)) << std::setfill('0') << header_.message_length;
//         oss << std::setw(sizeof(std::underlying_type_t<MessageType>))
//                 << std::setfill('0') << static_cast<std::underlying_type_t<MessageType>>(type());
//
//         oss << message_;
//
//         data_ = oss.str();
//     }
//
//     void Message::deserialize() {
//         std::istringstream iss(data_);
//
//         std::string message_length_str(sizeof(header_.message_length), '0');
//         iss.read(&message_length_str[0], sizeof(header_.message_length));
//         header_.message_length = std::stoull(message_length_str);
//
//         std::string message_type_str(sizeof(std::underlying_type_t<MessageType>), '0');
//         iss.read(&message_type_str[0], sizeof(std::underlying_type_t<MessageType>));
//         header_.message_type = static_cast<MessageType>(std::stoul(message_type_str));
//
//         std::getline(iss, message_);
//     }
//
//     MessageType Message::type() const {
//         return header_.message_type;
//     }
//
//     const Message::message_header& Message::header() const {
//         return header_;
//     }
//
//     const char* Message::data() const {
//         return data_.data();
//     }
//
//     char* Message::data() {
//         return data_.data();
//     }
//
//     const std::string& Message::body() const {
//         return message_;
//     }
//
//     std::string& Message::body() {
//         return message_;
//     }
//
//     std::size_t Message::length() const {
//         return message_.length();
//     }
//
//     std::size_t Message::size() const {
//         return data_.size();
//     }
//
//     bool Message::empty() const {
//         return message_.empty();
//     }
//
//     std::ostream& operator<<(std::ostream& os, const Message& message) {
//         os << message.data();
//
//         return os;
//     }
//
//
// } // namespace cp2p


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
