//
// Created by generalsuslik on 03.03.25.
//

#include "../inc/message.hpp"

#include "../../crypto/inc/aes.hpp"

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
        // std::tie(header_.aes_key, header_.aes_iv) = aes::generate_aes_key_iv();

        std::strcpy(data_ + HEADER_LENGTH, message.c_str());
        encode_header();
    }

    Message::Message(const nlohmann::json& json, const MessageType type)
        : Message(json.dump(), type) {}

    void Message::encrypt() {

    }

    void Message::decrypt() {

    }

    nlohmann::json Message::to_json() const {
        try {
            return nlohmann::json::parse(body_);
        } catch (const nlohmann::json::exception&) {
            return nlohmann::json::object();
        }
    }

    const char* Message::data() const {
        return data_;
    }

    char* Message::data() {
        return data_;
    }

    Message::message_header Message::header() const {
        return header_;
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

        // std::vector<unsigned char> aes_key(aes::key_length);
        // iss.read(reinterpret_cast<char*>(aes_key.data()), aes_key.size());
        //
        // std::vector<unsigned char> aes_iv(aes::iv_length);
        // iss.read(reinterpret_cast<char*>(aes_iv.data()), aes_iv.size());
        //
        // header_.aes_key = std::move(aes_key);
        // header_.aes_iv = std::move(aes_iv);

        body_length_ = header_.message_length;
        if (body_length_ > MAX_BODY_LENGTH) {
            body_length_ = 0;
            header_.message_length = 0;
            return false;
        }

        return true;
    }

    std::ostream& operator<<(std::ostream& os, const std::vector<unsigned char>& rhs) {
        for (const auto val : rhs) {
            os << val;
        }

        return os;
    }

    void Message::encode_header() {
        std::ostringstream oss;

        oss << std::setw(sizeof(header_.message_length)) << std::setfill('0') << header_.message_length;
        oss << std::setw(sizeof(std::underlying_type_t<MessageType>))
                << std::setfill('0') << static_cast<std::underlying_type_t<MessageType>>(header_.message_type);
        // oss << std::setw(aes::key_length) << std::setfill('0') << header_.aes_key;
        // oss << std::setw(aes::iv_length) << std::setfill('0') << header_.aes_iv;

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
