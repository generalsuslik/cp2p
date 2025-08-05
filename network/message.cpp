//
// Created by generalsuslik on 03.03.25.
//

#include "message.hpp"

#include "crypto/aes.hpp"

#include <iomanip>
#include <iostream>

namespace cp2p {


    Message::Message()
            : body_length_(0) {}

    Message::Message(const std::string& message, const MessageType type)
            : data_(HEADER_LENGTH + message.length())
            , body_(message.begin(), message.end())
            , body_length_(message.length())
            , header_(message.length(), type) {
        std::memcpy(data_.data() + HEADER_LENGTH, body_.data(), body_length_);
        encode_header();
    }

    // template <MessageContainer Container>
    Message::Message(const std::vector<std::uint8_t>& message_data, MessageType type)
        : Message(message_data.begin(), message_data.end(), type)
    {
    }

    template <std::contiguous_iterator It>
    Message::Message(It begin, It end, const MessageType type)
        : data_(std::distance(begin, end))
        , body_(begin, end)
        , body_length_(std::distance(begin, end))
        , header_(std::distance(begin, end), type)
    {   
        std::memcpy(data_.data() + HEADER_LENGTH, body_.data(), body_length_);
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

    const Message::data_type* Message::data() const {
        return data_.data();
    }

    Message::data_type* Message::data() {
        return data_.data();
    }

    const std::vector<Message::data_type>& Message::data_vector() const {
        return data_;
    }

    std::vector<Message::data_type>& Message::data_vector() {
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

    const std::vector<std::uint8_t>& Message::body() const {
        return body_;
    }

    Message::data_type* Message::body_data() {
        return data_.data() + HEADER_LENGTH;
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
        std::basic_istringstream<data_type> iss(data_.data());

        std::basic_string<data_type> message_length_str(sizeof(header_.message_length), '0');
        iss.read(&message_length_str[0], sizeof(header_.message_length));
        header_.message_length = std::stoull(reinterpret_cast<char*>(message_length_str.data()));

        std::basic_string<data_type> message_type_str(sizeof(std::underlying_type_t<MessageType>), '0');
        iss.read(&message_type_str[0], sizeof(std::underlying_type_t<MessageType>));
        header_.message_type = static_cast<MessageType>(std::stoul(reinterpret_cast<char*>(message_type_str.data())));

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

        std::memcpy(data_.data(), oss.str().c_str(), HEADER_LENGTH);
    }

    bool Message::empty() const {
        return header_.message_length == 0;
    }

    std::ostream& operator<<(std::ostream& os, const Message& message) {
        for (const auto& byte : message.data_) {
            os << byte;
        }

        return os;
    }


} // namespace cp2p
