//
// Created by generalsuslik on 03.03.25.
//

#include "../inc/message.hpp"

namespace cp2p {


    Message::Message()
        : data_()
        , body_length_(0) {}

    const char* Message::data() const {
        return data_;
    }

    char* Message::data() {
        return data_;
    }

    std::size_t Message::length() const {
        return header_length + body_length_;
    }

    std::size_t Message::size() const {
        return header_length + body_length_;
    }

    const char* Message::body() const {
        return data_ + header_length;
    }

    char* Message::body() {
        return data_ + header_length;
    }

    std::size_t Message::body_length() const {
        return body_length_;
    }

    void Message::set_body_length(const std::size_t length) {
        body_length_ = length;
        if (body_length_ > max_body_length) {
            body_length_ = max_body_length;
        }
    }

    bool Message::decode_header() {
        char header[header_length + 1] = "";
        std::memcpy(header, data_, header_length);
        body_length_ = std::strtol(header, nullptr, 10);
        if (body_length_ > max_body_length) {
            body_length_ = 0;
            return false;
        }

        return true;
    }

    void Message::encode_header() {
        char header[header_length + 1] = "";
        std::sprintf(header, "%4d", static_cast<int>(body_length_));
        std::memcpy(data_, header, header_length);
    }


} // namespace cp2p
