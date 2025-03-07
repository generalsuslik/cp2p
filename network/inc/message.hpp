//
// Created by generalsuslik on 24.02.25.
//

#ifndef MESSAGE_HPP
#define MESSAGE_HPP

#include <cstdint>
#include <cstring>
#include <memory>

namespace cp2p {

    class Message {
    public:
        enum : uint32_t {
            header_length = 4,
            max_body_length = 512,
        };

        Message();

        const char* data() const;

        char* data();

        std::size_t length() const;

        std::size_t size() const;

        const char* body() const;

        char* body();

        std::size_t body_length() const;

        void set_body_length(std::size_t length);

        bool decode_header();

        void encode_header();

    private:
        char data_[header_length + max_body_length];
        std::size_t body_length_;
    };


} // cp2p



#endif //MESSAGE_HPP
