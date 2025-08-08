//
// Created by generalsuslik on 01.02.25.
//

#ifndef UTIL_HPP
#define UTIL_HPP

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

namespace cp2p {

    constexpr std::uint8_t DELIMITER = '\t';

    template <std::input_iterator Iter>
    std::string to_hex(Iter begin, Iter end) {
        std::ostringstream oss;
        for (auto it = begin; it != end; ++it) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(*it);
        }

        return oss.str();
    }

    template <std::random_access_iterator Iter>
    std::vector<unsigned char> from_hex(Iter begin, Iter end) {
        const std::size_t len = std::distance(begin, end);
        if (len % 2 == 1) {
            throw std::runtime_error("Invalid hex string length");
        }

        std::vector<unsigned char> bytes;
        bytes.reserve(len / 2);

        for (const auto it = begin; it != end; it += 2) {
            unsigned char byte;
            std::istringstream iss(std::string(it, it + 2));
            if (!(iss >> std::hex >> byte)) {
                throw std::runtime_error("Invalid hex character");
            }

            bytes.push_back(byte);
        }

        return bytes;
    }

    template <typename Container>
    concept CMessageContainer = requires(Container container) {
        typename Container::value_type;
        requires sizeof(typename Container::value_type) == 1;

        typename Container::iterator;
        requires (
            std::random_access_iterator<typename Container::iterator>
            || std::contiguous_iterator<typename Container::iterator>
        );

        typename Container::value_type;
        requires (
            std::convertible_to<typename Container::value_type, std::uint8_t>
            || std::convertible_to<typename Container::value_type, char>
        );

        { container.size() } -> std::convertible_to<size_t>;
    };

    template <CMessageContainer Container>
    std::vector<std::uint8_t> make_message_data(
        const Container& encrypted_message,
        const Container& encrypted_aes,
        const Container& encrypted_iv
    ) {
        std::vector<std::uint8_t> message;
        message.reserve(encrypted_message.size() + 1 + encrypted_aes.size() + 1 + encrypted_iv.size());

        for (const auto& byte : encrypted_message) {
            message.push_back(byte);
        }
        message.push_back(DELIMITER);
        for (const auto& byte : encrypted_aes) {
            message.push_back(byte);
        }
        message.push_back(DELIMITER);
        for (const auto& byte : encrypted_iv) {
            message.push_back(byte);
        }

        return message;
    }

    template <CMessageContainer MessageContainer>
    std::string get_string_from_container(const MessageContainer& container) {
        std::string s(reinterpret_cast<const char*>(container.data()), container.size());
        return s;
    }

    template <CMessageContainer MessageContainer = std::vector<std::uint8_t>>
    MessageContainer get_container_from_string(const std::string& s) {
        MessageContainer container(s.begin(), s.end());
        return container;
    }

} // namespace cp2p

#endif //UTIL_HPP