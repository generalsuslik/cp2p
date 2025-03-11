//
// Created by generalsuslik on 01.02.25.
//

#ifndef UTIL_HPP
#define UTIL_HPP

#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

template <typename input_iter>
std::string to_hex(input_iter begin, input_iter end) {
    std::ostringstream oss;
    for (auto it = begin; it != end; ++it) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(*it);
    }

    return oss.str();
}

template <typename rand_access_iter>
std::vector<unsigned char> from_hex(rand_access_iter begin, rand_access_iter end) {
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

#endif //UTIL_HPP
