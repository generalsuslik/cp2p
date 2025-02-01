//
// Created by generalsuslik on 01.02.25.
//

#include "../inc/util.hpp"

#include <iomanip>
#include <iostream>

std::string to_hex(const std::vector<unsigned char>& data) {
    std::ostringstream oss;
    for (const auto byte : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

std::vector<unsigned char> from_hex(const std::string& data) {
    if (data.length() % 2 != 0) {
        throw std::runtime_error("Invalid hex string length");
    }

    std::vector<unsigned char> bytes;
    bytes.reserve(data.length() / 2);
    for (size_t i = 0; i < data.length(); i += 2) {
        unsigned byte;
        std::istringstream iss(data.substr(i, 2));
        if (!(iss >> std::hex >> byte)) {
            throw std::runtime_error("Invalid hex character");
        }
        bytes.push_back(byte);
    }

    return bytes;
}

