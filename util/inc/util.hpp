//
// Created by generalsuslik on 01.02.25.
//

#ifndef UTIL_HPP
#define UTIL_HPP

#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

template <typename I>
concept InputIterator = requires (I it)
{
    typename std::iterator_traits<I>::value_type;
    { *it } -> std::same_as<typename std::iterator_traits<I>::reference>;
    { ++it } -> std::same_as<I&>;
};

template <typename I>
concept RandomAccessIterator = InputIterator<I> && requires (I it, I it2, int n)
{
    { it + n } -> std::same_as<I>;
    { it - n } -> std::same_as<I>;
    { it - it2 } -> std::integral;
    { it[n] } -> std::same_as<typename std::iterator_traits<I>::reference>;
    { it < it2 } -> std::convertible_to<bool>;
    { it <= it2 } -> std::convertible_to<bool>;
    { it > it2 } -> std::convertible_to<bool>;
    { it >= it2 } -> std::convertible_to<bool>;
};

std::string to_hex(InputIterator auto begin, decltype(begin) end) {
    std::ostringstream oss;
    for (auto it = begin; it != end; ++it) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(*it);
    }

    return oss.str();
}

std::vector<unsigned char> from_hex(RandomAccessIterator auto begin, decltype(begin) end) {
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
