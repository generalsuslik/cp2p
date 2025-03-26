//
// Created by generalsuslik on 11.03.25.
//

#include "test_util.hpp"

#include <algorithm>

std::string random_string(const std::size_t len) {
    const std::string alphanum =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, static_cast<int>(alphanum.size()) - 1);

    std::string res;
    res.reserve(len);

    for (size_t i = 0; i < len; ++i) {
        res += alphanum[distrib(gen)];
    }

    return res;
}
