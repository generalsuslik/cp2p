//
// Created by generalsuslik on 11.03.25.
//

#include "test_util.hpp"

#include <algorithm>

std::string random_string(const std::size_t len) {
    constexpr char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    std::string res;
    res.resize(len);

    std::default_random_engine generator(std::random_device{}());
    std::uniform_int_distribution<> distribution(0, sizeof(alphanum) - 1);

    std::generate_n(res.begin(), len, [&alphanum, &distribution, &generator]{
        return alphanum[distribution(generator)];
    });

    return res;
}
