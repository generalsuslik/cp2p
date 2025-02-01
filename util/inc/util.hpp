//
// Created by generalsuslik on 01.02.25.
//

#ifndef UTIL_HPP
#define UTIL_HPP

#include <string>
#include <vector>

std::string to_hex(const std::vector<unsigned char>& data);

std::vector<unsigned char> from_hex(const std::string& data);

#endif //UTIL_HPP
