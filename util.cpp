#include <stdlib.h>

#include <cctype>
#include <iostream>
#include <sstream>
#include <string>

bool is_number(const std::string& str) {
    try {
        size_t pos;
        std::stoi(str, &pos);
        return pos == str.length();
    } catch (const std::exception& e) {
        return false;
    }
}

bool is_alphanumerical(const std::string& str) {
    for (const char c : str) {
        if (!std::isalnum(c)) return false;
    }
    return true;
}

bool is_valid_filename(const std::string& str) {
    size_t idx = str.find('.');
    if (idx == std::string::npos || str.substr(0, idx).length() <= 0 ||
        str.substr(0, idx).length() > 20 || str.substr(idx + 1).length() != 3) {
        return false;
    }
    return true;
}