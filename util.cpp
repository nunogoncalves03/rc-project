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
