#include <stdlib.h>

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
