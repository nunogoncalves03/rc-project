#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

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

ssize_t _read(int fd, void* buf, size_t count) {
    ssize_t bytes_read;
    do {
        bytes_read = read(fd, buf, count);
    } while (bytes_read < 0 && errno == EINTR);
    return bytes_read;
}

ssize_t _write(int fd, const void* buf, size_t count) {
    ssize_t bytes_written;
    do {
        bytes_written = write(fd, buf, count);
    } while (bytes_written < 0 && errno == EINTR);
    return bytes_written;
}