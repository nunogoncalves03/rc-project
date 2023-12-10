#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <cctype>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

std::string zero_pad_number(int number, int width) {
    std::ostringstream oss;
    oss << std::setw(width) << std::setfill('0') << number;

    return oss.str();
}

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

std::string get_date(time_t& n_sec) {
    struct tm* current_time = gmtime(&n_sec);
    std::string date = std::to_string(current_time->tm_year + 1900) + "-" +
                       zero_pad_number(current_time->tm_mon + 1, 2) + "-" +
                       zero_pad_number(current_time->tm_mday, 2) + " " +
                       zero_pad_number(current_time->tm_hour, 2) + ":" +
                       zero_pad_number(current_time->tm_min, 2) + ":" +
                       zero_pad_number(current_time->tm_sec, 2);

    return date;
}

ssize_t _read(int fd, void* buf, size_t count) {
    ssize_t bytes_read;
    do {
        bytes_read = read(fd, buf, count);
    } while (bytes_read < 0 && errno == EINTR);
    return bytes_read;
}

ssize_t read_from_tcp_socket(int fd, char* buf, size_t count) {
    ssize_t n;
    size_t nleft = count;
    while (nleft > 0) {
        n = _read(fd, buf + (count - nleft), nleft);
        if (n == 0) {
            return (ssize_t)(count - nleft);
        }
        if (n == -1) {
            return -1;
        }

        nleft -= (size_t)n;
    }

    return (ssize_t)(count - nleft);
}

ssize_t _write(int fd, const void* buf, size_t count) {
    ssize_t bytes_written;
    do {
        bytes_written = write(fd, buf, count);
    } while (bytes_written < 0 && errno == EINTR);
    return bytes_written;
}