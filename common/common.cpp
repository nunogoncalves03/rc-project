#include "common.hpp"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <cctype>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

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

bool is_alphanumerical(const std::string& str,
                       const std::string& special_chars) {
    for (const char c : str) {
        if (!std::isalnum(c) && special_chars.find(c) == std::string::npos)
            return false;
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

bool read_tokens(std::istringstream& stream, std::vector<std::string>& tokens,
                 int n_tokens, bool end_expected) {
    if (stream.peek() == ' ' || stream.peek() == '\n') {
        return false;
    }

    std::string token;
    for (int i = 0; i < n_tokens; i++) {
        if (!(stream >> token)) {
            return false;
        }
        tokens.push_back(token);

        if (i == n_tokens - 1) {
            break;
        }

        if (stream.get() != ' ' || stream.peek() == ' ' ||
            stream.peek() == '\n') {
            return false;
        }
    }

    if (end_expected) {
        if (stream.get() != '\n' || stream.peek() != EOF) {
            return false;
        }
    } else {
        if (stream.get() != ' ' || stream.peek() == ' ' ||
            stream.peek() == '\n' || stream.peek() == EOF) {
            return false;
        }
    }

    return true;
}

ssize_t read_tokens_from_tcp_socket(int fd, std::vector<std::string>& tokens,
                                    int n_tokens, size_t max_token_size,
                                    bool read_token, char rest[128]) {
    char buffer[128];
    ssize_t n;
    ssize_t nleft = 128;
    std::string token;
    while (n_tokens > 0 && nleft > 0) {
        n = _read(fd, buffer, (size_t)nleft);
        if (n == -1 || n == 0) {
            if (n == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
                std::cout << "TCP timeout occurred while receiving command"
                          << std::endl;
            } else {
                std::cerr << "Error receiving data: " << strerror(errno)
                          << std::endl;
            }
            return -1;
        }

        size_t i = 0;
        char c;
        while (true) {
            if (read_token) {
                size_t j = i;
                while (j < (size_t)n &&
                       j - i + 1 + token.length() <= max_token_size &&
                       buffer[j] != ' ' && buffer[j] != '\n') {
                    j++;
                }

                if (j == (size_t)n) {
                    token += std::string(buffer + i, j - i);
                    break;
                }

                c = buffer[j];
                if (j - i + 1 + token.length() > max_token_size && c != ' ' &&
                    c != '\n') {
                    return -1;
                }

                if (c == ' ' || c == '\n') {
                    read_token = false;
                    if (i == j) {
                        if (token.length() == 0) {
                            return -1;
                        } else {
                            // jump
                            continue;
                        }

                    } else {
                        token += std::string(buffer + i, j - i);
                        i = j;
                    }
                }
            } else {
                c = buffer[i];
                if (c != ' ' && c != '\n') {
                    return -1;
                }

                if (token.length() != 0) {
                    tokens.push_back(token);
                    token = "";
                    n_tokens--;
                }

                if (c == '\n' && n_tokens > 0) {
                    return -1;
                }

                // espaço ou \n com n_tokens = 0
                if (n_tokens == 0) {
                    memcpy(rest, buffer + i, (size_t)n - i);
                    return n - (ssize_t)i;
                }

                // espaço e tokens > 0
                read_token = true;
                i++;
            }
        }

        nleft -= n;
        memset(buffer, 0, sizeof(buffer));
    }

    return -1;
}

ssize_t _write(int fd, const void* buf, size_t count) {
    ssize_t bytes_written;
    do {
        bytes_written = write(fd, buf, count);
    } while (bytes_written < 0 && errno == EINTR);
    return bytes_written;
}

ssize_t write_to_tcp_socket(int fd, const char* buf, size_t count) {
    ssize_t n;
    size_t nleft = count;
    while (nleft > 0) {
        n = _write(fd, buf + (count - nleft), nleft);
        if (n == -1) {
            return -1;
        }

        nleft -= (size_t)n;
    }

    return (ssize_t)(count - nleft);
}
