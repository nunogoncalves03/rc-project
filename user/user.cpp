#include "user.hpp"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#include "common.hpp"

struct addrinfo hints, *dns_res;
int udp_fd;

// User credentials
std::string uid, password;
bool logged_in = false;

int main(int argc, char** argv) {
    // signal to handle CTRL+C (SIGINT) and gracefully shutdown
    if (signal(SIGINT, graceful_shutdown) == SIG_ERR) {
        std::cout << "coudln't register SIGINT handler" << std::endl;
        exit(1);
    }
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        std::cout << "coudln't register SIGPIPE handler" << std::endl;
        exit(1);
    }

    std::string as_ip = "localhost";
    std::string as_port = "58058";

    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "-n" && argc > i + 1) {
            as_ip = std::string(argv[i + 1]);
            i++;  // Skip the next argument
        } else if (std::string(argv[i]) == "-p" && argc > i + 1) {
            as_port = std::string(argv[i + 1]);
            i++;  // Skip the next argument
        } else {
            // Handle unknown or incorrectly formatted arguments
            std::cout << "Usage: " << argv[0] << " [-n ASIP] [-p ASport]"
                      << std::endl;
            exit(1);
        }
    }

    if (!is_number(as_port) || std::stoi(as_port) < 0 ||
        std::stoi(as_port) > 65535) {
        std::cout << "port has to be a number between 0 and 65535" << std::endl;
        exit(0);
    }

    // Global UDP socket
    udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd == -1) {
        std::cout << "ERROR: couldn't open UDP socket" << std::endl;
        exit(1);
    }

    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    // Set socket timeout for both reads and writes
    if (setsockopt(udp_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) <
            0 ||
        setsockopt(udp_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) <
            0) {
        std::cout << "ERROR: couldn't set UDP socket timeout" << std::endl;
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;  // IPv4
    hints.ai_socktype = 0;      // Socket of any type

    // DNS lookup
    int errcode = getaddrinfo(as_ip.c_str(), as_port.c_str(), &hints, &dns_res);
    if (errcode != 0) {
        std::cout << "DNS lookup failed, couldn't get host info" << std::endl;
        exit(1);
    }

    // Loop reading commands from user
    while (true) {
        std::cout << "> ";
        std::string cmd, msg;
        std::cin >> cmd;

        if (cmd == "login") {
            std::string temp_uid, temp_password;
            const bool left_over_chars =
                read_from_terminal(temp_uid, temp_password);

            if (logged_in) {
                std::cout << "already logged in; to login as a different user, "
                             "please logout first"
                          << std::endl;
                continue;
            }

            if (left_over_chars || temp_uid == "" || temp_password == "") {
                std::cout << "invalid arguments" << std::endl;
                continue;
            }

            if (!is_number(temp_uid) || temp_uid.length() != UID_SIZE) {
                std::cout << "uid has to be a number with " << UID_SIZE
                          << " digits" << std::endl;
                continue;
            }

            if (!is_alphanumerical(temp_password) ||
                temp_password.length() != PASSWORD_SIZE) {
                std::cout << "password needs to have " << PASSWORD_SIZE
                          << " alphanumerical characters" << std::endl;
                continue;
            }

            msg = "LIN " + temp_uid + " " + temp_password + "\n";

            std::optional<std::string> res =
                udp_request(udp_fd, msg, LOGIN_RES_SIZE);
            if (!res.has_value()) {
                continue;
            }
            handle_login_response(res.value(), temp_uid, temp_password);
        } else if (cmd == "logout") {
            const bool left_over_chars = read_from_terminal();

            if (uid == "") {
                std::cout << "you need to perform a successful login first"
                          << std::endl;
                continue;
            }

            if (left_over_chars) {
                std::cout << "invalid arguments" << std::endl;
                continue;
            }

            msg = "LOU " + uid + " " + password + "\n";

            std::optional<std::string> res =
                udp_request(udp_fd, msg, LOGOUT_RES_SIZE);
            if (!res.has_value()) {
                continue;
            }
            handle_logout_response(res.value());
        } else if (cmd == "unregister") {
            const bool left_over_chars = read_from_terminal();

            if (uid == "") {
                std::cout << "you need to perform a successful login first"
                          << std::endl;
                continue;
            }

            if (left_over_chars) {
                std::cout << "invalid arguments" << std::endl;
                continue;
            }

            msg = "UNR " + uid + " " + password + "\n";

            std::optional<std::string> res =
                udp_request(udp_fd, msg, UNREGISTER_RES_SIZE);
            if (!res.has_value()) {
                continue;
            }
            handle_unregister_response(res.value());
        } else if (cmd == "exit") {
            const bool left_over_chars = read_from_terminal();

            if (logged_in) {
                std::cout << "there's an active login, please logout first"
                          << std::endl;
                continue;
            }

            if (left_over_chars) {
                std::cout << "invalid arguments" << std::endl;
                continue;
            }

            graceful_shutdown(0);
        } else if (cmd == "open") {
            std::string name, asset_fname, start_value, time_active;
            const bool left_over_chars =
                read_from_terminal(name, asset_fname, start_value, time_active);

            if (uid == "") {
                std::cout << "you need to perform a successful login first"
                          << std::endl;
                continue;
            }

            if (left_over_chars || name == "" || asset_fname == "" ||
                start_value == "" || time_active == "") {
                std::cout << "invalid arguments" << std::endl;
                continue;
            }

            if (!is_alphanumerical(name, "-_") ||
                name.length() > AUCTION_NAME_SIZE) {
                std::cout << "name can only contain up to " << AUCTION_NAME_SIZE
                          << " alphanumerical characters" << std::endl;
                continue;
            }

            std::filesystem::path asset_path(asset_fname);
            std::string asset_base_name = asset_path.filename().string();
            if (!is_valid_filename(asset_base_name)) {
                std::cout << "invalid filename" << std::endl;
                continue;
            }

            if (!is_number(start_value) || start_value.length() > VALUE_SIZE) {
                std::cout << "start_value has to be a number with "
                          << VALUE_SIZE << " digits maximum" << std::endl;
                continue;
            }

            if (!is_number(time_active) ||
                time_active.length() > DURATION_SIZE) {
                std::cout << "time_active has to be a number with "
                          << DURATION_SIZE << " digits maximum" << std::endl;
                continue;
            }

            struct stat stat_buffer;
            if (stat(asset_fname.c_str(), &stat_buffer) == -1) {
                if (errno == ENOENT) {
                    // pathname does not exist
                    std::cout << "file " << asset_fname << " doesn't exist"
                              << std::endl;
                    continue;
                }
                std::cout << "ERROR: syscall stat failed on file "
                          << asset_fname << std::endl;
                graceful_shutdown(1);
            }
            ssize_t fsize = (ssize_t)stat_buffer.st_size;
            if (fsize > MAX_ASSET_FILE_SIZE_MB * MB_N_BYTES) {
                std::cout << "file too big, limit is " << MAX_ASSET_FILE_SIZE_MB
                          << " MB" << std::endl;
                continue;
            }

            msg = "OPA " + uid + " " + password + " " + name + " " +
                  start_value + " " + time_active + " " + asset_base_name +
                  " " + std::to_string(fsize) + " ";

            handle_open_request(msg, asset_fname, fsize);
        } else if (cmd == "close") {
            std::string aid;
            const bool left_over_chars = read_from_terminal(aid);

            if (uid == "") {
                std::cout << "you need to perform a successful login first"
                          << std::endl;
                continue;
            }

            if (left_over_chars || aid == "") {
                std::cout << "invalid arguments" << std::endl;
                continue;
            }

            if (!is_number(aid) || aid.length() != AID_SIZE) {
                std::cout << "aid has to be a number with " << AID_SIZE
                          << " digits" << std::endl;
                continue;
            }

            msg = "CLS " + uid + " " + password + " " + aid + "\n";

            int fd = send_tcp_request(msg);
            if (fd == -1) {
                continue;
            }
            handle_close_response(fd);
        } else if (cmd == "myauctions" || cmd == "ma") {
            const bool left_over_chars = read_from_terminal();

            if (uid == "") {
                std::cout << "you need to perform a successful login first"
                          << std::endl;
                continue;
            }

            if (left_over_chars) {
                std::cout << "invalid arguments" << std::endl;
                continue;
            }

            msg = "LMA " + uid + "\n";

            std::optional<std::string> res =
                udp_request(udp_fd, msg, MYAUCTIONS_RES_SIZE);
            if (!res.has_value()) {
                continue;
            }
            handle_myauctions_response(res.value());
        } else if (cmd == "mybids" || cmd == "mb") {
            const bool left_over_chars = read_from_terminal();

            if (uid == "") {
                std::cout << "you need to perform a successful login first"
                          << std::endl;
                continue;
            }

            if (left_over_chars) {
                std::cout << "invalid arguments" << std::endl;
                continue;
            }

            msg = "LMB " + uid + "\n";

            std::optional<std::string> res =
                udp_request(udp_fd, msg, MYBIDS_RES_SIZE);
            if (!res.has_value()) {
                continue;
            }
            handle_mybids_response(res.value());
        } else if (cmd == "list" || cmd == "l") {
            const bool left_over_chars = read_from_terminal();

            if (left_over_chars) {
                std::cout << "invalid arguments" << std::endl;
                continue;
            }

            msg = "LST\n";

            std::optional<std::string> res =
                udp_request(udp_fd, msg, LIST_RES_SIZE);
            if (!res.has_value()) {
                continue;
            }
            handle_list_response(res.value());
        } else if (cmd == "show_asset" || cmd == "sa") {
            std::string aid;
            const bool left_over_chars = read_from_terminal(aid);

            if (left_over_chars || aid == "") {
                std::cout << "invalid arguments" << std::endl;
                continue;
            }

            if (!is_number(aid) || aid.length() != AID_SIZE) {
                std::cout << "aid has to be a number with " << AID_SIZE
                          << " digits" << std::endl;
                continue;
            }

            msg = "SAS " + aid + "\n";

            int fd = send_tcp_request(msg);
            if (fd == -1) {
                continue;
            }
            handle_show_asset_response(fd);
        } else if (cmd == "bid" || cmd == "b") {
            std::string aid, value;
            const bool left_over_chars = read_from_terminal(aid, value);

            if (uid == "") {
                std::cout << "you need to perform a successful login first"
                          << std::endl;
                continue;
            }

            if (left_over_chars || aid == "" || value == "") {
                std::cout << "invalid arguments" << std::endl;
                continue;
            }

            if (!is_number(aid) || aid.length() != AID_SIZE) {
                std::cout << "aid has to be a number with " << AID_SIZE
                          << " digits" << std::endl;
                continue;
            }

            if (!is_number(value) || value.length() > VALUE_SIZE) {
                std::cout << "value has to be a number with " << VALUE_SIZE
                          << " digits maximum" << std::endl;
                continue;
            }

            msg =
                "BID " + uid + " " + password + " " + aid + " " + value + "\n";

            int fd = send_tcp_request(msg);
            if (fd == -1) {
                continue;
            }
            handle_bid_response(fd);
        } else if (cmd == "show_record" || cmd == "sr") {
            std::string aid;
            const bool left_over_chars = read_from_terminal(aid);

            if (left_over_chars || aid == "") {
                std::cout << "invalid arguments" << std::endl;
                continue;
            }

            if (!is_number(aid) || aid.length() != AID_SIZE) {
                std::cout << "aid has to be a number with " << AID_SIZE
                          << " digits" << std::endl;
                continue;
            }

            msg = "SRC " + aid + "\n";

            std::optional<std::string> res =
                udp_request(udp_fd, msg, SHOWRECORD_RES_SIZE);
            if (!res.has_value()) {
                continue;
            }
            handle_show_record_response(res.value());
        } else {
            if (std::cin.eof()) {
                break;
            }

            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "unknown command" << std::endl;
        }
    }

    graceful_shutdown(0);

    return 0;
}

std::optional<std::string> udp_request(int socket_fd, const std::string& msg,
                                       size_t res_max_size) {
    ssize_t n = sendto(socket_fd, msg.c_str(), msg.length(), 0,
                       dns_res->ai_addr, dns_res->ai_addrlen);
    if (n == -1) {
        std::cout << "ERROR: couldn't send UDP message" << std::endl;
        return std::nullopt;
    }

    char buffer[res_max_size];
    n = recvfrom(socket_fd, buffer, res_max_size, 0, NULL, NULL);
    if (n == -1) {
        std::cout << "ERROR: couldn't receive UDP message" << std::endl;
        return std::nullopt;
    }

    std::string res = std::string(buffer, (size_t)n);

    return res;
}

int send_tcp_request(std::string& msg) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        std::cout << "ERROR: couldn't open TCP socket" << std::endl;
        return -1;
    }

    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    // Set socket timeout for both reads and writes
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) < 0) {
        std::cout << "ERROR: couldn't set TCP socket timeout" << std::endl;
        return -1;
    }

    ssize_t n = connect(fd, dns_res->ai_addr, dns_res->ai_addrlen);
    if (n == -1) {
        std::cout << "ERROR: couldn't perform TCP socket connect" << std::endl;
        return -1;
    }

    n = _write(fd, msg.c_str(), msg.length());
    if (n == -1) {
        std::cout << "ERROR: couldn't send TCP message" << std::endl;
        return -1;
    }

    return fd;
}

void handle_login_response(std::string& res, std::string& uid_,
                           std::string& password_) {
    if (res == "RLI OK\n") {
        std::cout << "successful login" << std::endl;
        logged_in = true;
        uid = uid_;
        password = password_;
    } else if (res == "RLI NOK\n") {
        std::cout << "incorrect login attempt" << std::endl;
    } else if (res == "RLI REG\n") {
        std::cout << "new user registered" << std::endl;
        logged_in = true;
        uid = uid_;
        password = password_;
    } else if (res == "RLI ERR\n") {
        std::cout << "ERR: unable to login" << std::endl;
    } else {
        std::cout << "ERROR: unexpected response from server" << std::endl;
    }
}

void handle_logout_response(std::string& res) {
    if (res == "RLO OK\n") {
        std::cout << "successful logout" << std::endl;
        logged_in = false;
    } else if (res == "RLO NOK\n") {
        std::cout << "user not logged in" << std::endl;
    } else if (res == "RLO UNR\n") {
        std::cout << "unknown user" << std::endl;
    } else if (res == "RLO ERR\n") {
        std::cout << "ERR: unable to logout" << std::endl;
    } else {
        std::cout << "ERROR: unexpected response from server" << std::endl;
    }
}

void handle_unregister_response(std::string& res) {
    if (res == "RUR OK\n") {
        std::cout << "successful unregister" << std::endl;
        logged_in = false;
    } else if (res == "RUR NOK\n") {
        std::cout << "user not logged in" << std::endl;
    } else if (res == "RUR UNR\n") {
        std::cout << "unknown user" << std::endl;
    } else if (res == "RUR ERR\n") {
        std::cout << "ERR: unable to unregister" << std::endl;
    } else {
        std::cout << "ERROR: unexpected response from server" << std::endl;
    }
}

void handle_open_request(std::string& msg, std::string& asset_path,
                         ssize_t asset_fsize) {
    int fd = send_tcp_request(msg);
    if (fd == -1) {
        return;
    }

    std::ifstream asset_file(asset_path);
    if (!asset_file.is_open()) {
        std::cout << "couldn't open file " << asset_path << std::endl;
        close(fd);
        return;
    }

    char fdata_buffer[512];
    ssize_t n;
    ssize_t nleft = asset_fsize;
    while (nleft > 0) {
        ssize_t n_to_write = nleft < 512 ? nleft : 512;
        asset_file.read(fdata_buffer, n_to_write);
        nleft -= n_to_write;

        n = _write(fd, fdata_buffer, (size_t)n_to_write);
        if (n == -1) {
            // Server parsed the "header" part of the request and already sent a
            // response, closing the socket before the whole fdata arrived
            if (errno == EPIPE || errno == ECONNRESET) {
                break;
            }
            std::cout << "ERROR: couldn't write to TCP socket" << std::endl;
            close(fd);
            return;
        }
    }

    n = _write(fd, "\n", 1);
    if (n == -1 && errno != EPIPE && errno != ECONNRESET) {
        std::cout << "ERROR: couldn't write to TCP socket" << std::endl;
        close(fd);
        return;
    }

    char res_status_buffer[CMD_SIZE + 1 + 3];
    n = read_from_tcp_socket(fd, res_status_buffer, sizeof(res_status_buffer));
    if (n == -1) {
        std::cout << "ERROR: couldn't read from TCP socket" << std::endl;
        close(fd);
        return;
    }

    const std::string res_status(res_status_buffer, (size_t)n);

    char rest[128] = {0};
    if (res_status == "ROA OK ") {
        std::vector<std::string> tokens;
        n = read_tokens_from_tcp_socket(fd, tokens, 1, AID_SIZE, true, rest);
        close(fd);

        if (n == -1) {
            std::cout << "ERROR: unexpected response from server" << std::endl;
            return;
        }

        std::string aid = tokens[0];
        if (n != 1 || rest[0] != '\n' || !is_number(aid) ||
            aid.length() != AID_SIZE) {
            std::cout << "ERROR: unexpected response from server" << std::endl;
            return;
        }

        std::cout << "auction successfully opened with ID " << aid << std::endl;
    } else {
        // read the '\n'
        n = read_from_tcp_socket(fd, rest, 2);
        close(fd);
        if (n == -1 && errno != ECONNRESET) {
            std::cout << "ERROR: couldn't read from TCP socket" << std::endl;
            return;
        }

        if ((n == 2 && strlen(rest) == 1) || strlen(rest) != 1 ||
            rest[0] != '\n') {
            std::cout << "ERROR: unexpected response from server" << std::endl;
            return;
        }

        if (res_status == "ROA NOK") {
            std::cout << "couldn't start auction" << std::endl;
        } else if (res_status == "ROA NLG") {
            std::cout << "user not logged in" << std::endl;
        } else if (res_status == "ROA ERR") {
            std::cout << "ERR: unable to open a new auction" << std::endl;
        } else {
            std::cout << "ERROR: unexpected response from server" << std::endl;
        }
    }
}

void handle_close_response(int fd) {
    char rest[128];
    std::vector<std::string> tokens;
    ssize_t n =
        read_tokens_from_tcp_socket(fd, tokens, 2, CMD_SIZE, true, rest);
    close(fd);

    if (n == -1) {
        std::cout << "ERROR: unexpected response from server" << std::endl;
        return;
    }

    std::string cmd = tokens[0];
    std::string status = tokens[1];
    if (n != 1 || rest[0] != '\n' || cmd != "RCL") {
        std::cout << "ERROR: unexpected response from server" << std::endl;
        return;
    }

    if (status == "OK") {
        std::cout << "auction successfully closed" << std::endl;
    } else if (status == "EAU") {
        std::cout << "auction doesn't exist" << std::endl;
    } else if (status == "EOW") {
        std::cout << "auctions can only be closed by the owners" << std::endl;
    } else if (status == "END") {
        std::cout << "auction is already closed" << std::endl;
    } else if (status == "NLG") {
        std::cout << "user not logged in" << std::endl;
    } else if (status == "NOK") {
        std::cout << "invalid user credentials" << std::endl;
    } else if (status == "ERR") {
        std::cout << "ERR: unable to close the auction" << std::endl;
    } else {
        std::cout << "ERROR: unexpected response from server" << std::endl;
    }
}

void handle_myauctions_response(std::string& res) {
    std::istringstream res_stream(res);
    char cmd_buffer[CMD_SIZE + 1 + 3];
    ssize_t n = res_stream.readsome(cmd_buffer, sizeof(cmd_buffer));
    std::string cmd_status(cmd_buffer, (size_t)n);

    if (cmd_status == "RMA OK ") {
        std::string output;
        char listing_buffer[AID_SIZE + 1 + STATE_SIZE];

        while (res_stream.readsome(listing_buffer, sizeof(listing_buffer)) ==
               sizeof(listing_buffer)) {
            std::istringstream stream(
                std::string(listing_buffer, sizeof(listing_buffer)));
            std::string aid, state;
            stream >> aid;
            if (stream.get() != ' ') {
                std::cout << "ERROR: unexpected response from server"
                          << std::endl;
                return;
            }
            stream >> state;
            if (!is_number(aid) || aid.length() != AID_SIZE ||
                !is_number(state) || !(state == "0" || state == "1")) {
                std::cout << "ERROR: unexpected response from server"
                          << std::endl;
                return;
            }

            output += "auction " + aid +
                      (state == "1" ? " (open)" : " (closed)") + "\n";

            char c = (char)res_stream.get();
            if (c == '\n' && res_stream.peek() == EOF) {
                output.pop_back();
                std::cout << output << std::endl;
                return;
            } else if (c == ' ' && res_stream.peek() != ' ') {
                continue;
            } else {
                break;
            }
        }

        std::cout << "ERROR: unexpected response from server" << std::endl;
    } else {
        if (res_stream.get() != '\n' || res_stream.peek() != EOF) {
            std::cout << "ERROR: unexpected response from server" << std::endl;
            return;
        }

        if (cmd_status == "RMA NOK") {
            std::cout << "you have not started an auction" << std::endl;
        } else if (cmd_status == "RMA NLG") {
            std::cout << "user not logged in" << std::endl;
        } else if (cmd_status == "RMA ERR") {
            std::cout << "ERR: unable to list your auctions" << std::endl;
        } else {
            std::cout << "ERROR: unexpected response from server" << std::endl;
        }
    }
}

void handle_mybids_response(std::string& res) {
    std::istringstream res_stream(res);
    char cmd_buffer[CMD_SIZE + 1 + 3];
    ssize_t n = res_stream.readsome(cmd_buffer, sizeof(cmd_buffer));
    std::string cmd_status(cmd_buffer, (size_t)n);

    if (cmd_status == "RMB OK ") {
        std::string output;
        char listing_buffer[AID_SIZE + 1 + STATE_SIZE];

        while (res_stream.readsome(listing_buffer, sizeof(listing_buffer)) ==
               sizeof(listing_buffer)) {
            std::istringstream stream(
                std::string(listing_buffer, sizeof(listing_buffer)));
            std::string aid, state;
            stream >> aid;
            if (stream.get() != ' ') {
                std::cout << "ERROR: unexpected response from server"
                          << std::endl;
                return;
            }
            stream >> state;
            if (!is_number(aid) || aid.length() != AID_SIZE ||
                !is_number(state) || !(state == "0" || state == "1")) {
                std::cout << "ERROR: unexpected response from server"
                          << std::endl;
                return;
            }

            output += "auction " + aid +
                      (state == "1" ? " (open)" : " (closed)") + "\n";

            char c = (char)res_stream.get();
            if (c == '\n' && res_stream.peek() == EOF) {
                output.pop_back();
                std::cout << output << std::endl;
                return;
            } else if (c == ' ' && res_stream.peek() != ' ') {
                continue;
            } else {
                break;
            }
        }

        std::cout << "ERROR: unexpected response from server" << std::endl;
    } else {
        if (res_stream.get() != '\n' || res_stream.peek() != EOF) {
            std::cout << "ERROR: unexpected response from server" << std::endl;
            return;
        }

        if (cmd_status == "RMB NOK") {
            std::cout << "you have no registered bids" << std::endl;
        } else if (cmd_status == "RMB NLG") {
            std::cout << "user not logged in" << std::endl;
        } else if (cmd_status == "RMB ERR") {
            std::cout << "ERR: unable to list your bids" << std::endl;
        } else {
            std::cout << "ERROR: unexpected response from server" << std::endl;
        }
    }
}

void handle_list_response(std::string& res) {
    std::istringstream res_stream(res);
    char cmd_buffer[CMD_SIZE + 1 + 3];
    ssize_t n = res_stream.readsome(cmd_buffer, sizeof(cmd_buffer));
    std::string cmd_status(cmd_buffer, (size_t)n);

    if (cmd_status == "RLS OK ") {
        std::string output;
        char listing_buffer[AID_SIZE + 1 + STATE_SIZE];

        while (res_stream.readsome(listing_buffer, sizeof(listing_buffer)) ==
               sizeof(listing_buffer)) {
            std::istringstream stream(
                std::string(listing_buffer, sizeof(listing_buffer)));
            std::string aid, state;
            stream >> aid;
            if (stream.get() != ' ') {
                std::cout << "ERROR: unexpected response from server"
                          << std::endl;
                return;
            }
            stream >> state;
            if (!is_number(aid) || aid.length() != AID_SIZE ||
                !is_number(state) || !(state == "0" || state == "1")) {
                std::cout << "ERROR: unexpected response from server"
                          << std::endl;
                return;
            }

            output += "auction " + aid +
                      (state == "1" ? " (open)" : " (closed)") + "\n";

            char c = (char)res_stream.get();
            if (c == '\n' && res_stream.peek() == EOF) {
                output.pop_back();
                std::cout << output << std::endl;
                return;
            } else if (c == ' ' && res_stream.peek() != ' ') {
                continue;
            } else {
                break;
            }
        }

        std::cout << "ERROR: unexpected response from server" << std::endl;
    } else {
        if (res_stream.get() != '\n' || res_stream.peek() != EOF) {
            std::cout << "ERROR: unexpected response from server" << std::endl;
            return;
        }

        if (cmd_status == "RLS NOK") {
            std::cout << "no auctions were started yet" << std::endl;
        } else if (cmd_status == "RLS ERR") {
            std::cout << "ERR: unable to list auctions" << std::endl;
        } else {
            std::cout << "ERROR: unexpected response from server" << std::endl;
        }
    }
}

void handle_show_asset_response(int fd) {
    char res_status_buffer[CMD_SIZE + 1 + 3];

    ssize_t n =
        read_from_tcp_socket(fd, res_status_buffer, sizeof(res_status_buffer));
    if (n == -1) {
        std::cout << "ERROR: couldn't read from TCP socket" << std::endl;
        close(fd);
        return;
    }

    std::string res = std::string(res_status_buffer, (size_t)n);

    char rest[128] = {0};
    if (res == "RSA OK ") {
        std::vector<std::string> tokens;
        n = read_tokens_from_tcp_socket(fd, tokens, 2, MAX_FNAME_SIZE, true,
                                        rest);
        if (n == -1) {
            std::cout << "ERROR: unexpected response from server" << std::endl;
            close(fd);
            return;
        }

        std::string fname = tokens[0];
        std::string fsize = tokens[1];

        if (!is_valid_filename(fname) || !is_number(fsize) ||
            fsize.length() > MAX_FSIZE_SIZE) {
            std::cout << "ERROR: unexpected response from server" << std::endl;
            close(fd);
            return;
        }

        if (rest[0] != ' ') {
            std::cout << "ERROR: unexpected response from server" << std::endl;
            close(fd);
            return;
        }

        char* fdata_portion = n == 1 ? rest : rest + 1;

        if (!std::filesystem::exists("./ASSETS/")) {
            if (!std::filesystem::create_directory("./ASSETS/")) {
                std::cerr << "Error creating directory: ./ASSETS/" << std::endl;
                close(fd);
                return;
            }
        }

        std::ofstream asset_file("./ASSETS/" + fname);
        if (!asset_file.is_open()) {
            std::cout << "couldn't create file " << fname << std::endl;
            close(fd);
            return;
        }

        ssize_t portion_size = n - 1;
        if (portion_size >= std::stoi(fsize)) {
            asset_file.write(fdata_portion, std::stoi(fsize));
        } else {
            asset_file.write(fdata_portion, portion_size);

            char fdata_buffer[512];
            ssize_t nleft = (ssize_t)std::stoi(fsize) - portion_size;
            while (nleft > 0) {
                n = _read(fd, fdata_buffer, 512);
                if (n == -1 || n == 0) {
                    if (n == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
                        std::cout << "TCP timeout occurred while reading asset"
                                  << std::endl;
                    } else {
                        std::cout << "ERROR: couldn't read from TCP socket"
                                  << std::endl;
                    }

                    close(fd);
                    asset_file.close();

                    if (!std::filesystem::remove("./ASSETS/" + fname)) {
                        std::cerr << "Error removing file: ./ASSETS/" << fname
                                  << std::endl;
                    }

                    return;
                }

                // in the last read, the '\n' will be included, but it isn't
                // part of the file
                ssize_t n_to_write = nleft < n ? nleft : n;
                asset_file.write(fdata_buffer, n_to_write);
                nleft -= n_to_write;
            }
        }

        close(fd);
        asset_file.close();
        std::cout << "asset saved in ./ASSETS/" << fname << std::endl;
    } else {
        // read the '\n'
        n = read_from_tcp_socket(fd, rest, 2);
        close(fd);
        if (n == -1 && errno != ECONNRESET) {
            std::cout << "ERROR: couldn't read from TCP socket" << std::endl;
            return;
        }

        if ((n == 2 && strlen(rest) == 1) || strlen(rest) != 1 ||
            rest[0] != '\n') {
            std::cout << "ERROR: unexpected response from server" << std::endl;
            return;
        }

        if (res == "RSA NOK") {
            std::cout << "auction doesn't exist, there's no file associated "
                         "with the auction or some "
                         "internal error occurred"
                      << std::endl;
        } else if (res == "RSA ERR") {
            std::cout << "ERR: unable to download the asset" << std::endl;
        } else {
            std::cout << "ERROR: unexpected response from server" << std::endl;
        }
    }
}

void handle_bid_response(int fd) {
    char rest[128];
    std::vector<std::string> tokens;
    ssize_t n =
        read_tokens_from_tcp_socket(fd, tokens, 2, CMD_SIZE, true, rest);
    close(fd);

    if (n == -1) {
        std::cout << "ERROR: unexpected response from server" << std::endl;
        return;
    }

    std::string cmd = tokens[0];
    std::string status = tokens[1];
    if (n != 1 || rest[0] != '\n' || cmd != "RBD") {
        std::cout << "ERROR: unexpected response from server" << std::endl;
        return;
    }

    if (status == "ACC") {
        std::cout << "bid registered successfully" << std::endl;
    } else if (status == "REF") {
        std::cout << "there's already been placed a higher bid" << std::endl;
    } else if (status == "NOK") {
        std::cout << "auction no longer active" << std::endl;
    } else if (status == "NLG") {
        std::cout << "user not logged in" << std::endl;
    } else if (status == "ILG") {
        std::cout << "you can't bid on your own auction" << std::endl;
    } else if (status == "ERR") {
        std::cout << "ERR: unable to bid" << std::endl;
    } else {
        std::cout << "ERROR: unexpected response from server" << std::endl;
    }
}

void handle_show_record_response(std::string& res) {
    std::istringstream res_stream(res);
    char cmd_buffer[CMD_SIZE + 1 + 3];
    ssize_t n = res_stream.readsome(cmd_buffer, sizeof(cmd_buffer));
    std::string cmd_status(cmd_buffer, (size_t)n);
    std::string output;

    if (cmd_status == "RRC OK ") {
        std::string host_uid, auction_name, asset_fname, start_value,
            start_date, start_time, time_active;
        std::vector<std::string*> tokens = {
            &host_uid,   &auction_name, &asset_fname, &start_value,
            &start_date, &start_time,   &time_active};

        int c;
        for (size_t i = 0; i < tokens.size(); i++) {
            std::string& token = *(tokens[i]);
            c = res_stream.peek();
            if (c == ' ' || c == '\n' || c == EOF) {
                std::cout << "ERROR: unexpected response from server"
                          << std::endl;
                return;
            }

            res_stream >> token;

            if (i < tokens.size() - 1 && res_stream.get() != ' ') {
                std::cout << "ERROR: unexpected response from server"
                          << std::endl;
                return;
            }
        }

        if (!is_number(host_uid) || host_uid.length() != UID_SIZE ||
            !is_alphanumerical(auction_name, "-_") ||
            auction_name.length() > AUCTION_NAME_SIZE ||
            !is_valid_filename(asset_fname) || !is_number(start_value) ||
            start_value.length() > VALUE_SIZE ||
            start_date.length() != DATE_SIZE ||
            start_time.length() != TIME_SIZE || !is_number(time_active) ||
            time_active.length() > DURATION_SIZE) {
            std::cout << "ERROR: unexpected response from server" << std::endl;
            return;
        }

        output += auction_name + " - hosted by " + host_uid + "\n";
        output += "asset filename: " + asset_fname + "\n";
        output += "start value: " + start_value + "\n";
        output += "started at: " + start_date + " " + start_time + "\n";
        output += "duration: " + time_active + " seconds" + "\n";

        c = res_stream.get();
        if (c == '\n' && res_stream.peek() == EOF) {
            output.pop_back();
            std::cout << output << std::endl;
            return;
        } else if (c != ' ') {
            std::cout << "ERROR: unexpected response from server" << std::endl;
            return;
        }

        c = res_stream.get();
        if (c != 'B' && c != 'E') {
            std::cout << "ERROR: unexpected response from server" << std::endl;
            return;
        }

        if (c == 'B') {
            output += "\nBids:\n";
        }
        while (c == 'B') {
            std::string bidder_uid, bid_value, bid_date, bid_time, bid_sec_time;
            tokens = {&bidder_uid, &bid_value, &bid_date, &bid_time,
                      &bid_sec_time};

            for (size_t i = 0; i < tokens.size(); i++) {
                std::string& token = *(tokens[i]);
                c = res_stream.get();
                if (c != ' ' || res_stream.peek() == ' ' ||
                    res_stream.peek() == '\n' || res_stream.peek() == EOF) {
                    std::cout << "ERROR: unexpected response from server"
                              << std::endl;
                    return;
                }
                res_stream >> token;
            }

            if (!is_number(bidder_uid) || bidder_uid.length() != UID_SIZE ||
                !is_number(bid_value) || bid_value.length() > VALUE_SIZE ||
                bid_date.length() != DATE_SIZE ||
                bid_time.length() != TIME_SIZE || !is_number(bid_sec_time) ||
                bid_sec_time.length() > DURATION_SIZE) {
                std::cout << "ERROR: unexpected response from server"
                          << std::endl;
                return;
            }

            output += bid_value + " - by user " + bidder_uid + " at " +
                      bid_date + " " + bid_time + " (" + bid_sec_time +
                      " seconds elapsed)\n";

            c = res_stream.get();
            if (c == ' ') {
                c = res_stream.get();
                if (c != 'B' && c != 'E') {
                    std::cout << "ERROR: unexpected response from server"
                              << std::endl;
                    return;
                }
            } else if (c == '\n' && res_stream.peek() == EOF) {
                output.pop_back();
                std::cout << output << std::endl;
                return;
            } else {
                std::cout << "ERROR: unexpected response from server"
                          << std::endl;
                return;
            }
        }

        if (c == 'E') {
            std::string end_date, end_time, end_sec_time;
            tokens = {&end_date, &end_time, &end_sec_time};

            for (size_t i = 0; i < tokens.size(); i++) {
                std::string& token = *(tokens[i]);
                c = res_stream.get();
                if (c != ' ' || res_stream.peek() == ' ' ||
                    res_stream.peek() == '\n' || res_stream.peek() == EOF) {
                    std::cout << "ERROR: unexpected response from server"
                              << std::endl;
                    return;
                }
                res_stream >> token;
            }

            if (end_date.length() != DATE_SIZE ||
                end_time.length() != TIME_SIZE || !is_number(end_sec_time) ||
                end_sec_time.length() > DURATION_SIZE) {
                std::cout << "ERROR: unexpected response from server"
                          << std::endl;
                return;
            }

            output += "\nauction ended at " + end_date + " " + end_time + " (" +
                      end_sec_time + " seconds elapsed)\n";

            if (res_stream.get() == '\n' && res_stream.peek() == EOF) {
                output.pop_back();
                std::cout << output << std::endl;
            } else {
                std::cout << "ERROR: unexpected response from server"
                          << std::endl;
            }
        }
    } else {
        if (res_stream.get() != '\n' || res_stream.peek() != EOF) {
            std::cout << "ERROR: unexpected response from server" << std::endl;
            return;
        }

        if (cmd_status == "RRC NOK") {
            std::cout << "there's no auction with the given id" << std::endl;
        } else if (cmd_status == "RRC ERR") {
            std::cout << "ERR: unable to show the record" << std::endl;
        } else {
            std::cout << "ERROR: unexpected response from server" << std::endl;
        }
    }
}

// free memory, close UDP socket and exit with the given code
void graceful_shutdown(int code) {
    freeaddrinfo(dns_res);
    close(udp_fd);

    std::cout << std::endl;
    exit(code == SIGINT ? 0 : code);
}
