#include "server.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <csignal>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>

#include "common.hpp"
#include "database.hpp"

std::atomic<bool> verbose(false);
std::atomic<bool> shutdown_flag(false);
std::string as_port = "58058";

void signalHandler(int signal) {
    if (signal == SIGINT) {
        std::cout << std::endl
                  << "Ctrl+C received. Shutting down server..." << std::endl;
        shutdown_flag.store(true);
    }
}

int main(int argc, char **argv) {
    std::signal(SIGINT, signalHandler);

    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "-v") {
            verbose.store(true);
        } else if (std::string(argv[i]) == "-p" && argc > i + 1) {
            as_port = std::string(argv[i + 1]);
            i++;  // Skip the next argument
        } else {
            // Handle unknown or incorrectly formatted arguments
            std::cout << "Usage: " << argv[0] << " [-p ASport] [-v]"
                      << std::endl;
            exit(1);
        }
    }

    if (!is_number(as_port) || std::stoi(as_port) < 0 ||
        std::stoi(as_port) > 65535) {
        std::cout << "port has to be a number between 0 and 65535" << std::endl;
        exit(0);
    }

    db_init();

    std::thread udp_worker(udp_handler);
    udp_worker.join();

    return 0;
}

void udp_handler() {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        exit(1);
    }

    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    // Set socket timeout for both reads and writes
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) < 0) {
        std::cout << "ERROR: couldn't set UDP socket timeout" << std::endl;
        exit(1);
    }

    ssize_t n;
    socklen_t addrlen;
    struct addrinfo hints, *dns_res;
    struct sockaddr_in addr;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    // passing NULL means that we are the host
    int errcode = getaddrinfo(NULL, as_port.c_str(), &hints, &dns_res);
    if (errcode != 0) {
        exit(1);
    }

    n = bind(fd, dns_res->ai_addr, dns_res->ai_addrlen);
    if (n == -1) {
        exit(1);
    }

    // loop waiting for udp requests until the shutdown flag is activated
    while (!shutdown_flag.load()) {
        char buffer[MAX_REQ_SIZE + 1];
        addrlen = sizeof(addr);

        n = recvfrom(fd, buffer, MAX_REQ_SIZE + 1, 0, (struct sockaddr *)&addr,
                     &addrlen);
        if (n == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                std::cout << "UDP timeout occurred while receiving data"
                          << std::endl;
                continue;
            } else {
                std::cerr << "Error receiving data: " << strerror(errno)
                          << std::endl;
                exit(1);
            }
        }

        char ip_str[addrlen + 1];
        // Convert binary IP address to string
        if (inet_ntop(AF_INET, &(addr.sin_addr), ip_str, addrlen) == NULL) {
            exit(1);
        }

        // Convert port number to host byte order
        int port = ntohs(addr.sin_port);

        std::string req = std::string(buffer, (size_t)n);

        if (verbose.load()) {
            std::cout << "[" << ip_str << ":" << port << "] received: " << req
                      << std::endl;
        }

        if (n > MAX_REQ_SIZE || n < MIN_REQ_SIZE) {
            n = sendto(fd, ERROR_MSG, sizeof(ERROR_MSG) - 1, 0,
                       (struct sockaddr *)&addr, addrlen);
            if (n == -1) {
                exit(1);
            }
            continue;
        }

        std::string cmd, res;
        std::istringstream req_stream(req);
        req_stream >> cmd;

        if (cmd == "LIN") {
            std::string uid, password;
            req_stream >> uid >> password;

            if (req_stream.get() != '\n' || !is_number(uid) ||
                uid.length() != UID_SIZE || !is_alphanumerical(password) ||
                password.length() != PASSWORD_SIZE) {
                n = sendto(fd, ERROR_MSG, sizeof(ERROR_MSG) - 1, 0,
                           (struct sockaddr *)&addr, addrlen);
                if (n == -1) {
                    exit(1);
                }
                continue;
            }

            int status_code = user_create(uid, password);
            if (status_code == SUCCESS_CODE) {
                res = "RLI REG\n";
                if (user_login(uid, password) != SUCCESS_CODE) {
                    res = "RLI NOK\n";  // FIXME
                }
            } else if (status_code == ERR_USER_ALREADY_EXISTS) {
                status_code = user_login(uid, password);
                if (status_code == SUCCESS_CODE ||
                    status_code == ERR_USER_ALREADY_LOGGED_IN) {
                    res = "RLI OK\n";
                } else if (status_code == ERR_USER_INVALID_PASSWORD) {
                    res = "RLI NOK\n";
                } else {
                    res = "RLI NOK\n";  // FIXME
                }
            } else {
                res = "RLI NOK\n";  // FIXME
            }
            // } else if (cmd == "LOU") {
            // } else if (cmd == "UNR") {
            // } else if (cmd == "LMA") {
            // } else if (cmd == "LMB") {
            // } else if (cmd == "LST") {
            // } else if (cmd == "SRC") {
        } else {
            res = ERROR_MSG;
        }

        n = sendto(fd, res.c_str(), res.length(), 0, (struct sockaddr *)&addr,
                   addrlen);
        if (n == -1) {
            exit(1);
        }
    }

    std::cout << "Shutting down UDP worker thread..." << std::endl;
    freeaddrinfo(dns_res);
    close(fd);
}