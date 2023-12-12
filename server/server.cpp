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
#include <functional>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "common.hpp"
#include "database.hpp"

std::atomic<bool> verbose(false);
std::mutex db_mutex;
std::atomic<bool> shutdown_flag(false);
std::string as_port = "58058";

void signalHandler(int signal) {
    if (signal == SIGINT) {
        std::cout << std::endl
                  << "Ctrl+C received. Shutting down server..." << std::endl;
        shutdown_flag.store(true);
    }
}

template <typename Func, typename... Args>
auto db_lock(Func func, Args &&...args) {
    std::lock_guard<std::mutex> lock(db_mutex);

    // Call the provided function with its arguments
    return func(std::forward<Args>(args)...);
}

int main(int argc, char **argv) {
    std::signal(SIGINT, signalHandler);
    std::signal(SIGPIPE, SIG_IGN);

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
    std::thread tcp_worker(tcp_handler);

    udp_worker.join();
    tcp_worker.join();

    return 0;
}

void udp_handler() {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        std::cerr << "Couldn't open UDP socket" << std::endl;
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
        std::cerr << "DNS lookup failed" << std::endl;
        exit(1);
    }

    n = bind(fd, dns_res->ai_addr, dns_res->ai_addrlen);
    if (n == -1) {
        std::cerr << "Couldn't bind UDP socket" << std::endl;
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
                // std::cout << "UDP timeout occurred while receiving data"
                //           << std::endl;
                continue;
            } else {
                std::cerr << "Error receiving data: " << strerror(errno)
                          << std::endl;
                continue;
            }
        }

        char ip_str[addrlen + 1];
        std::string address;
        // Convert binary IP address to string
        if (inet_ntop(AF_INET, &(addr.sin_addr), ip_str, addrlen) != NULL) {
            // Convert port number to host byte order
            int port = ntohs(addr.sin_port);

            address = std::string(ip_str) + ":" + std::to_string(port);
        } else {
            std::cerr << "Couldn't convert IP to string" << std::endl;
            address = "ERR";
        }

        std::string req = std::string(buffer, (size_t)n);

        log_connection(address, req, false, true);

        if (n > MAX_REQ_SIZE || n < MIN_REQ_SIZE) {
            n = sendto(fd, ERROR_MSG, sizeof(ERROR_MSG) - 1, 0,
                       (struct sockaddr *)&addr, addrlen);
            if (n == -1) {
                std::cerr << "Couldn't send UDP msg" << std::endl;
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
                send_udp_msg(fd, "RLI ERR\n", &addr, addrlen);
                continue;
            }

            int status_code = db_lock(user_create, uid, password);
            if (status_code == SUCCESS_CODE) {
                res = "RLI REG\n";
                if (db_lock(user_login, uid, password) != SUCCESS_CODE) {
                    res = "RLI NOK\n";  // FIXME
                }
            } else if (status_code == ERR_USER_ALREADY_EXISTS) {
                status_code = db_lock(user_login, uid, password);
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
        } else if (cmd == "LOU") {
            std::string uid, password;
            req_stream >> uid >> password;

            if (req_stream.get() != '\n' || !is_number(uid) ||
                uid.length() != UID_SIZE || !is_alphanumerical(password) ||
                password.length() != PASSWORD_SIZE) {
                send_udp_msg(fd, "RLO ERR\n", &addr, addrlen);
                continue;
            }

            int status_code = db_lock(user_logout, uid, password);
            if (status_code == SUCCESS_CODE) {
                res = "RLO OK\n";
            } else if (status_code == ERR_USER_NOT_LOGGED_IN) {
                res = "RLO NOK\n";
            } else if (status_code == ERR_USER_DOESNT_EXIST) {
                res = "RLO UNR\n";
            } else {
                res = "RLO NOK\n";  // FIXME
            }
        } else if (cmd == "UNR") {
            std::string uid, password;
            req_stream >> uid >> password;

            if (req_stream.get() != '\n' || !is_number(uid) ||
                uid.length() != UID_SIZE || !is_alphanumerical(password) ||
                password.length() != PASSWORD_SIZE) {
                send_udp_msg(fd, "RUR ERR\n", &addr, addrlen);
                continue;
            }

            int status_code = db_lock(user_unregister, uid, password);
            if (status_code == SUCCESS_CODE) {
                res = "RUR OK\n";
            } else if (status_code == ERR_USER_NOT_LOGGED_IN) {
                res = "RUR NOK\n";
            } else if (status_code == ERR_USER_DOESNT_EXIST) {
                res = "RUR UNR\n";
            } else {
                res = "RUR NOK\n";  // FIXME
            }
        } else if (cmd == "LMA") {
            std::string uid;
            req_stream >> uid;

            if (req_stream.get() != '\n' || !is_number(uid) ||
                uid.length() != UID_SIZE) {
                send_udp_msg(fd, "RMA ERR\n", &addr, addrlen);
                continue;
            }

            std::vector<auction_struct> auctions_list;
            int status_code = db_lock(user_auctions, uid, auctions_list);
            if (status_code == SUCCESS_CODE) {
                if (auctions_list.size() == 0) {
                    res = "RMA NOK\n";
                } else {
                    res = "RMA OK";
                    for (auction_struct &auction : auctions_list) {
                        res += " " + auction.aid + " " +
                               (auction.end_sec_time == -1 ? "1" : "0");
                    }
                    res += "\n";
                }
            } else if (status_code == ERR_USER_NOT_LOGGED_IN ||
                       status_code == ERR_USER_DOESNT_EXIST) {
                res = "RMA NLG\n";
            } else {
                res = "RMA NOK\n";  // FIXME
            }
        } else if (cmd == "LMB") {
            std::string uid;
            req_stream >> uid;

            if (req_stream.get() != '\n' || !is_number(uid) ||
                uid.length() != UID_SIZE) {
                send_udp_msg(fd, "RMB ERR\n", &addr, addrlen);
                continue;
            }

            std::vector<auction_struct> auctions_list;
            int status_code = db_lock(user_bidded_auctions, uid, auctions_list);
            if (status_code == SUCCESS_CODE) {
                if (auctions_list.size() == 0) {
                    res = "RMB NOK\n";
                } else {
                    res = "RMB OK";
                    for (auction_struct &auction : auctions_list) {
                        res += " " + auction.aid + " " +
                               (auction.end_sec_time == -1 ? "1" : "0");
                    }
                    res += "\n";
                }
            } else if (status_code == ERR_USER_NOT_LOGGED_IN ||
                       status_code == ERR_USER_DOESNT_EXIST) {
                res = "RMB NLG\n";
            } else {
                res = "RMB NOK\n";  // FIXME
            }
        } else if (cmd == "LST") {
            if (req_stream.get() != '\n') {
                send_udp_msg(fd, "RLS ERR\n", &addr, addrlen);
                continue;
            }

            std::vector<auction_struct> auctions_list;
            int status_code = db_lock(auction_list, auctions_list);
            if (status_code == SUCCESS_CODE) {
                if (auctions_list.size() == 0) {
                    res = "RLS NOK\n";
                } else {
                    res = "RLS OK";
                    for (auction_struct &auction : auctions_list) {
                        res += " " + auction.aid + " " +
                               (auction.end_sec_time == -1 ? "1" : "0");
                    }
                    res += "\n";
                }
            } else {
                res = "RLS NOK\n";  // FIXME
            }
        } else if (cmd == "SRC") {
            std::string aid;
            req_stream >> aid;

            if (req_stream.get() != '\n' || !is_number(aid) ||
                aid.length() != AID_SIZE) {
                send_udp_msg(fd, "RRC ERR\n", &addr, addrlen);
                continue;
            }

            auction_struct auction;
            int status_code = db_lock(auction_get_info, aid, &auction);
            if (status_code == SUCCESS_CODE) {
                res = "RRC OK " + auction.uid + " " + auction.name + " " +
                      auction.asset_fname + " " +
                      std::to_string(auction.start_value) + " " +
                      auction.start_datetime + " " +
                      std::to_string(auction.timeactive);

                std::vector<bid_struct> bid_list;
                if (db_lock(auction_bids, aid, bid_list) == SUCCESS_CODE) {
                    for (bid_struct &bid : bid_list) {
                        res += " B " + bid.uid + " " +
                               std::to_string(bid.value) + " " + bid.datetime +
                               " " + std::to_string(bid.sec_time);
                    }

                    if (auction.end_sec_time != -1) {
                        res += " E " + auction.end_datetime + " " +
                               std::to_string(auction.end_sec_time);
                    }
                    res += "\n";
                } else {
                    res = "RRC NOK\n";  // FIXME
                }
            } else if (status_code == ERR_AUCTION_DOESNT_EXIST) {
                res = "RRC NOK\n";
            } else {
                res = "RRC NOK\n";  // FIXME
            }
        } else {
            res = ERROR_MSG;
        }

        send_udp_msg(fd, res, &addr, addrlen);
        log_connection(address, res, false, false);
    }

    std::cout << "Shutting down UDP worker thread..." << std::endl;
    freeaddrinfo(dns_res);
    close(fd);
}

void send_udp_msg(int fd, std::string msg, sockaddr_in *addr,
                  socklen_t addrlen) {
    ssize_t n = sendto(fd, msg.c_str(), msg.length(), 0,
                       (struct sockaddr *)addr, addrlen);
    if (n == -1) {
        std::cerr << "Error sending UDP message" << std::endl;
    }
}

void tcp_handler() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        std::cerr << "Couldn't open TCP socket" << std::endl;
        exit(1);
    }

    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    // Set socket timeout for both reads and writes
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) < 0) {
        std::cout << "ERROR: couldn't set TCP socket timeout" << std::endl;
        exit(1);
    }

    ssize_t n;
    socklen_t addrlen;
    struct addrinfo hints, *dns_res;
    struct sockaddr_in addr;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int errcode = getaddrinfo(NULL, as_port.c_str(), &hints, &dns_res);
    if (errcode != 0) {
        std::cerr << "DNS lookup failed" << std::endl;
        exit(1);
    }

    n = bind(fd, dns_res->ai_addr, dns_res->ai_addrlen);
    if (n == -1) {
        std::cerr << "Couldn't bind TCP socket" << std::endl;
        exit(1);
    }

    // 5 connection requests will be queued before further requests are refused
    if (listen(fd, 5) == -1) {  // FIXME
        std::cerr << "Couldn't listen on TCP socket" << std::endl;
        exit(1);
    }

    std::vector<std::thread> threads;
    while (!shutdown_flag.load()) {
        addrlen = sizeof(addr);

        int new_fd;
        if ((new_fd = accept(fd, (struct sockaddr *)&addr, &addrlen)) == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                // std::cout
                //     << "TCP timeout occurred while waiting for connections"
                //     << std::endl;
                continue;
            } else {
                std::cerr << "Error receiving data: " << strerror(errno)
                          << std::endl;
                continue;
            }
        }

        char ip_str[addrlen + 1];
        std::string address;
        // Convert binary IP address to string
        if (inet_ntop(AF_INET, &(addr.sin_addr), ip_str, addrlen) != NULL) {
            // Convert port number to host byte order
            int port = ntohs(addr.sin_port);

            address = std::string(ip_str) + ":" + std::to_string(port);
        } else {
            std::cerr << "Couldn't convert IP to string" << std::endl;
            address = "ERR";
        }

        threads.push_back(std::thread(handle_tcp_request, new_fd, address));
    }

    for (std::thread &t : threads) {
        t.join();
    }

    freeaddrinfo(dns_res);
    close(fd);
}

void handle_tcp_request(int fd, std::string address) {
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    // Set socket timeout for both reads and writes
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) < 0) {
        std::cout << "ERROR: couldn't set TCP socket timeout" << std::endl;
        close(fd);
        return;
    }

    char cmd_buffer[CMD_SIZE];
    ssize_t n;
    ssize_t nleft = CMD_SIZE;
    while (nleft > 0) {
        n = _read(fd, cmd_buffer + (CMD_SIZE - nleft), (size_t)nleft);
        if (n == -1 || n == 0) {
            if (n == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
                std::cout << "TCP timeout occurred while receiving command"
                          << std::endl;
            } else {
                std::cerr << "Error receiving data: " << strerror(errno)
                          << std::endl;
            }
            close(fd);
            return;
        }

        nleft -= n;
    }

    std::string cmd(cmd_buffer, CMD_SIZE);
    std::string res;

    if (cmd == "OPA") {
        char buffer[128];

        std::vector<std::string> tokens;
        n = read_tokens_from_tcp_socket(fd, tokens, 7, MAX_FNAME_SIZE, false,
                                        buffer);
        if (n == -1) {
            terminate_tcp_conn(fd, "ROA ERR\n", address);
            return;
        }

        std::string uid = tokens[0];
        std::string password = tokens[1];
        std::string name = tokens[2];
        std::string start_value = tokens[3];
        std::string time_active = tokens[4];
        std::string asset_fname = tokens[5];
        std::string asset_fsize = tokens[6];

        cmd += " " + uid + " " + password + " " + name + " " + start_value +
               " " + time_active + " " + asset_fname + " " + asset_fsize + "\n";
        log_connection(address, cmd, true, true);

        if (!is_number(uid) || uid.length() != UID_SIZE ||
            !is_alphanumerical(password) ||
            password.length() != PASSWORD_SIZE ||
            !is_alphanumerical(name, "-_") ||
            name.length() > AUCTION_NAME_SIZE || !is_number(start_value) ||
            start_value.length() > VALUE_SIZE || !is_number(time_active) ||
            time_active.length() > DURATION_SIZE ||
            std::stoi(asset_fsize) > MAX_ASSET_FILE_SIZE_MB * MB_N_BYTES) {
            terminate_tcp_conn(fd, "ROA ERR\n", address);
            return;
        }

        if (buffer[0] != ' ') {
            terminate_tcp_conn(fd, "ROA ERR\n", address);
            return;
        }

        char *buffer_ptr = n == 1 ? buffer : buffer + 1;

        std::string aid;
        int status_code =
            db_lock(auction_create, aid, uid, password, name, asset_fname,
                    std::stoi(start_value), std::stoi(time_active));
        if (status_code == SUCCESS_CODE) {
            status_code = db_lock(auction_store_asset, aid, fd, asset_fname,
                                  asset_fsize, buffer_ptr, n - 1);
            if (status_code == SUCCESS_CODE) {
                res = "ROA OK " + aid + "\n";
            } else {
                auction_remove(aid);
                res = "ROA NOK\n";  // FIXME
            }
        } else if (status_code == ERR_AUCTION_LIMIT_REACHED) {
            res = "ROA NOK\n";
        } else if (status_code == ERR_USER_DOESNT_EXIST ||
                   status_code == ERR_USER_NOT_LOGGED_IN ||
                   status_code == ERR_USER_INVALID_PASSWORD) {
            res = "ROA NLG\n";
        } else {
            res = "ROA NOK\n";  // FIXME
        }
    } else if (cmd == "CLS") {
        char buffer[128];

        std::vector<std::string> tokens;
        n = read_tokens_from_tcp_socket(fd, tokens, 3, PASSWORD_SIZE, false,
                                        buffer);
        if (n == -1) {
            terminate_tcp_conn(fd, "RCL ERR\n", address);
            return;
        }

        std::string uid = tokens[0];
        std::string password = tokens[1];
        std::string aid = tokens[2];

        cmd += " " + uid + " " + password + " " + aid +
               std::string(buffer, (size_t)n);
        log_connection(address, cmd, true, true);

        if (n != 1 || buffer[0] != '\n' || !is_number(aid) ||
            aid.length() != AID_SIZE || !is_number(uid) ||
            uid.length() != UID_SIZE || !is_alphanumerical(password) ||
            password.length() != PASSWORD_SIZE) {
            terminate_tcp_conn(fd, "RCL ERR\n", address);
            return;
        }

        int status_code = db_lock(auction_close, aid, uid, password);
        if (status_code == SUCCESS_CODE) {
            res = "RCL OK\n";
        } else if (status_code == ERR_USER_DOESNT_EXIST ||
                   status_code == ERR_USER_INVALID_PASSWORD) {
            res = "RCL NOK\n";
        } else if (status_code == ERR_USER_NOT_LOGGED_IN) {
            res = "RCL NLG\n";
        } else if (status_code == ERR_AUCTION_DOESNT_EXIST) {
            res = "RCL EAU\n";
        } else if (status_code == ERR_AUCTION_NOT_OWNED_BY_USER) {
            res = "RCL EOW\n";
        } else if (status_code == ERR_AUCTION_ALREADY_CLOSED) {
            res = "RCL END\n";
        } else {
            res = "RCL NOK\n";  // FIXME
        }
    } else if (cmd == "SAS") {
        char buffer[128];

        std::vector<std::string> tokens;
        n = read_tokens_from_tcp_socket(fd, tokens, 1, AID_SIZE, false, buffer);
        if (n == -1) {
            terminate_tcp_conn(fd, "RSA ERR\n", address);
            return;
        }

        std::string aid = tokens[0];

        cmd += " " + aid + std::string(buffer, (size_t)n);
        log_connection(address, cmd, true, true);

        if (n != 1 || buffer[0] != '\n' || !is_number(aid) ||
            aid.length() != AID_SIZE) {
            terminate_tcp_conn(fd, "RSA ERR\n", address);
            return;
        }

        int status_code = db_lock(auction_send_asset, aid, fd);
        if (status_code == SUCCESS_CODE) {
            log_connection(address, "RSA OK [...]\n", true, false);
            close(fd);
            return;
        } else {
            res = "RSA NOK\n";
        }
    } else if (cmd == "BID") {
        char buffer[128];

        std::vector<std::string> tokens;
        n = read_tokens_from_tcp_socket(fd, tokens, 4, PASSWORD_SIZE, false,
                                        buffer);
        if (n == -1) {
            terminate_tcp_conn(fd, "RBD ERR\n", address);
            return;
        }

        std::string uid = tokens[0];
        std::string password = tokens[1];
        std::string aid = tokens[2];
        std::string value = tokens[3];

        cmd += " " + uid + " " + password + " " + aid + " " + value +
               std::string(buffer, (size_t)n);
        log_connection(address, cmd, true, true);

        if (n != 1 || buffer[0] != '\n' || !is_number(uid) ||
            uid.length() != UID_SIZE || !is_alphanumerical(password) ||
            password.length() != PASSWORD_SIZE || !is_number(aid) ||
            aid.length() != AID_SIZE || !is_number(value) ||
            value.length() > VALUE_SIZE) {
            terminate_tcp_conn(fd, "RBD ERR\n", address);
            return;
        }

        int status_code =
            db_lock(bid_create, aid, uid, password, std::stoi(value));
        if (status_code == SUCCESS_CODE) {
            res = "RBD ACC\n";
        } else if (status_code == ERR_AUCTION_ALREADY_CLOSED) {
            res = "RBD NOK\n";
        } else if (status_code == ERR_USER_NOT_LOGGED_IN ||
                   status_code == ERR_USER_DOESNT_EXIST ||
                   status_code == ERR_USER_INVALID_PASSWORD) {
            res = "RBD NLG\n";
        } else if (status_code == ERR_BID_TOO_LOW) {
            res = "RBD REF\n";
        } else if (status_code == ERR_BID_OWN_AUCTION) {
            res = "RBD ILG\n";
        } else if (status_code == ERR_AUCTION_DOESNT_EXIST) {
            res = "RBD NOK\n";  // FIXME
        } else {
            res = "RBD NOK\n";  // FIXME
        }
    } else {
        cmd += " (unknown command)";
        log_connection(address, cmd, true, true);
        res = ERROR_MSG;
    }

    terminate_tcp_conn(fd, res, address);
}

void terminate_tcp_conn(int fd, std::string msg, std::string address) {
    _write(fd, msg.c_str(), msg.length());
    log_connection(address, msg, true, false);
    close(fd);
}

void log_connection(const std::string &address, const std::string &cmd,
                    bool tcp, bool received) {
    if (verbose.load()) {
        std::cout << "[" << address << "](" << (tcp ? "TCP" : "UDP") << ") "
                  << (received ? "received: " : "sent: ") << cmd << std::endl;
    }
}
