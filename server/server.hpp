#ifndef _SERVER_H__
#define _SERVER_H__

#include <arpa/inet.h>

#include <string>
#include <vector>

#include "common.hpp"

#define ERROR_MSG "ERR\n"

// Requests maximum sizes
#define LOGIN_REQ_SIZE (CMD_SIZE + 1 + UID_SIZE + 1 + PASSWORD_SIZE + 1)
#define LOGOUT_REQ_SIZE (CMD_SIZE + 1 + UID_SIZE + 1 + PASSWORD_SIZE + 1)
#define UNREGISTER_REQ_SIZE (CMD_SIZE + 1 + UID_SIZE + 1 + PASSWORD_SIZE + 1)
#define MYAUCTIONS_REQ_SIZE (CMD_SIZE + 1 + UID_SIZE + 1)
#define MYBIDS_REQ_SIZE (CMD_SIZE + 1 + UID_SIZE + 1)
#define LIST_REQ_SIZE (CMD_SIZE + 1)
#define SHOWRECORD_REQ_SIZE (CMD_SIZE + 1 + AID_SIZE + 1)
#define MAX_REQ_SIZE LOGIN_REQ_SIZE
#define MIN_REQ_SIZE (CMD_SIZE + 1)

void udp_handler();
void send_udp_msg(int fd, std::string msg, sockaddr_in *addr,
                  socklen_t addrlen);
void log_udp_msg(sockaddr_in *addr, socklen_t addrlen, const std::string &msg,
                 bool received);

void tcp_handler();
void handle_tcp_request(int fd, std::string address);

void terminate_tcp_conn(int fd, std::string msg, std::string address);
void log_tcp_connection(const std::string &address, const std::string &cmd,
                        bool received);

#endif