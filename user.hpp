#ifndef _USER_H__
#define _USER_H__

#define CMD_SIZE 3
#define UID_SIZE 6
#define PASSWORD_SIZE 8

#include <string>

std::string udp_request(int socket_fd, std::string& msg);

void handle_login_response(std::string& res);
void handle_logout_response(std::string& res);
void handle_unregister_response(std::string& res);
void handle_myauctions_response(std::string& res);
void handle_mybids_response(std::string& res);
void handle_list_response(std::string& res);

#endif
