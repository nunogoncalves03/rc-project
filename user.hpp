#ifndef _USER_H__
#define _USER_H__

#define CMD_SIZE 3
#define UID_SIZE 6
#define PASSWORD_SIZE 8
#define AID_SIZE 3
#define MAX_FNAME_SIZE 24
#define MAX_FSIZE_SIZE 8
#define MAX_ASSET_FILE_SIZE_MB 10

#include <string>

std::string udp_request(int socket_fd, std::string& msg);
std::string tcp_request(std::string& msg);

void handle_login_response(std::string& res, std::string& uid_, std::string& password_);
void handle_logout_response(std::string& res);
void handle_unregister_response(std::string& res);
void handle_open_response(std::string& res);
void handle_close_response(std::string& res);
void handle_myauctions_response(std::string& res);
void handle_mybids_response(std::string& res);
void handle_list_response(std::string& res);
void handle_show_asset_request(std::string& msg);
void handle_bid_response(std::string& res);
void handle_show_record_response(std::string& res);

#endif
