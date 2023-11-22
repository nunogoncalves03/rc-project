#ifndef _USER_H__
#define _USER_H__

#include <string>

#define CMD_SIZE 3
#define UID_SIZE 6
#define PASSWORD_SIZE 8
#define AID_SIZE 3
#define AUCTION_NAME_SIZE 10
#define DATE_TIME_SIZE 19
#define MAX_FNAME_SIZE 24
#define MAX_FSIZE_SIZE 8
#define MAX_ASSET_FILE_SIZE_MB 10
#define VALUE_SIZE 6
#define DURATION_SIZE 6

// Responses maximum sizes
#define LOGIN_RES_SIZE (CMD_SIZE + 1 + 3 + 1)
#define LOGOUT_RES_SIZE (CMD_SIZE + 1 + 3 + 1)
#define UNREGISTER_RES_SIZE (CMD_SIZE + 1 + 3 + 1)
#define MYAUCTIONS_RES_SIZE (CMD_SIZE + 1 + 2 + 999 * (1 + AID_SIZE + 1 + 1) + 1)
#define MYBIDS_RES_SIZE (CMD_SIZE + 1 + 2 + 50 * (1 + AID_SIZE + 1 + 1) + 1)
#define LIST_RES_SIZE (CMD_SIZE + 1 + 2 + 999 * (1 + AID_SIZE + 1 + 1) + 1)
#define SHOWRECORD_RES_SIZE (CMD_SIZE + 1 + 2 + 1 + (UID_SIZE + 1 + AUCTION_NAME_SIZE \
         + 1 + MAX_FNAME_SIZE + 1 + VALUE_SIZE + 1 + DATE_TIME_SIZE + 1 + DURATION_SIZE) \
         + 50 * (1 + 1 + 1 + UID_SIZE + 1 +  VALUE_SIZE + 1 + DATE_TIME_SIZE + 1 + DURATION_SIZE) \
         + (1 + 1 + 1 + DATE_TIME_SIZE + 1 + DURATION_SIZE) + 1)


std::string udp_request(int socket_fd, std::string& msg, size_t res_max_size);
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

void graceful_shutdown(int code);

#endif
