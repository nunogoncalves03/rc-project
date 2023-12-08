#ifndef _SERVER_H__
#define _SERVER_H__

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

#endif