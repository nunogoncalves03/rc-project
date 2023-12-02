#ifndef _DATABASE_H__
#define _DATABASE_H__

#include <string>

#define SUCCESS_CODE 0

#define ERR_USER_ALREADY_EXISTS 2
#define ERR_USER_DOESNT_EXIST 3
#define ERR_USER_ALREADY_LOGGED_IN 4
#define ERR_USER_NOT_LOGGED_IN 5

#define USER_NOT_LOGGED_IN 10

int init();
int user_create(std::string uid, std::string pass);
int user_login(std::string uid);
int user_logout(std::string uid);
int user_exists(std::string uid);
int user_is_logged_in(std::string uid);
int remove_user(std::string uid);

#endif