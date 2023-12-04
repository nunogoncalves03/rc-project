#ifndef _DATABASE_H__
#define _DATABASE_H__

#include <string>

#define TRUE 0
#define FALSE 1
#define SUCCESS_CODE 2
#define ERROR_CODE 3

#define ERR_USER_ALREADY_EXISTS 4
#define ERR_USER_DOESNT_EXIST 5
#define ERR_USER_ALREADY_LOGGED_IN 6
#define ERR_USER_NOT_LOGGED_IN 7

/**
 * @brief init the database 
 * 
 * @return SUCCESS_CODE if the database was initialized correctly \n
 * @return ERROR_CODE if some unexpected error occurs \n
 */
int init();

// user functions
/**
 * @brief create a new user (not logged in)
 * 
 * @param uid 
 * @param pass 
 * 
 * @return SUCCESS_CODE if user was created successfully \n
 * @return ERR_USER_ALREADY_EXISTS if user already exists \n
 * @return ERROR_CODE if some unexpected error occurs \n
 */
int user_create(std::string uid, std::string pass);
/**
 * @brief login the given user
 * 
 * @param uid 
 * 
 * @return SUCCESS_CODE if user was logged in successfully \n
 * @return ERR_USER_DOESNT_EXIST if user doesn't exist \n
 * @return ERR_USER_ALREADY_LOGGED_IN if user is already logged in \n
 * @return ERROR_CODE if some unexpected error occurs \n
 */
int user_login(std::string uid);
/**
 * @brief logs out the given user
 * 
 * @param uid 
 * 
 * @return SUCCESS_CODE if user was logged out successfully \n
 * @return ERR_USER_DOESNT_EXIST if user doesn't exist \n
 * @return ERR_USER_NOT_LOGGED_IN if user is not logged in \n
 * @return ERROR_CODE if some unexpected error occurs \n
 */
int user_logout(std::string uid);
/**
 * @brief checks if the user exists in the database
 * 
 * @param uid 
 * @return TRUE if user exists \n
 * @return FALSE if not \n
 */
int user_exists(std::string uid);
/**
 * @brief checks if user is logged in
 * 
 * @param uid 
 * @return TRUE if user is logged in \n
 * @return FALSE if not \n
 * @return ERR_USER_DOESNT_EXIST if user doesn't exist \n
 */
int user_is_logged_in(std::string uid);
/**
 * @brief remove the user and logout if user is logged in
 * 
 * @param uid 
 * 
 * @return SUCCESS_CODE if user was removed successfully \n
 * @return ERR_USER_DOESNT_EXIST if user doesn't exist \n
 * @return ERROR_CODE if some unexpected error occurs \n
 */
int user_remove(std::string uid);

// auction functions
// int auction_create(std::string aid, std::string uid, std::string name,
//                    std::string asset_fname, int start_value, int duration);

/**
 * @brief counts the number of existing auctions
 * 
 * @return the number of auctions (directories)
 */
int auction_count();

#endif