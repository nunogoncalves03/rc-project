#ifndef _DATABASE_H__
#define _DATABASE_H__

#include <string>
#include <vector>

#define MAX_AUCTIONS_N 999

#define TRUE 0
#define FALSE 1
#define SUCCESS_CODE 2
#define ERROR_CODE 3

#define ERR_USER_ALREADY_EXISTS 10
#define ERR_USER_DOESNT_EXIST 11
#define ERR_USER_ALREADY_LOGGED_IN 12
#define ERR_USER_NOT_LOGGED_IN 13

#define ERR_AUCTION_LIMIT_REACHED 20
#define ERR_AUCTION_DOESNT_EXIST 21
#define ERR_AUCTION_ALREADY_CLOSED 22

#define ERR_BID_OWN_AUCTION 30
#define ERR_BID_TOO_LOW 31

typedef struct auction {
    std::string aid;
    std::string uid;
    std::string name;
    std::string asset_fname;
    ssize_t asset_fsize;
    int start_value;
    int timeactive;
    std::string start_datetime;
    time_t start_fulltime;
    std::string end_datetime;
    time_t end_sec_time;
} auction_struct;

typedef struct bid {
    std::string aid;
    std::string uid;
    int value;
    std::string datetime;
    time_t sec_time;
} bid_struct;

/**
 * @brief init the database 
 * 
 * @return SUCCESS_CODE if the database was initialized correctly \n
 * @return ERROR_CODE if some unexpected error occurs \n
 */
int db_init();

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
int user_unregister(std::string uid);
/**
 * @brief stores in the given vector all the user auctions
 * 
 * @param uid 
 * @param auctions_list
 * 
 * @return SUCCESS_CODE if the info was successfully retrieved \n
 * @return ERR_USER_DOESNT_EXIST if user doesn't exist \n
 * @return ERROR_CODE if some unexpected error occurs \n
 */
int user_auctions(std::string uid, std::vector<auction_struct>& auctions_list);
/**
 * @brief stores in the given vector all the auctions where the user placed bids
 * 
 * @param uid 
 * @param auctions_list
 * 
 * @return SUCCESS_CODE if the info was successfully retrieved \n
 * @return ERR_USER_DOESNT_EXIST if user doesn't exist \n
 * @return ERROR_CODE if some unexpected error occurs \n
 */
int user_bidded_auctions(std::string uid, std::vector<auction_struct>& auctions_list);

// auction functions
/**
 * @brief counts the number of existing auctions
 * 
 * @return the number of auctions (directories)
 */
int auction_count();
/**
 * @brief writes on the given struct all the info stored related to the auction
 * 
 * @param aid
 * @param auction - ptr to the auction_struct where the info will be stored 
 *
 * @return SUCCESS_CODE if the info was retrieved successfully \n
 * @return ERR_AUCTION_DOESNT_EXIST if there's no such auction \n
 * @return ERROR_CODE  if some unexpected error occurs \n
 */
int auction_get_info(std::string aid, auction_struct *auction);
/**
 * @brief stores in the given vector all the auctions
 * 
 * @param auctions_list
 * 
 * @return SUCCESS_CODE if the info was successfully retrieved \n
 * @return ERROR_CODE if some unexpected error occurs \n
 */
int auction_list(std::vector<auction_struct>& auctions_list);
/**
 * @brief creates an auction (doesn't store the asset)
 * 
 * @param aid
 * @param uid
 * @param name
 * @param asset_fname
 * @param start_value
 * @param time_active
 * @param start_datetime
 * @param start_fulltime
 * 
 * @return SUCCESS_CODE if the auction was created successfully \n
 * @return ERR_AUCTION_LIMIT_REACHED if the max number of auctions has been reached \n
 * @return ERROR_CODE if some unexpected error occurs \n
 */
int auction_create(std::string& aid, std::string uid, std::string name,
                    std::string asset_fname, int start_value, int time_active);
/**
 * @brief reads the asset_fdata from the given socket and stores it
 * 
 * @param aid
 * @param socket_fd
 * @param asset_fname
 * @param asset_fsize
 * 
 * @return SUCCESS_CODE if the asset was stored successfully \n
 * @return ERR_AUCTION_DOESNT_EXIST if there's no such auction \n
 * @return ERROR_CODE if some unexpected error occurs \n
 */
int auction_store_asset(std::string aid, int socket_fd, std::string asset_fname,
                        std::string asset_fsize);
/**
 * @brief writes the asset_fdata to the given socket
 * 
 * @param aid
 * @param socket_fd
 * @param asset_fname
 * @param asset_fsize
 * 
 * @return SUCCESS_CODE if the asset was sent successfully \n
 * @return ERR_AUCTION_DOESNT_EXIST if there's no such auction \n
 * @return ERROR_CODE if some unexpected error occurs \n
 */
int auction_send_asset(std::string aid, int socket_fd, std::string asset_fname,
                        ssize_t asset_fsize);
/**
 * @brief checks if the auction exists in the database
 * 
 * @param aid 
 * @return TRUE if auction exists \n
 * @return FALSE if not \n
 */
int auction_exists(std::string aid);
/**
 * @brief closes the given auction
 * 
 * @param aid 
 * @return SUCCESS_CODE if the auction was closed successfully \n
 * @return ERR_AUCTION_DOESNT_EXIST if there's no such auction \n
 * @return ERR_AUCTION_ALREADY_CLOSED if the auction was already closed
 * @return ERROR_CODE if some unexpected error occurs \n
 */
int auction_close(std::string aid);
/**
 * @brief closes the given auction if it has expired
 * 
 * @param aid 
 * @return SUCCESS_CODE if there was no error \n
 * @return ERROR_CODE if some unexpected error occurs \n
 */
int auction_close_if_expired(std::string aid, auction_struct* auction);
/**
 * @brief stores in the given vector all the bids from the auction
 * 
 * @param aid 
 * @param bids_list 
 * @return SUCCESS_CODE if there was no error \n
 * @return ERR_AUCTION_DOESNT_EXIST if there's no such auction \n
 * @return ERROR_CODE if some unexpected error occurs \n
 */
int auction_bids(std::string aid, std::vector<bid_struct>& bids_list);
/**
 * @brief places a bid from the given user on the given auction
 * 
 * @param aid 
 * @param uid 
 * @param value 
 * @return SUCCESS_CODE if there was no error \n
 * @return ERR_AUCTION_DOESNT_EXIST if there's no such auction \n
 * @return ERR_AUCTION_ALREADY_CLOSED if the auction was already closed \n
 * @return ERR_BID_TOO_LOW if there's already an equal or higher bid placed \n
 * @return ERR_BID_OWN_AUCTION if the user is trying to bid on his own auction \n
 * @return ERROR_CODE if some unexpected error occurs \n
 */
int bid_create(std::string aid, std::string uid, int value);

#endif