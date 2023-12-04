#include "database.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>

#include "common.hpp"

int init() {
    if (!std::filesystem::exists("./DATABASE/")) {
        if (!std::filesystem::create_directory("./DATABASE/")) {
            std::cerr << "Error creating directory: ./DATABASE/" << std::endl;
            return ERROR_CODE;
        }
    }

    if (!std::filesystem::exists("./DATABASE/USERS/")) {
        if (!std::filesystem::create_directory("./DATABASE/USERS/")) {
            std::cerr << "Error creating directory: ./DATABASE/USERS/"
                      << std::endl;
            return ERROR_CODE;
        }
    }

    if (!std::filesystem::exists("./DATABASE/AUCTIONS/")) {
        if (!std::filesystem::create_directory("./DATABASE/AUCTIONS/")) {
            std::cerr << "Error creating directory: ./DATABASE/AUCTIONS/"
                      << std::endl;
            return ERROR_CODE;
        }
    }

    return SUCCESS_CODE;
}

int user_create(std::string uid, std::string pass) {
    if (!std::filesystem::exists("./DATABASE/USERS/" + uid)) {
        if (!std::filesystem::create_directory("./DATABASE/USERS/" + uid)) {
            std::cerr << "Error creating directory: ./DATABASE/USERS/" << uid
                      << std::endl;
            return ERROR_CODE;
        }

        if (!std::filesystem::create_directory("./DATABASE/USERS/" + uid +
                                               "/HOSTED/")) {
            std::cerr << "Error creating directory: ./DATABASE/USERS/" << uid
                      << "/HOSTED/" << std::endl;
            return ERROR_CODE;
        }

        if (!std::filesystem::create_directory("./DATABASE/USERS/" + uid +
                                               "/BIDDED/")) {
            std::cerr << "Error creating directory: ./DATABASE/USERS/" << uid
                      << "/BIDDED/" << std::endl;
            return ERROR_CODE;
        }
    } else {
        if (user_exists(uid) == TRUE) {
            return ERR_USER_ALREADY_EXISTS;
        }
    }

    std::string password_file_path =
        "./DATABASE/USERS/" + uid + "/" + uid + "_pass.txt";
    std::ofstream password_file(password_file_path);

    if (!password_file.is_open()) {
        std::cerr << "Failed to open the file " << password_file_path
                  << std::endl;
        return ERROR_CODE;
    }

    password_file << pass << std::endl;
    password_file.close();

    return SUCCESS_CODE;
}

int user_login(std::string uid) {
    if (user_exists(uid) == FALSE) {
        return ERR_USER_DOESNT_EXIST;
    }

    if (user_is_logged_in(uid) == TRUE) {
        return ERR_USER_ALREADY_LOGGED_IN;
    }

    std::ofstream login_file("./DATABASE/USERS/" + uid + "/" + uid +
                             "_login.txt");

    if (!login_file.is_open()) {
        return ERROR_CODE;
    }

    login_file.close();

    return SUCCESS_CODE;
}

int user_logout(std::string uid) {
    if (user_exists(uid) == FALSE) {
        return ERR_USER_DOESNT_EXIST;
    }

    if (user_is_logged_in(uid) == FALSE) {
        return ERR_USER_NOT_LOGGED_IN;
    }

    if (!std::filesystem::remove("./DATABASE/USERS/" + uid + "/" + uid +
                                 "_login.txt")) {
        std::cerr << "Error removing file: ./DATABASE/USERS/" << uid << "/"
                  << uid << "_login.txt" << std::endl;
        return ERROR_CODE;
    }

    return SUCCESS_CODE;
}

int user_exists(std::string uid) {
    if (std::filesystem::exists("./DATABASE/USERS/" + uid + "/" + uid +
                                "_pass.txt")) {
        return TRUE;
    }
    return FALSE;
}

int user_is_logged_in(std::string uid) {
    if (user_exists(uid) == TRUE) {
        if (std::filesystem::exists("./DATABASE/USERS/" + uid + "/" + uid +
                                    "_login.txt")) {
            return TRUE;
        }
        return FALSE;
    }
    return ERR_USER_DOESNT_EXIST;
}

int user_remove(std::string uid) {
    if (user_exists(uid) == TRUE) {
        if (user_is_logged_in(uid) == TRUE) {
            if (!std::filesystem::remove("./DATABASE/USERS/" + uid + "/" + uid +
                                         "_login.txt")) {
                std::cerr << "Error removing file: ./DATABASE/USERS/" << uid
                          << "/" << uid << "_login.txt" << std::endl;
                return ERROR_CODE;
            }
        }

        if (!std::filesystem::remove("./DATABASE/USERS/" + uid + "/" + uid +
                                     "_pass.txt")) {
            std::cerr << "Error removing file: ./DATABASE/USERS/" << uid << "/"
                      << uid << "_pass.txt" << std::endl;
            return ERROR_CODE;
        }

        return SUCCESS_CODE;
    }

    return ERR_USER_DOESNT_EXIST;
}

// int auction_create(std::string aid, std::string uid, std::string name,
//                    std::string asset_fname, int start_value, int duration) {}

int auction_count() {
    int counter = 0;

    for (const auto& entry : std::filesystem::directory_iterator("./DATABASE/AUCTIONS/")) {
        if (entry.is_directory()) {
            counter++;
        }
    }

    return counter;
}