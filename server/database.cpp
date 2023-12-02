#include "common.hpp"
#include "database.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>

int init() {
    if (!std::filesystem::exists("./DATABASE/")) {
        if (!std::filesystem::create_directory("./DATABASE/")) {
            std::cerr << "Error creating directory: ./DATABASE/" << std::endl;
            return 1;
        }
    }
    
    if (!std::filesystem::exists("./DATABASE/USERS/")) {
        if (!std::filesystem::create_directory("./DATABASE/USERS/")) {
            std::cerr << "Error creating directory: ./DATABASE/USERS/" << std::endl;
            return 1;
        }
    }

    if (!std::filesystem::exists("./DATABASE/AUCTIONS/")) {
        if (!std::filesystem::create_directory("./DATABASE/AUCTIONS/")) {
            std::cerr << "Error creating directory: ./DATABASE/AUCTIONS/" << std::endl;
            return 1;
        }
    }

    return SUCCESS_CODE;
}

int user_create(std::string uid, std::string pass) {
    std::string password_file_path = "./DATABASE/USERS/" + uid + "/" + uid + "_pass.txt";

    if (!std::filesystem::exists("./DATABASE/USERS/" + uid)) {
        if (!std::filesystem::create_directory("./DATABASE/USERS/" + uid)) {
            std::cerr << "Error creating directory: ./DATABASE/USERS/" << uid << std::endl;
            return 1;
        }

        if (!std::filesystem::create_directory("./DATABASE/USERS/" + uid + "/HOSTED/")) {
            std::cerr << "Error creating directory: ./DATABASE/USERS/" << uid << "/HOSTED/" << std::endl;
            return 1;
        }

        if (!std::filesystem::create_directory("./DATABASE/USERS/" + uid + "/BIDDED/")) {
            std::cerr << "Error creating directory: ./DATABASE/USERS/" << uid << "/BIDDED/" << std::endl;
            return 1;
        }
    } else {
        if (std::filesystem::exists(password_file_path)) {
            return ERR_USER_ALREADY_EXISTS;
        }
    }

    std::ofstream password_file(password_file_path);

    if (!password_file.is_open()) {
        std::cerr << "Failed to open the file " << password_file_path << std::endl;
        return 1;
    }

    password_file << pass << std::endl;
    password_file.close();

    if (user_login(uid) != SUCCESS_CODE) {
        return 1;
    }

    return SUCCESS_CODE;
}

int user_login(std::string uid) {
    if (user_exists(uid) == 1) {
        return ERR_USER_DOESNT_EXIST;
    }
    
    if (user_is_logged_in(uid) == SUCCESS_CODE) {
        return ERR_USER_ALREADY_LOGGED_IN;
    }

    std::ofstream login_file("./DATABASE/USERS/" + uid + "/" + uid + "_login.txt");

    if (!login_file.is_open()) {
        return 1;
    }

    login_file.close();

    return SUCCESS_CODE;
}

int user_logout(std::string uid) {
    if (user_exists(uid) == 1) {
        return ERR_USER_DOESNT_EXIST;
    }
    
    if (user_is_logged_in(uid) != SUCCESS_CODE) {
        return ERR_USER_NOT_LOGGED_IN;
    }

    if (!std::filesystem::remove("./DATABASE/USERS/" + uid + "/" + uid + "_login.txt")) {
        std::cerr << "Error removing file: ./DATABASE/USERS/" << uid << "/" << uid << "_login.txt" << std::endl;
        return 1;
    }

    return SUCCESS_CODE;
}

int user_exists(std::string uid) {
    if (std::filesystem::exists("./DATABASE/USERS/" + uid + "/" + uid + "_pass.txt")) {
        return SUCCESS_CODE;
    }
    return 1;
}

int user_is_logged_in(std::string uid) {
    if (user_exists(uid) == SUCCESS_CODE) {
        if (std::filesystem::exists("./DATABASE/USERS/" + uid + "/" + uid + "_login.txt")) {
            return SUCCESS_CODE;
        }
        return USER_NOT_LOGGED_IN;
    }
    return ERR_USER_DOESNT_EXIST;
}

int remove_user(std::string uid) {
    if (user_exists(uid) == SUCCESS_CODE) {
        if (user_is_logged_in(uid) == SUCCESS_CODE) {
            if (!std::filesystem::remove("./DATABASE/USERS/" + uid + "/" + uid + "_login.txt")) {
                std::cerr << "Error removing file: ./DATABASE/USERS/" << uid << "/" << uid << "_login.txt" << std::endl;
                return 1;
            }
        }

        if (!std::filesystem::remove("./DATABASE/USERS/" + uid + "/" + uid + "_pass.txt")) {
            std::cerr << "Error removing file: ./DATABASE/USERS/" << uid << "/" << uid << "_pass.txt" << std::endl;
            return 1;
        }
    }

    return ERR_USER_DOESNT_EXIST;
}
