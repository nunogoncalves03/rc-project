#include "database.hpp"

#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

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

int user_auctions(std::string uid, std::vector<auction_struct>& auctions_list) {
    if (user_exists(uid) == FALSE) {
        return ERR_USER_DOESNT_EXIST;
    }

    for (const auto& entry : std::filesystem::directory_iterator(
             "./DATABASE/USERS/" + uid + "/HOSTED/")) {
        if (entry.is_regular_file()) {
            const std::string filename = entry.path().filename().string();
            std::string aid = filename.substr(0, filename.find_last_of('.'));

            auction_struct auction;
            if (auction_get_info(aid, &auction) != SUCCESS_CODE) {
                return ERROR_CODE;
            }

            auctions_list.push_back(auction);
        }
    }

    std::sort(auctions_list.begin(), auctions_list.end(),
              [](const auction_struct& a, const auction_struct& b) {
                  return std::atoi(a.aid.c_str()) < std::atoi(b.aid.c_str());
              });

    return SUCCESS_CODE;
}

int auction_count() {
    int counter = 0;

    for (const auto& entry :
         std::filesystem::directory_iterator("./DATABASE/AUCTIONS/")) {
        if (entry.is_directory()) {
            counter++;
        }
    }

    return counter;
}

int auction_get_info(std::string aid, auction_struct* auction) {
    const std::string auction_base_path = "./DATABASE/AUCTIONS/" + aid + "/";

    if (auction_exists(aid) == FALSE) {
        return ERR_AUCTION_DOESNT_EXIST;
    }

    std::string start_file_path = auction_base_path + "START_" + aid + ".txt";
    std::ifstream start_file(start_file_path);

    if (!start_file.is_open()) {
        std::cerr << "Failed to open the file " << start_file_path << std::endl;
        return ERROR_CODE;
    }

    auction->aid = aid;

    start_file >> auction->uid >> auction->name >> auction->asset_fname >>
        auction->start_value >> auction->timeactive;
    start_file.get();

    char date[DATE_TIME_SIZE + 1];
    start_file.read(date, DATE_TIME_SIZE);
    auction->start_datetime = std::string(date, DATE_TIME_SIZE);

    start_file >> auction->start_fulltime;

    start_file.close();

    if (auction_is_closed(aid) == TRUE) {
        std::string end_file_path = auction_base_path + "END_" + aid + ".txt";
        std::ifstream end_file(end_file_path);

        if (!end_file.is_open()) {
            std::cerr << "Failed to open the file " << end_file_path
                      << std::endl;
            return ERROR_CODE;
        }

        end_file.read(date, DATE_TIME_SIZE);
        auction->end_datetime = std::string(date, DATE_TIME_SIZE);

        end_file >> auction->end_sec_time;

        end_file.close();
    } else {
        auction->end_datetime = "";
        auction->end_sec_time = -1;
    }

    struct stat stat_buffer;
    const std::string asset_path = auction_base_path + "ASSET/" + auction->asset_fname;
    if (stat(asset_path.c_str(), &stat_buffer) == -1) {
        if (errno == ENOENT) {
            // pathname does not exist
            auction->asset_fsize = -1;
        } else {
            std::cerr << "Failed to open the file " << asset_path << std::endl;
            return ERROR_CODE;
        }
    } else {
        auction->asset_fsize = (ssize_t)stat_buffer.st_size;
    }

    return SUCCESS_CODE;
}

int auction_list(std::vector<auction_struct>& auctions_list) {
    for (const auto& entry :
         std::filesystem::directory_iterator("./DATABASE/AUCTIONS/")) {
        if (entry.is_directory()) {
            const std::string aid = entry.path().filename().string();

            auction_struct auction;
            if (auction_get_info(aid, &auction) != SUCCESS_CODE) {
                return ERROR_CODE;
            }

            auctions_list.push_back(auction);
        }
    }

    std::sort(auctions_list.begin(), auctions_list.end(),
              [](const auction_struct& a, const auction_struct& b) {
                  return std::atoi(a.aid.c_str()) < std::atoi(b.aid.c_str());
              });

    return SUCCESS_CODE;
}

int auction_create(std::string& aid, std::string uid, std::string name,
                   std::string asset_fname, int start_value, int time_active) {
    int count = auction_count();
    if (count >= MAX_AUCTIONS_N) {
        return ERR_AUCTION_LIMIT_REACHED;
    }

    aid = zero_pad_number(count + 1, 3);

    const std::string auction_base_path = "./DATABASE/AUCTIONS/" + aid + "/";
    if (!std::filesystem::create_directory(auction_base_path)) {
        std::cerr << "Error creating directory:" << auction_base_path
                  << std::endl;
        return ERROR_CODE;
    }

    time_t start_fulltime;
    time(&start_fulltime);
    std::string start_datetime = get_date(start_fulltime);

    std::string start_file_path = auction_base_path + "START_" + aid + ".txt";
    std::ofstream start_file(start_file_path);

    if (!start_file.is_open()) {
        std::cerr << "Failed to open the file " << start_file_path << std::endl;
        return ERROR_CODE;
    }

    start_file << uid << " " << name << " " << asset_fname << " " << start_value
               << " " << time_active << " " << start_datetime << " "
               << start_fulltime;

    start_file.close();

    if (!std::filesystem::create_directory(auction_base_path + "ASSET/")) {
        std::cerr << "Error creating directory:" << auction_base_path
                  << "ASSET/" << std::endl;
        return ERROR_CODE;
    }

    if (!std::filesystem::create_directory(auction_base_path + "BIDS/")) {
        std::cerr << "Error creating directory:" << auction_base_path << "BIDS/"
                  << std::endl;
        return ERROR_CODE;
    }

    const std::string user_auction_path = "./DATABASE/USERS/" + uid + "/HOSTED/" + aid + ".txt";
    std::ofstream user_auction_file(user_auction_path);

    if (!user_auction_file.is_open()) {
        std::cerr << "Failed to open the file " << user_auction_path << std::endl;
        return ERROR_CODE;
    }
    user_auction_file.close();

    return SUCCESS_CODE;
}

int auction_store_asset(std::string aid, int socket_fd, std::string asset_fname,
                        std::string asset_fsize) {
    const std::string asset_base_path =
        "./DATABASE/AUCTIONS/" + aid + "/ASSET/";

    if (auction_exists(aid) == FALSE) {
        return ERR_AUCTION_DOESNT_EXIST;
    }

    std::ofstream asset_file(asset_base_path + asset_fname);
    if (!asset_file.is_open()) {
        std::cout << "Failed to open the file " << asset_base_path
                  << asset_fname << std::endl;
        return ERROR_CODE;
    }

    char fdata_buffer[512];
    ssize_t n;
    ssize_t nleft = (ssize_t)std::stoi(asset_fsize);
    while (nleft > 0) {
        n = _read(socket_fd, fdata_buffer, 512);
        if (n == -1) {
            std::cout << "ERROR: couldn't read from TCP socket" << std::endl;
            return ERROR_CODE;
        }

        // in the last read, the '\n' will be included, but it isn't part of
        // the file
        ssize_t n_to_write = nleft < n ? nleft : n;
        asset_file.write(fdata_buffer, n_to_write);
        nleft -= n_to_write;
    }

    asset_file.close();

    return SUCCESS_CODE;
}

int auction_send_asset(std::string aid, int socket_fd, std::string asset_fname,
                        ssize_t asset_fsize) {
    const std::string asset_path =
        "./DATABASE/AUCTIONS/" + aid + "/ASSET/" + asset_fname;

    if (auction_exists(aid) == FALSE) {
        return ERR_AUCTION_DOESNT_EXIST;
    }

    std::ifstream asset_file(asset_path);
    if (!asset_file.is_open()) {
        std::cout << "Failed to open the file " << asset_path << std::endl;
        return ERROR_CODE;
    }

    char fdata_buffer[512];
    ssize_t n;
    ssize_t nleft = asset_fsize;
    while (nleft > 0) {
        ssize_t n_to_write = nleft < 512 ? nleft : 512;
        asset_file.read(fdata_buffer, n_to_write);
        nleft -= n_to_write;

        n = _write(socket_fd, fdata_buffer, (size_t)n_to_write);
        if (n == -1) {
            std::cout << "ERROR: couldn't write to TCP socket" << std::endl;
            return ERROR_CODE;
        }
    }

    asset_file.close();

    return SUCCESS_CODE;
}

int auction_exists(std::string aid) {
    if (std::filesystem::exists("./DATABASE/AUCTIONS/" + aid + "/")) {
        return TRUE;
    }
    return FALSE;
}

int auction_close(std::string aid) {
    const std::string auction_base_path = "./DATABASE/AUCTIONS/" + aid + "/";

    if (auction_exists(aid) == FALSE) {
        return ERR_AUCTION_DOESNT_EXIST;
    }

    if (auction_is_closed(aid) == TRUE) {
        return ERR_AUCTION_ALREADY_CLOSED;
    }

    time_t end_fulltime;
    time(&end_fulltime);
    std::string end_datetime = get_date(end_fulltime);

    auction_struct auction;
    if (auction_get_info(aid, &auction) != SUCCESS_CODE) {
        return ERROR_CODE;
    }

    const time_t end_sec_time = end_fulltime - auction.start_fulltime;

    std::ofstream end_file(auction_base_path + "END_" + aid + ".txt");
    if (!end_file.is_open()) {
        std::cout << "Failed to open the file " << auction_base_path << "END_"
                  << aid << ".txt" << std::endl;
        return ERROR_CODE;
    }

    if (end_sec_time > auction.timeactive) {
        time_t default_end_sec_time =
            auction.start_fulltime + auction.timeactive;
        const std::string default_end_date = get_date(default_end_sec_time);

        end_file << default_end_date << " "
                 << default_end_sec_time - auction.start_fulltime;
    } else {
        end_file << end_datetime << " " << end_sec_time;
    }

    end_file.close();

    return SUCCESS_CODE;
}

int auction_is_closed(std::string aid) {
    if (auction_exists(aid) == TRUE) {
        if (std::filesystem::exists("./DATABASE/AUCTIONS/" + aid + "/END_" +
                                    aid + ".txt")) {
            return TRUE;
        }
        return FALSE;
    }
    return ERR_AUCTION_DOESNT_EXIST;
}
