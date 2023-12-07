#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include <iostream>
#include <string>

#include "common.hpp"
#include "database.hpp"

int main() {
    db_init();

    int status_code;

    status_code = user_create("103392", "123456");
    if (status_code != SUCCESS_CODE) {
        std::cerr << "Error creating user" << std::endl;
        return ERROR_CODE;
    }

    status_code = user_create("102802", "123456");
    if (status_code != SUCCESS_CODE) {
        std::cerr << "Error creating user" << std::endl;
        return ERROR_CODE;
    }

    status_code = user_create("123456", "123456");
    if (status_code != SUCCESS_CODE) {
        std::cerr << "Error creating user" << std::endl;
        return ERROR_CODE;
    }

        std::string aid;
    for (int i = 1; i < 10 + 1; i++) {
        status_code = auction_create(aid, "103392", "BMW", "bmw.jpg", 0, i);
        if (status_code != SUCCESS_CODE) {
            std::cerr << "Error creating auction" << std::endl;
            return ERROR_CODE;
        }

        if (i % 2 == 0) {
            status_code = bid_create(aid, "102802", i);
            if (status_code != SUCCESS_CODE) {
                std::cerr << "3 Error creating bid" << std::endl;
                return ERROR_CODE;
            }
        } else {
            status_code = bid_create(aid, "123456", i);
            if (status_code != SUCCESS_CODE) {
                std::cerr << "3 Error creating bid" << std::endl;
                return ERROR_CODE;
            }
        }
    }

    std::vector<auction_struct> bidded_auctions;
    status_code = user_bidded_auctions("123456", bidded_auctions);
    if (status_code != SUCCESS_CODE) {
        std::cerr << "Error getting user bidded_auctions" << std::endl;
        return ERROR_CODE;
    }

    std::cout << "User bidded_auctions: "
              << "123456" << std::endl;
    for (auto auction : bidded_auctions) {
        std::cout << auction.aid << " "
                  << (auction.end_sec_time == -1 ? "(open)" : "(closed)")
                  << std::endl;
    }

    std::vector<auction_struct> bidded_auctions_2;
    status_code = user_bidded_auctions("102802", bidded_auctions_2);
    if (status_code != SUCCESS_CODE) {
        std::cerr << "Error getting user bidded_auctions_2" << std::endl;
        return ERROR_CODE;
    }

    std::cout << "User bidded_auctions_2: "
              << "102802" << std::endl;
    for (auto auction_2 : bidded_auctions_2) {
        std::cout << auction_2.aid << " "
                  << (auction_2.end_sec_time == -1 ? "(open)" : "(closed)")
                  << std::endl;
    }

    std::vector<bid_struct> bids;
    status_code = auction_bids("999", bids);
    if (status_code != ERR_AUCTION_DOESNT_EXIST) {
        std::cerr << "Error getting auction bids" << std::endl;
        return ERROR_CODE;
    }

    sleep(5);

    std::vector<auction_struct> auctions_2;
    status_code = user_bidded_auctions("102802", auctions_2);
    if (status_code != SUCCESS_CODE) {
        std::cerr << "Error getting auction bids" << std::endl;
        return ERROR_CODE;
    }

    for (auto auction : auctions_2) {
        std::cout << auction.aid << " "
                  << (auction.end_sec_time == -1 ? "(open)" : "(closed)")
                  << std::endl;
    }

    std::vector<auction_struct> auctions_3;
    status_code = user_bidded_auctions("123456", auctions_3);
    if (status_code != SUCCESS_CODE) {
        std::cerr << "Error getting auction bids" << std::endl;
        return ERROR_CODE;
    }

    for (auto auction : auctions_3) {
        std::cout << auction.aid << " "
                  << (auction.end_sec_time == -1 ? "(open)" : "(closed)")
                  << std::endl;
    }

    return 0;
}