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
    auction_struct auction;

    int fd = open("./assets/bmw.jpg", O_RDONLY);
    if (fd == -1) {
        std::cerr << "Error opening file" << std::endl;
        return ERROR_CODE;
    }

    status_code = user_create("103392", "123456");
    if (status_code != SUCCESS_CODE) {
        std::cerr << "Error creating user" << std::endl;
        return ERROR_CODE;
    }

    std::string aid;
    status_code = auction_create(aid, "103392", "BMW", "bmw.jpg", 100, 1);
    if (status_code != SUCCESS_CODE) {
        std::cerr << "Error creating auction" << std::endl;
        return ERROR_CODE;
    }

    sleep(2);

    std::vector<auction_struct> auctions_list_2;
    status_code = user_auctions("103392", auctions_list_2);
    if (status_code != SUCCESS_CODE) {
        std::cerr << "Error listing auctions" << std::endl;
        return ERROR_CODE;
    }

    std::cout << "Auctions list:" << std::endl;
    for (auto x : auctions_list_2) {
        std::cout << "aid: " << x.aid << std::endl;
        std::cout << "closed: " << (x.end_sec_time != -1 ? "yes" : "no") <<
        std::endl;
    }

    return 0;
}