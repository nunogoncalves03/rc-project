#include <iostream>
#include <string>

#include "common.hpp"
#include "database.hpp"
#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    init();

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
    
    status_code = user_create("102802", "123456");
    if (status_code != SUCCESS_CODE) {
        std::cerr << "Error creating user" << std::endl;
        return ERROR_CODE;
    }

    std::string aid;
    status_code = auction_create(aid, "103392", "BMW", "bmw.jpg", 100, 10);
    if (status_code != SUCCESS_CODE) {
        std::cerr << "Error creating auction" << std::endl;
        return ERROR_CODE;
    }

    status_code = auction_get_info(aid, &auction);
    std::cout << "Auction info:" << std::endl;
    std::cout << "aid: " << auction.aid << std::endl;
    std::cout << "uid: " << auction.uid << std::endl;
    std::cout << "name: " << auction.name << std::endl;
    std::cout << "asset_fname: " << auction.asset_fname << std::endl;
    std::cout << "asset_fsize: " << auction.asset_fsize << std::endl;
    std::cout << "start_value: " << auction.start_value << std::endl;
    std::cout << "timeactive: " << auction.timeactive << std::endl;
    std::cout << "start_datetime: " << auction.start_datetime << std::endl;
    std::cout << "start_fulltime: " << auction.start_fulltime << std::endl;
    std::cout << "end_datetime: " << auction.end_datetime << std::endl;
    std::cout << "end_sec_time: " << auction.end_sec_time << std::endl;

    status_code = auction_store_asset(aid, fd, "bmw.jpg", "159123");
    if (status_code != SUCCESS_CODE) {
        std::cerr << "Error storing asset" << std::endl;
        return ERROR_CODE;
    }

    int fd_2 = open("./assets/bmw2.jpg", O_WRONLY | O_CREAT, 0666);
    if (fd_2 == -1) {
        std::cerr << "Error opening file" << std::endl;
        return ERROR_CODE;
    }

    status_code = auction_get_info(aid, &auction);
    std::cout << "Auction info:" << std::endl;
    std::cout << "aid: " << auction.aid << std::endl;
    std::cout << "uid: " << auction.uid << std::endl;
    std::cout << "name: " << auction.name << std::endl;
    std::cout << "asset_fname: " << auction.asset_fname << std::endl;
    std::cout << "asset_fsize: " << auction.asset_fsize << std::endl;
    std::cout << "start_value: " << auction.start_value << std::endl;
    std::cout << "timeactive: " << auction.timeactive << std::endl;
    std::cout << "start_datetime: " << auction.start_datetime << std::endl;
    std::cout << "start_fulltime: " << auction.start_fulltime << std::endl;
    std::cout << "end_datetime: " << auction.end_datetime << std::endl;
    std::cout << "end_sec_time: " << auction.end_sec_time << std::endl;

    status_code = auction_send_asset("999", fd_2, auction.asset_fname, auction.asset_fsize);
    if (status_code != ERR_AUCTION_DOESNT_EXIST) {
        std::cerr << "Error sending asset" << std::endl;
        return ERROR_CODE;
    }

    status_code = auction_send_asset(aid, fd_2, auction.asset_fname, auction.asset_fsize);
    if (status_code != SUCCESS_CODE) {
        std::cerr << "Error sending asset" << std::endl;
        return ERROR_CODE;
    }

    status_code = auction_create(aid, "103392", "BMW", "bmw.jpg", 100, 10);
    if (status_code != SUCCESS_CODE) {
        std::cerr << "Error creating auction" << std::endl;
        return ERROR_CODE;
    }

    status_code = auction_close(aid);
    if (status_code != SUCCESS_CODE) {
        std::cerr << "Error closing auction" << std::endl;
        return ERROR_CODE;
    }

    status_code = auction_create(aid, "102802", "BMW", "bmw.jpg", 100, 10);
    if (status_code != SUCCESS_CODE) {
        std::cerr << "Error creating auction" << std::endl;
        return ERROR_CODE;
    }

    std::vector<auction_struct> auctions_list;
    status_code = auction_list(auctions_list);
    if (status_code != SUCCESS_CODE) {
        std::cerr << "Error listing auctions" << std::endl;
        return ERROR_CODE;
    }

    std::cout << "Auctions list:" << std::endl;
    for (auto x : auctions_list) {
        std::cout << "aid: " << x.aid << std::endl;
        std::cout << "closed: " << (x.end_sec_time != -1 ? "yes" : "no") << std::endl;
    }

    std::vector<auction_struct> auctions_list_2;
    status_code = user_auctions("103392", auctions_list_2);
    if (status_code != SUCCESS_CODE) {
        std::cerr << "Error listing auctions" << std::endl;
        return ERROR_CODE;
    }

    std::cout << "Nuno's list:" << std::endl;
    for (auto x : auctions_list_2) {
        std::cout << "aid: " << x.aid << std::endl;
        std::cout << "closed: " << (x.end_sec_time != -1 ? "yes" : "no") << std::endl;
    }

    std::vector<auction_struct> auctions_list_3;
    status_code = user_auctions("102802", auctions_list_3);
    if (status_code != SUCCESS_CODE) {
        std::cerr << "Error listing auctions" << std::endl;
        return ERROR_CODE;
    }

    std::cout << "Mata's list:" << std::endl;
    for (auto x : auctions_list_3) {
        std::cout << "aid: " << x.aid << std::endl;
        std::cout << "closed: " << (x.end_sec_time != -1 ? "yes" : "no") << std::endl;
    }

    status_code = user_auctions("999", auctions_list_3);
    if (status_code != ERR_USER_DOESNT_EXIST) {
        std::cerr << "Error listing auctions" << std::endl;
        return ERROR_CODE;
    }

    return 0;
}