#include <iostream>
#include <string>

#include "common.hpp"
#include "database.hpp"

int main() {
    init();

    std::cout << auction_count() << std::endl;

    return 0;
}