#include "user.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

/*
hints - Estrutura que contém informações sobre o tipo de conexão que será
estabelecida. Podem-se considerar, literalmente, dicas para o sistema
operacional sobre como deve ser feita a conexão, de forma a facilitar a
aquisição ou preencher dados.

res - Localização onde a função getaddrinfo() armazenará informações sobre o
endereço.
*/
struct addrinfo hints, *res;

std::string uid, password;
bool logged_in = false;

int main(int argc, char** argv) {
    std::string as_ip = "localhost";
    std::string as_port = "58058";

    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "-n" && argc > i + 1) {
            as_ip = std::string(argv[i + 1]);
            i++;  // Skip the next argument
        } else if (std::string(argv[i]) == "-p" && argc > i + 1) {
            as_port = std::string(argv[i + 1]);
            i++;  // Skip the next argument
        } else {
            // Handle unknown or incorrectly formatted arguments
            std::cerr << "Usage: " << argv[0] << " [-n ASIP] [-p ASport]"
                      << std::endl;
            return 1;
        }
    }

    /* Cria um socket UDP (SOCK_DGRAM) para IPv4 (AF_INET).
    É devolvido um descritor de ficheiro (fd) para onde se deve comunicar. */
    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd == -1) {
        exit(1);
    }

    /* Preenche a estrutura com 0s e depois atribui a informação já conhecida da
     * ligação */
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;  // IPv4
    hints.ai_socktype = 0;      // socket of any type

    /* Busca informação do host "localhost", na porta especificada,
    guardando a informação nas `hints` e na `res`. Caso o host seja um nome
    e não um endereço IP (como é o caso), efetua um DNS Lookup. */
    int errcode = getaddrinfo(as_ip.c_str(), as_port.c_str(), &hints, &res);
    if (errcode != 0) {
        exit(1);
    }

    while (true) {
        // char command[CMD_SIZE + 1];
        // if (fgets(command, CMD_SIZE + 1, STDIN_FILENO) == NULL) {
        //     exit(-1);
        // }
        // std::string cmd = std::string(command);

        std::cout << "> ";
        std::string cmd, msg;
        std::cin >> cmd;

        if (cmd == "login") {
            // char buffer[CMD_SIZE + UID_SIZE + PASSWORD_SIZE + 3];
            // memcpy(buffer, command, CMD_SIZE);
            // buffer[CMD_SIZE] = ' ';

            // if (getchar() != ' ') {
            //     exit(1);
            // }

            // if (fgets(buffer + CMD_SIZE + 1, UID_SIZE + 1, STDIN_FILENO) ==
            // NULL) {
            //     exit(1);
            // }

            // if (fgets(buffer + CMD_SIZE + UID_SIZE + 2, PASSWORD_SIZE + 1,
            // STDIN_FILENO) == NULL) {
            //     exit(1)
            // }

            std::string temp_uid, temp_password;
            std::cin >> temp_uid >> temp_password;

            if (logged_in) {
                std::cout << "already logged in; to login as a different user, "
                             "please logout first"
                          << std::endl;
                continue;
            }

            if (temp_uid.length() != UID_SIZE ||
                temp_password.length() != PASSWORD_SIZE) {
                std::cout << "invalid arguments" << std::endl;
                continue;
            }

            msg = "LIN " + temp_uid + " " + temp_password + "\n";

            std::string res = udp_request(udp_fd, msg);
            handle_login_response(res, temp_uid, temp_password);
        } else if (cmd == "logout") {
            if (uid == "") {
                std::cout << "you need to perform a successful login first"
                          << std::endl;
                continue;
            }

            msg = "LOU " + uid + " " + password + "\n";

            std::string res = udp_request(udp_fd, msg);
            handle_logout_response(res);
        } else if (cmd == "unregister") {
            if (uid == "") {
                std::cout << "you need to perform a successful login first"
                          << std::endl;
                continue;
            }

            msg = "UNR " + uid + " " + password + "\n";

            std::string res = udp_request(udp_fd, msg);
            handle_unregister_response(res);
        } else if (cmd == "exit") {
            if (logged_in) {
                std::cout << "there's an active login, please logout first"
                          << std::endl;
                continue;
            }

            exit(0);
        } else if (cmd == "open") {
            std::string name, asset_fname, start_value, time_active;
            std::cin >> name >> asset_fname >> start_value >> time_active;

            if (uid == "") {
                std::cout << "you need to perform a successful login first"
                          << std::endl;
                continue;
            }

            size_t idx = asset_fname.find('.');
            if (idx == std::string::npos ||
                asset_fname.substr(0, idx).length() <= 0 ||
                asset_fname.substr(0, idx).length() > 20 ||
                asset_fname.substr(idx + 1).length() != 3) {
                std::cout << "invalid filename" << std::endl;
                continue;
            }

            struct stat stat_buffer;
            if (stat(asset_fname.c_str(), &stat_buffer) == -1) {
                // pathname does not exist
                exit(1);
            }
            size_t fsize = (size_t)stat_buffer.st_size;
            if (fsize > MAX_ASSET_FILE_SIZE_MB * 1000000) {
                std::cout << "file too big, limit is " << MAX_ASSET_FILE_SIZE_MB
                          << " MB" << std::endl;
                continue;
            }

            std::ifstream asset_file(asset_fname);
            if (!asset_file.is_open()) {
                exit(1);
            }

            std::vector<char> fdata(fsize);
            asset_file.read(fdata.data(), fsize);

            std::string msg = "OPA " + uid + " " + password + " " + name + " " +
                              start_value + " " + time_active + " " +
                              asset_fname + " " + std::to_string(fsize) + " ";

            msg.insert(msg.end(), fdata.begin(), fdata.end());
            msg += "\n";

            std::string res = tcp_request(msg);
            handle_open_response(res);
        } else if (cmd == "close") {
            std::string aid;
            std::cin >> aid;

            if (uid == "") {
                std::cout << "you need to perform a successful login first"
                          << std::endl;
                continue;
            }

            if (aid.length() != AID_SIZE) {
                std::cout << "invalid arguments" << std::endl;
                continue;
            }

            msg = "CLS " + uid + " " + password + " " + aid + "\n";

            std::string res = tcp_request(msg);
            handle_close_response(res);
        } else if (cmd == "myauctions" || cmd == "ma") {
            if (uid == "") {
                std::cout << "you need to perform a successful login first"
                          << std::endl;
                continue;
            }

            msg = "LMA " + uid + "\n";

            std::string res = udp_request(udp_fd, msg);
            handle_myauctions_response(res);
        } else if (cmd == "mybids" || cmd == "mb") {
            if (uid == "") {
                std::cout << "you need to perform a successful login first"
                          << std::endl;
                continue;
            }

            msg = "LMB " + uid + "\n";

            std::string res = udp_request(udp_fd, msg);
            handle_mybids_response(res);
        } else if (cmd == "list" || cmd == "l") {
            msg = "LST\n";

            std::string res = udp_request(udp_fd, msg);
            handle_list_response(res);
        } else if (cmd == "show_asset" || cmd == "sa") {
            std::string aid;
            std::cin >> aid;

            if (aid.length() != AID_SIZE) {
                std::cout << "invalid arguments" << std::endl;
                continue;
            }

            msg = "SAS " + aid + "\n";

            handle_show_asset_request(msg);
        } else if (cmd == "bid" || cmd == "b") {
            std::string aid, value;
            std::cin >> aid >> value;

            if (uid == "") {
                std::cout << "you need to perform a successful login first"
                          << std::endl;
                continue;
            }

            if (aid.length() != AID_SIZE) {
                std::cout << "invalid arguments" << std::endl;
                continue;
            }

            msg =
                "BID " + uid + " " + password + " " + aid + " " + value + "\n";

            std::string res = tcp_request(msg);
            handle_bid_response(res);
        } else if (cmd == "show_record" || cmd == "sr") {
            std::string aid;
            std::cin >> aid;

            if (aid.length() != AID_SIZE) {
                std::cout << "invalid arguments" << std::endl;
                continue;
            }

            msg = "SRC " + aid + "\n";

            std::string res = udp_request(udp_fd, msg);
            handle_show_record_response(res);
        } else {
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "unknown command" << std::endl;
        }
    }

    /* Desaloca a memória da estrutura `res` e fecha o socket */
    freeaddrinfo(res);
    close(udp_fd);

    return 0;
}

std::string udp_request(int socket_fd, std::string& msg) {
    /* Envia para o `fd` (socket) a mensagem "Hello!\n" com o tamanho 7.
       Não são passadas flags (0), e é passado o endereço de destino.
       É apenas aqui criada a ligação ao servidor. */
    ssize_t n = sendto(socket_fd, msg.c_str(), msg.length(), 0, res->ai_addr,
                       res->ai_addrlen);
    if (n == -1) {
        exit(1);
    }

    std::cout << "sent: " << msg;

    /* Recebe 128 Bytes do servidor e guarda-os no buffer.
       As variáveis `addr` e `addrlen` não são usadas pois não foram
       inicializadas. */
    // char buffer[128];
    char buffer[65536];
    std::string res;

    while (true) {
        n = recvfrom(socket_fd, buffer, 65536, 0, NULL, NULL);
        if (n == -1) {
            exit(1);
        }

        std::string buffer_str = std::string(buffer);
        if (buffer_str.find('\n') == std::string::npos) {
            res += buffer_str;
        } else {
            res += buffer_str.substr(0, buffer_str.find('\n') + 1);
            break;
        }
    }

    std::cout << "received: " << res;

    return res;
}

std::string tcp_request(std::string& msg) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        exit(1);
    }

    /* Em TCP é necessário estabelecer uma ligação com o servidor primeiro
       (Handshake). Então primeiro cria a conexão para o endereço obtido através
       de `getaddrinfo()`. */
    ssize_t n = connect(fd, res->ai_addr, res->ai_addrlen);
    if (n == -1) {
        exit(1);
    }

    /* Escreve a mensagem "Hello!\n" para o servidor, especificando o seu
     * tamanho */
    n = write(fd, msg.c_str(), msg.length());
    if (n == -1) {
        exit(1);
    }
    std::cout << "sent: " << msg;

    char buffer[128];
    std::string res;
    /* Lê 128 Bytes do servidor e guarda-os no buffer. */
    while (true) {
        n = read(fd, buffer, 128);
        if (n == -1) {
            exit(1);
        }

        std::string buffer_str = std::string(buffer);
        if (buffer_str.find('\n') == std::string::npos) {
            res += buffer_str;
        } else {
            res += buffer_str.substr(0, buffer_str.find('\n') + 1);
            break;
        }
    }

    std::cout << "received: " << res;

    /* Desaloca a memória da estrutura `res` e fecha o socket */
    // freeaddrinfo(res);
    close(fd);

    return res;
}

void handle_login_response(std::string& res, std::string& uid_,
                           std::string& password_) {
    if (res == "RLI OK\n") {
        std::cout << "successful login" << std::endl;
        logged_in = true;
        uid = uid_;
        password = password_;
    } else if (res == "RLI NOK\n") {
        std::cout << "incorrect login attempt" << std::endl;
    } else if (res == "RLI REG\n") {
        std::cout << "new user registered" << std::endl;
        logged_in = true;
        uid = uid_;
        password = password_;
    } else {
        std::cout << "ERR: unable to login" << std::endl;
    }
}

void handle_logout_response(std::string& res) {
    if (res == "RLO OK\n") {
        std::cout << "successful logout" << std::endl;
        logged_in = false;
    } else if (res == "RLO NOK\n") {
        std::cout << "user not logged in" << std::endl;
    } else if (res == "RLO UNR\n") {
        std::cout << "unknown user" << std::endl;
    } else {
        std::cout << "ERR: unable to logout" << std::endl;
    }
}

void handle_unregister_response(std::string& res) {
    if (res == "RUR OK\n") {
        std::cout << "successful unregister" << std::endl;
        logged_in = false;
    } else if (res == "RUR NOK\n") {
        std::cout << "incorrect unregister attempt" << std::endl;
    } else if (res == "RUR UNR\n") {
        std::cout << "unknown user" << std::endl;
    } else {
        std::cout << "ERR: unable to unregister" << std::endl;
    }
}

void handle_open_response(std::string& res) {
    if (res.substr(0, res.find("OK") + 2) == "ROA OK") {
        std::string aid = res.substr(res.find("OK") + 3, 3);
        std::cout << "auction successfully opened with ID " << aid << std::endl;
    } else if (res == "ROA NOK\n") {
        std::cout << "couldn't start auction" << std::endl;
    } else if (res == "ROA NLG\n") {
        std::cout << "user not logged in" << std::endl;
    } else {
        std::cout << "ERR: unable to open a new auction" << std::endl;
    }
}

void handle_close_response(std::string& res) {
    if (res == "RCL OK\n") {
        std::cout << "auction successfully closed" << std::endl;
    } else if (res == "RCL EAU\n") {
        std::cout << "auction doesn't exist" << std::endl;
    } else if (res == "RCL EOW\n") {
        std::cout << "auctions can only be closed by the owners" << std::endl;
    } else if (res == "RCL END\n") {
        std::cout << "auction is already closed" << std::endl;
    } else if (res == "RCL NLG\n") {
        std::cout << "user not logged in" << std::endl;
    } else {
        std::cout << "ERR: unable to close the auction" << std::endl;
    }
}

void handle_myauctions_response(std::string& res) {
    if (res.substr(0, res.find("OK") + 2) == "RMA OK") {
        std::string auctions = res.substr(res.find("OK") + 3);
        std::istringstream auctions_stream(auctions);

        std::string aid, state;
        while (auctions_stream >> aid >> state) {
            std::cout << "auction " << aid
                      << (state == "1" ? " (open)" : " (closed)") << std::endl;
        }
    } else if (res == "RMA NOK\n") {
        std::cout << "you have no ongoing auctions" << std::endl;
    } else if (res == "RMA NLG\n") {
        std::cout << "user not logged in" << std::endl;
    } else {
        std::cout << "ERR: unable to list your auctions" << std::endl;
    }
}

void handle_mybids_response(std::string& res) {
    if (res.substr(0, res.find("OK") + 2) == "RMB OK") {
        std::string auctions = res.substr(res.find("OK") + 3);
        std::istringstream auctions_stream(auctions);

        std::string aid, state;
        while (auctions_stream >> aid >> state) {
            std::cout << "auction " << aid
                      << (state == "1" ? " (open)" : " (closed)") << std::endl;
        }
    } else if (res == "RMB NOK\n") {
        std::cout << "you have no ongoing bids" << std::endl;
    } else if (res == "RMB NLG\n") {
        std::cout << "user not logged in" << std::endl;
    } else {
        std::cout << "ERR: unable to list your bids" << std::endl;
    }
}

void handle_list_response(std::string& res) {
    if (res.substr(0, res.find("OK") + 2) == "RLS OK") {
        std::string auctions = res.substr(res.find("OK") + 3);
        std::istringstream auctions_stream(auctions);

        std::string aid, state;
        while (auctions_stream >> aid >> state) {
            std::cout << "auction " << aid
                      << (state == "1" ? " (open)" : " (closed)") << std::endl;
        }
    } else if (res == "RLS NOK\n") {
        std::cout << "there are no ongoing auctions" << std::endl;
    } else {
        std::cout << "ERR: unable to list ongoing auctions" << std::endl;
    }
}

void handle_show_asset_request(std::string& msg) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        exit(1);
    }

    /* Em TCP é necessário estabelecer uma ligação com o servidor primeiro
       (Handshake). Então primeiro cria a conexão para o endereço obtido através
       de `getaddrinfo()`. */
    ssize_t n = connect(fd, res->ai_addr, res->ai_addrlen);
    if (n == -1) {
        exit(1);
    }

    /* Escreve a mensagem "Hello!\n" para o servidor, especificando o seu
     * tamanho */
    n = write(fd, msg.c_str(), msg.length());
    if (n == -1) {
        exit(1);
    }
    std::cout << "sent: " << msg;

    char res_status_buffer[7];

    n = read(fd, res_status_buffer, 7);
    if (n == -1) {
        exit(1);
    }

    std::string res = std::string(res_status_buffer);

    std::cout << "received: " << res;

    if (res == "RSA OK ") {
        char file_info_buffer[MAX_FNAME_SIZE + MAX_FSIZE_SIZE + 2];

        n = read(fd, file_info_buffer, sizeof(file_info_buffer));
        if (n == -1) {
            exit(1);
        }

        std::string fname, fsize;
        std::string file_info = std::string(file_info_buffer);
        std::istringstream file_info_stream(file_info);

        file_info_stream >> fname >> fsize;
        std::cout << fname << " " << fsize << std::endl;

        int fdata_idx = fsize.length() + fname.length() + 2;
        size_t fdata_portion_size;
        if (sizeof(file_info_buffer) - fdata_idx >= std::stoi(fsize)) {
            fdata_portion_size = std::stoi(fsize);
        } else {
            fdata_portion_size = sizeof(file_info_buffer) - fdata_idx;
        }
        char fdata_portion[fdata_portion_size];
        memcpy(fdata_portion, file_info.c_str() + fdata_idx,
               sizeof(fdata_portion));

        std::ofstream asset_file(fname);
        if (!asset_file.is_open()) {
            exit(1);
        }
        asset_file.write(fdata_portion, sizeof(fdata_portion));

        char fdata_buffer[512];
        ssize_t nleft = std::stoi(fsize) - sizeof(fdata_portion);
        while (nleft > 0) {
            n = read(fd, fdata_buffer, 512);
            if (n == -1) {
                exit(1);
            }

            size_t n_to_write = nleft < n ? nleft : n;
            asset_file.write(fdata_buffer, n_to_write);
            nleft -= n_to_write;
        }

        asset_file.close();
        std::cout << "asset saved in ./" << fname << std::endl;

        close(fd);
    } else if (res == "RSA NOK") {
        std::cout << "there's no file associated with the auction or some "
                     "internal error occurred"
                  << std::endl;
    } else {
        std::cout << "ERR: unable to download the asset" << std::endl;
    }
}

void handle_bid_response(std::string& res) {
    if (res == "RBD ACC\n") {
        std::cout << "bid registered successfully" << std::endl;
    } else if (res == "RBD REF\n") {
        std::cout << "there's already been placed a higher bid" << std::endl;
    } else if (res == "RBD NOK\n") {
        std::cout << "auction no longer active" << std::endl;
    } else if (res == "RBD NLG\n") {
        std::cout << "user not logged in" << std::endl;
    } else if (res == "RBD ILG\n") {
        std::cout << "you can't bid on your own auction" << std::endl;
    } else {
        std::cout << "ERR: unable to bid" << std::endl;
    }
}

void handle_show_record_response(std::string& res) {
    if (res.substr(0, res.find("OK") + 2) == "RRC OK") {
        std::string record = res.substr(res.find("OK") + 3);
        std::istringstream record_stream(record);

        std::string host_uid, auction_name, asset_fname, start_value,
            start_date, start_time, time_active;
        record_stream >> host_uid >> auction_name >> asset_fname >>
            start_value >> start_date >> start_time >> time_active;

        std::cout << auction_name << " - hosted by " << host_uid << std::endl;
        std::cout << "asset filename: " << asset_fname << std::endl;
        std::cout << "start value: " << start_value << std::endl;
        std::cout << "started at: " << start_date << " " << start_time
                  << std::endl;
        std::cout << "duration: " << time_active << " seconds" << std::endl;

        char next_char = record_stream.get();

        if (next_char == '\n') return;

        next_char = record_stream.get();

        if (next_char == 'B') {
            std::cout << std::endl;
        }
        while (next_char == 'B') {
            std::string bidder_uid, bid_value, bid_date, bid_time, bid_sec_time;
            record_stream >> bidder_uid >> bid_value >> bid_date >> bid_time >>
                bid_sec_time;

            std::cout << bid_value << " bid by user " << bidder_uid << " at "
                      << bid_date << " " << bid_time << " (" << bid_sec_time
                      << " seconds elapsed)" << std::endl;

            next_char = record_stream.get();
            if (next_char != '\n') next_char = record_stream.get();
        }

        if (next_char == 'E') {
            std::string end_date, end_time, end_sec_time;
            record_stream >> end_date >> end_time >> end_sec_time;

            std::cout << "\nauction ended at " << end_date << " " << end_time
                      << " (" << end_sec_time << " seconds elapsed)"
                      << std::endl;
        }
    } else if (res == "RRC NOK\n") {
        std::cout << "there's no auction with the given id" << std::endl;
    } else {
        std::cout << "ERR: unable to list ongoing auctions" << std::endl;
    }
}
