#include "user.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>

/*
hints - Estrutura que contém informações sobre o tipo de conexão que será
estabelecida. Podem-se considerar, literalmente, dicas para o sistema
operacional sobre como deve ser feita a conexão, de forma a facilitar a
aquisição ou preencher dados.

res - Localização onde a função getaddrinfo() armazenará informações sobre o
endereço.
*/
struct addrinfo hints, *res;
struct sockaddr_in addr;

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
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        exit(1);
    }

    /* Preenche a estrutura com 0s e depois atribui a informação já conhecida da
     * ligação */
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;       // IPv4
    hints.ai_socktype = SOCK_DGRAM;  // UDP socket

    /* Busca informação do host "localhost", na porta especificada,
    guardando a informação nas `hints` e na `res`. Caso o host seja um nome
    e não um endereço IP (como é o caso), efetua um DNS Lookup. */
    int errcode =
        getaddrinfo("tejo.tecnico.ulisboa.pt", as_port.c_str(), &hints, &res);
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

            if (logged_in) {
                std::cout << "already logged in; to login as a different user, "
                             "please logout first"
                          << std::endl;
                continue;
            }

            std::cin >> uid >> password;

            if (uid.length() != UID_SIZE ||
                password.length() != PASSWORD_SIZE) {
                std::cout << "invalid arguments" << std::endl;
                continue;
            }

            msg = "LIN " + uid + " " + password + "\n";

            std::string res = udp_request(fd, msg);
            handle_login_response(res);
        } else if (cmd == "logout") {
            msg = "LOU " + uid + " " + password + "\n";

            std::string res = udp_request(fd, msg);
            handle_logout_response(res);
        } else if (cmd == "unregister") {
            msg = "UNR " + uid + " " + password + "\n";

            std::string res = udp_request(fd, msg);
            handle_unregister_response(res);
        } else if (cmd == "exit") {
            if (logged_in) {
                std::cout << "there's an active login, please logout first"
                          << std::endl;
                continue;
            }

            exit(0);
        } else if (cmd == "myauctions" || cmd == "ma") {
            msg = "LMA " + uid + "\n";

            std::string res = udp_request(fd, msg);
            handle_myauctions_response(res);
        } else if (cmd == "mybids" || cmd == "mb") {
            msg = "LMB " + uid + "\n";

            std::string res = udp_request(fd, msg);
            handle_mybids_response(res);
        } else if (cmd == "list" || cmd == "l") {
            msg = "LST\n";

            std::string res = udp_request(fd, msg);
            handle_list_response(res);
        } else {
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "unknown command" << std::endl;
        }
    }

    /* Desaloca a memória da estrutura `res` e fecha o socket */
    freeaddrinfo(res);
    close(fd);

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
    socklen_t addrlen = sizeof(addr);
    std::string res;

    while (true) {
        n = recvfrom(socket_fd, buffer, 65536, 0, (struct sockaddr*)&addr,
                     &addrlen);
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

void handle_login_response(std::string& res) {
    if (res == "RLI OK\n") {
        std::cout << "successful login" << std::endl;
        logged_in = true;
    } else if (res == "RLI NOK\n") {
        std::cout << "incorrect login attempt" << std::endl;
    } else if (res == "RLI REG\n") {
        std::cout << "new user registered" << std::endl;
        logged_in = true;
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
