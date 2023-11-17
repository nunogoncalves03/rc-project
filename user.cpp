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
#include <string>

int fd, errcode;
ssize_t n;
socklen_t addrlen;  // Tamanho do endereço
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
char buffer[128];  // buffer para onde serão escritos os dados recebidos do
                   // servidor

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
    fd = socket(AF_INET, SOCK_DGRAM, 0);
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
    errcode =
        getaddrinfo("tejo.tecnico.ulisboa.pt", as_port.c_str(), &hints, &res);
    if (errcode != 0) {
        exit(1);
    }

    std::string uid, password;

    while (true) {
        // char command[CMD_SIZE + 1];
        // if (fgets(command, CMD_SIZE + 1, STDIN_FILENO) == NULL) {
        //     exit(-1);
        // }
        // std::string cmd = std::string(command);

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

            std::cin >> uid >> password;

            if (uid.length() != UID_SIZE ||
                password.length() != PASSWORD_SIZE) {
                std::cout << "invalid arguments" << std::endl;
                exit(1);
            }

            msg = "LIN " + uid + " " + password + "\n";
        } else if (cmd == "unregister") {
            msg = "UNR " + uid + " " + password + "\n";
        } else {
            exit(1);
        }

        /* Envia para o `fd` (socket) a mensagem "Hello!\n" com o tamanho 7.
           Não são passadas flags (0), e é passado o endereço de destino.
           É apenas aqui criada a ligação ao servidor. */
        n = sendto(fd, msg.c_str(), msg.length(), 0, res->ai_addr,
                   res->ai_addrlen);
        if (n == -1) {
            exit(1);
        }

        std::cout << "sent: " << msg;

        /* Recebe 128 Bytes do servidor e guarda-os no buffer.
           As variáveis `addr` e `addrlen` não são usadas pois não foram
           inicializadas. */
        addrlen = sizeof(addr);
        n = recvfrom(fd, buffer, 128, 0, (struct sockaddr*)&addr, &addrlen);
        if (n == -1) {
            exit(1);
        }

        /* Imprime a mensagem "echo" e o conteúdo do buffer (ou seja, o que foi
        recebido do servidor) para o STDOUT (fd = 1) */
        std::string res = std::string(buffer);
        res = res.substr(0, res.find("\n") + 1);
        std::cout << "received: " << res;

        if (res == "RLI OK\n")
            std::cout << "successful login" << std::endl;
        else if (res == "RLI NOK\n")
            std::cout << "incorrect login attempt" << std::endl;
        else if (res == "RLI REG\n")
            std::cout << "new user registered" << std::endl;
    }

    /* Desaloca a memória da estrutura `res` e fecha o socket */
    freeaddrinfo(res);
    close(fd);

    return 0;
}
