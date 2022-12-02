#ifndef SERVER_H
#define SERVER_H

#include "cryptosystems.h"
#include <iostream>
#include <thread>
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment (lib, "ws2_32.lib")
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <unistd.h>
#endif

const int RSA_KEY_SIZE = 256;
const int BUFFER_SIZE = 2048;

class Server {
public:
    Server() : rsa(), aes() {}

    int initialize() {
        #ifdef _WIN32
            if (WSAStartup(MAKEWORD(2,2), &wsa) != 0)
            {
                std::cout << std::endl << "Failed to initailize Winsock. Error Code: " << WSAGetLastError() << std::endl;
                return 1;
            }
        #endif
        
        std::cout << "Creating socket... ";
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            std::cout << std::endl << "Could not create socket. " << std::endl;
            return 1;
        }

        std::cout << "done" << std::endl;
        
        // prepare the sockaddr_in structure
        memset((char*) &server, 0, sizeof(server));
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = INADDR_ANY;
        server.sin_port = htons(8080);
        
        // bind the socket
        std::cout << "Binding socket... ";
        if (bind(sock, (struct sockaddr*) &server, sizeof(server)) < 0)
        {
            std::cout << "bind failed." << std::endl;
            return 1;
        }
        
        std::cout << "done" << std::endl;

        // listen for incoming connections
        std::cout << "Set socket to listening... ";
        if (listen(sock, 1) < 0) {
            std::cout << "listen failed." << std::endl;
            return 1;
        }

        std::cout << "done" << std::endl;

        return 0;
    }

    int execute() {
        std::cout << "Waiting for client... ";

        int c = sizeof(struct sockaddr_in);

        if ((new_socket = accept(sock, (struct sockaddr*) &client, (socklen_t*) &c)) < 0)
        {
            std::cout << "accept failed." << std::endl;
            return 1;
        }
        
        std::cout << "connected" << std::endl;

        // read in client public key for RSA encryption
        std::cout << "Reading client public key... ";

        int len = 0;
        while (len < RSA_KEY_SIZE + 5) {
            len += recv(new_socket, buffer + len, BUFFER_SIZE - len, 0);
            if (len < 0) {
                std::cout << std::endl << "Error reading client public key." << std::endl;
                return 1;
            }
        }

        buffer[len] = '\0';
        std::string key(buffer);
        std::string n = "0x" + key.substr(0, RSA_KEY_SIZE);
        std::string e = "0x" + key.substr(RSA_KEY_SIZE);
        std::cout << "done" << std::endl;

        std::cout << "Encrypting and sending AES symmetric key... ";
        rsa.initialize(n, e);

        std::string symmetricKey = rsa.encrypt(aes.getKey());
        std::string iv = rsa.encrypt(aes.getIV());
        std::string dataToSend = symmetricKey + iv;
        // std::cout << std::endl << "Key: " << aes.getKey();
        // std::cout << std::endl << "Encrypted Key: " << symmetricKey;
        // std::cout << std::endl << "IV: " << aes.getIV();
        // std::cout << std::endl << "Encrypted IV: " << iv << std::endl;

        // send symmetric key and iv
        if (send(new_socket, dataToSend.c_str(), dataToSend.length(), 0) < 0)
        {
            std::cout << std::endl << "Error sending symmetric key" << std::endl;
            return 1;
        }

        std::cout << "done" << std::endl << std::endl;

        // communication loop
        std::thread sendThread([this]() {
			while (true) {
				std::string message;

				while (message == "") {
					std::getline(std::cin, message);
				}

				message = aes.encrypt(message);

				if (send(new_socket, message.c_str(), message.length(), 0) < 0)
				{
					std::cout << std::endl << "Error sending message" << std::endl;
					return 1;
				}
			}
		});

        while (true) {
            len = recv(new_socket, buffer, BUFFER_SIZE, 0);
            if (len < 0) {
                std::cout << std::endl << "Error reading client message." << std::endl;
                return 1;
            }

            buffer[len] = '\0';
            std::string ciphertext(buffer);
            std::string plaintext(aes.decrypt(buffer, len));

            std::cout << "[Client] " << plaintext << std::endl;
        }

        #ifdef _WIN32
            closesocket(sock);
            closesocket(new_socket);
            WSACleanup();
        #else
            close(sock);
            close(new_socket);
        #endif

        return 0;
    }

private:
    // member variables
    RSASystem rsa;
    AESSystem aes;

    #ifdef _WIN32
    WSADATA wsa;
    #endif
    struct sockaddr_in server, client;
    int sock, new_socket;
    char buffer[BUFFER_SIZE];
};

#endif // SERVER_H
