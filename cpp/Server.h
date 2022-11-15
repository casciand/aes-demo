#ifndef SERVER_H
#define SERVER_H

#include "cryptosystems.h"
#include <iostream>
#include <thread>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment (lib, "ws2_32.lib")

class Server {
public:
    Server() : rsa(), aes() {}

    int initialize() {
        if (WSAStartup(MAKEWORD(2,2), &wsa) != 0)
        {
            std::cout << std::endl << "Failed to initailize Winsock. Error Code: " << WSAGetLastError() << std::endl;
            return 1;
        }
        
        std::cout << "Creating socket... ";
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
        {
            std::cout << std::endl << "Could not create socket: " << WSAGetLastError() << std::endl;
        }

        std::cout << "done" << std::endl;
        
        // prepare the sockaddr_in structure
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = INADDR_ANY;
        server.sin_port = htons(8080);
        
        // bind the socket
        std::cout << "Binding socket... ";
        if (bind(sock, (struct sockaddr*) &server, sizeof(server)) == SOCKET_ERROR)
        {
            std::cout << std::endl << "bind() failed with error code: " << WSAGetLastError() << std::endl;
        }
        
        std::cout << "done" << std::endl;
        
        // listen for incoming connections
        listen(sock, 3);
        std::cout << "Waiting for client... ";

        return 0;
    }

    int execute() {
        int c = sizeof(struct sockaddr_in);

        new_socket = accept(sock, (struct sockaddr *) &client, &c);
        if (new_socket == INVALID_SOCKET)
        {
            std::cout << std::endl << "accept() failed with error code: " << WSAGetLastError() << std::endl;
        }
        
        std::cout << "connected" << std::endl;

        // read in client public key for RSA encryption
        std::cout << "Reading client public key... ";
        int len = recv(new_socket, buffer, 2048, 0);
        if (len == SOCKET_ERROR) {
            std::cout << std::endl << "Error reading client public key." << std::endl;
            return 1;
        }

        buffer[len] = '\0';
        std::string n(buffer);

        len = recv(new_socket, buffer, 2048, 0);
        if (len == SOCKET_ERROR) {
            std::cout << std::endl << "Error reading client public key." << std::endl;
            return 1;
        }

        buffer[len] = '\0';
        std::string e(buffer);
        std::cout << "done" << std::endl;

        std::cout << "Encrypting and sending AES symmetric key... ";
        rsa.initialize(n, e);

        std::string symmetricKey = rsa.encrypt(aes.getKey());
        std::string iv = rsa.encrypt(aes.getIV());
        // std::cout << std::endl << "Key: " << aes.getKey();
        // std::cout << std::endl << "Encrypted Key: " << symmetricKey;
        // std::cout << std::endl << "IV: " << aes.getIV();
        // std::cout << std::endl << "Encrypted IV: " << iv;

        // send symmetric key and iv
        if (send(new_socket, symmetricKey.c_str(), symmetricKey.length(), 0) < 0)
        {
            std::cout << std::endl << "Error sending symmetric key" << std::endl;
            return 1;
        }

        if (send(new_socket, iv.c_str(), iv.length(), 0) < 0)
        {
            std::cout << std::endl << "Error sending initialization vector" << std::endl;
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
            len = recv(new_socket, buffer, 2048, 0);
            if (len == SOCKET_ERROR) {
                std::cout << std::endl << "Error reading client message." << std::endl;
                return 1;
            }

            buffer[len] = '\0';
            std::string ciphertext(buffer);
            std::string plaintext(aes.decrypt(buffer, len));

            std::cout << "[Client] " << plaintext << std::endl;
        }

        closesocket(sock);
        closesocket(new_socket);
        WSACleanup();

        return 0;
    }

private:
    // member variables
    RSASystem rsa;
    AESSystem aes;

    WSADATA wsa;
    struct sockaddr_in server, client;
    SOCKET sock, new_socket;
    char buffer[2048];
};

#endif // SERVER_H
