#include "cryptlib.h"
#include "rsa.h"
#include "rijndael.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"
#include <string>

#include <iostream>
#include <thread>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment (lib, "ws2_32.lib")

using namespace CryptoPP;

const std::string MODULUS = "";
const std::string EXPONENT = "";

class RSASystem {
public:
    // constructor
	RSASystem() : rng(), pubKey() {}

	// initialize
	void initialize(std::string n, std::string e) {
		pubKey.Initialize(Integer(n.c_str()), Integer(e.c_str()));
	}

    // encrypt
    std::string encrypt(const std::string& plaintext) {
		RSAES_OAEP_SHA_Encryptor enc(pubKey);
		std::string ciphertext, encoded;
		HexEncoder encoder(new StringSink(encoded));

		StringSource ss(plaintext, true,
			new PK_EncryptorFilter(rng, enc,
				new StringSink(ciphertext)
			)
		);

		encoder.Put((const byte*) &ciphertext[0], ciphertext.size());
    	encoder.MessageEnd();

		return encoded;
	}

private:
    // member variables
    AutoSeededRandomPool rng;
    RSA::PublicKey pubKey;
};

class AESSystem {
public:
    // constructor
	AESSystem() : key(AES::MAX_KEYLENGTH), iv(AES::BLOCKSIZE) {
		rng.GenerateBlock(key, key.size());
    	rng.GenerateBlock(iv, iv.size());
	}

    // encrypt
	std::string encrypt(const std::string& plaintext) {
		std::string ciphertext, encoded;
		HexEncoder encoder(new StringSink(encoded));

		try {
			CBC_Mode<AES>::Encryption e;
			e.SetKeyWithIV(key, key.size(), iv);

			StringSource s(plaintext, true, 
				new StreamTransformationFilter(e,
					new StringSink(ciphertext)
				)
			);

			encoder.Put((const byte*) &ciphertext[0], ciphertext.size());
    		encoder.MessageEnd();
		} catch(const Exception& e) {
			std::cerr << e.what() << std::endl;
			exit(1);
		}

		return encoded;
	}

    // decrypt
	std::string decrypt(const std::string& ciphertext) {
		std::string plaintext;
		SecByteBlock ciphertextBB(reinterpret_cast<const byte*>(&ciphertext[0]), ciphertext.size());

		try {
			CBC_Mode<AES>::Decryption d;
			d.SetKeyWithIV(key, key.size(), iv);

			StringSource s(ciphertextBB.BytePtr(), ciphertextBB.size(), true, 
				new StreamTransformationFilter(d,
					new StringSink(plaintext)
				)
			);
		} catch(const Exception& e) {
			std::cerr << e.what() << std::endl;
			exit(1);
		}

		return plaintext;
	}

    // getters
	std::string getKey() {
		std::string keyHex;

		StringSource ss(key.BytePtr(), key.size(), true,
			new HexEncoder(
				new StringSink(keyHex)
			)
		);

		return keyHex;
	}

	std::string getIV() {
		std::string ivHex;

		StringSource ss(iv.BytePtr(), iv.size(), true,
			new HexEncoder(
				new StringSink(ivHex)
			)
		);

		return ivHex;
	}

private:
    // member varaibles
	AutoSeededRandomPool rng;
	SecByteBlock key;
	SecByteBlock iv;
};

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
            std::string plaintext(aes.decrypt(ciphertext));

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

int main(int argc, char* argv[]) {
	Server server;
	
	if (server.initialize() != 0) {
		return 1;
	}

	return server.execute();
}
