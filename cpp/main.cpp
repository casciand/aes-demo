#include "cryptlib.h"
#include "rsa.h"
#include "rijndael.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"

#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment (lib, "ws2_32.lib")

using namespace CryptoPP;

// class to encrypt symmetric key for client/server session
class RSAEncryptor {
public:
    RSAEncryptor(std::string n, std::string e) {
		pubKey.Initialize(Integer(n.c_str()), Integer(e.c_str()));
	}

    std::string encrypt(const std::string& plaintext) {
		RSAES_OAEP_SHA_Encryptor enc(pubKey);
		std::string ciphertext, encoded;
		HexEncoder encoder(new StringSink(encoded));

		StringSource ss(plaintext, true,
			new PK_EncryptorFilter(rng, enc,
				new StringSink(ciphertext)
			) // PK_EncryptorFilter
		); // StringSource

		encoder.Put((const byte*) &ciphertext[0], ciphertext.size());
    	encoder.MessageEnd();

		return encoded;
	}

private:
    // member variables
    AutoSeededRandomPool rng;
    RSA::PublicKey pubKey;

    // helper function
    std::string hexToASCII(const std::string& hex) {
        std::string ascii;

        for (int i = 0; i < hex.length(); i += 2) {
            ascii += (int) std::stoul(hex.substr(i, 2), nullptr, 16);
        }

        return ascii;
    }
};

// class for encrypting and decrypting messages throughout client/server session
class AESSystem {
public:
	AESSystem() : key(AES::MAX_KEYLENGTH), iv(AES::BLOCKSIZE) {
		rng.GenerateBlock(key, key.size());
    	rng.GenerateBlock(iv, iv.size());
	}

	std::string encrypt(const std::string& plaintext) {
		std::string ciphertext;

		try {
			CBC_Mode<AES>::Encryption e;
			e.SetKeyWithIV(key, key.size(), iv);

			StringSource s(plaintext, true, 
				new StreamTransformationFilter(e,
					new StringSink(ciphertext)
				) // StreamTransformationFilter
			); // StringSource
		} catch(const Exception& e) {
			std::cerr << e.what() << std::endl;
			exit(1);
		}

		return ciphertext;
	}

	std::string decrypt(const std::string& ciphertext) {
		std::string plaintext;
		SecByteBlock ciphertextBB(reinterpret_cast<const byte*>(&ciphertext[0]), ciphertext.size());

		try {
			CBC_Mode<AES>::Decryption d;
			d.SetKeyWithIV(key, key.size(), iv);

			StringSource s(ciphertextBB.BytePtr(), ciphertextBB.size(), true, 
				new StreamTransformationFilter(d,
					new StringSink(plaintext)
				) // StreamTransformationFilter
			); // StringSource
		} catch(const Exception& e) {
			std::cerr << e.what() << std::endl;
			exit(1);
		}

		return plaintext;
	}

	std::string getKey() {
		std::string keyHex;

		StringSource ss(key.BytePtr(), key.size(), true,
			new HexEncoder(
				new StringSink(keyHex)
			) // HexEncoder
		); // StringSource

		return keyHex;
	}

	std::string getIV() {
		std::string ivHex;

		StringSource ss(iv.BytePtr(), iv.size(), true,
			new HexEncoder(
				new StringSink(ivHex)
			) // HexEncoder
		); // StringSource

		return ivHex;
	}

private:
	AutoSeededRandomPool rng;
	SecByteBlock key;
	SecByteBlock iv;
};

int main(int argc, char* argv[]) {
    WSADATA wsa;
	SOCKET s, new_socket;
	struct sockaddr_in server, client;
    char buffer[2048];

	if (WSAStartup(MAKEWORD(2,2), &wsa) != 0)
	{
		std::cout << std::endl << "Failed to initailize Winsock. Error Code: " << WSAGetLastError() << std::endl;
		return 1;
	}
	
    std::cout << "Creating socket... ";
	if ((s = socket(AF_INET , SOCK_STREAM , 0 )) == INVALID_SOCKET)
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
	if (bind(s, (struct sockaddr*) &server, sizeof(server)) == SOCKET_ERROR)
	{
		std::cout << std::endl << "bind() failed with error code: " << WSAGetLastError() << std::endl;
	}
	
	std::cout << "done" << std::endl;
	
	// listen for incoming connections
	listen(s, 3);
	std::cout << "Waiting for client... ";
	
	int c = sizeof(struct sockaddr_in);
	new_socket = accept(s, (struct sockaddr *) &client, &c);
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
	RSAEncryptor encryptor(n, e);
	AESSystem aes;

	std::string symmetricKey = encryptor.encrypt(aes.getKey());
	std::string iv = encryptor.encrypt(aes.getIV());
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

	// indefinitely read client messages
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

	closesocket(s);
	closesocket(new_socket);
	WSACleanup();

	return 0;
}
