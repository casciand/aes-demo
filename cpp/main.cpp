#include "cryptlib.h"
#include "rijndael.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"

#include <iostream>
#include <fstream>
#include <string>

using namespace CryptoPP;

const char* FILE_PATH = "C:\\Users\\acasc\\Documents\\research\\aesDemo\\message.txt";

std::string hexToASCII(std::string hex) {
    std::string ascii;

    for (int i = 0; i < hex.length(); i += 2) {
        ascii += (int) std::stoul(hex.substr(i, 2), nullptr, 16);
    }

    return ascii;
}

void EncryptStringToBytes_Aes(std::string plaintext) {
    AutoSeededRandomPool prng;
    HexEncoder encoder(new FileSink(FILE_PATH), true, 0, ":", "\n");

    SecByteBlock key(AES::MAX_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);

    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

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

    encoder.Put(key, key.size());
    encoder.MessageEnd();

    encoder.Put(iv, iv.size());
    encoder.MessageEnd();

    encoder.Put((const byte*)&ciphertext[0], ciphertext.size());
    encoder.MessageEnd();
}

std::string DecryptStringFromBytes_Aes() {
    std::ifstream file(FILE_PATH);
    std::string keyStr;
    std::string ivStr;
    std::string ciphertextStr;

    file >> keyStr;
    file >> ivStr;
    file >> ciphertextStr;

    keyStr = hexToASCII(keyStr);
    ivStr = hexToASCII(ivStr);
    ciphertextStr = hexToASCII(ciphertextStr);

    try {
        SecByteBlock key(reinterpret_cast<const byte*>(&keyStr[0]), keyStr.size());
        SecByteBlock iv(reinterpret_cast<const byte*>(&ivStr[0]), ivStr.size());
        SecByteBlock ciphertext(reinterpret_cast<const byte*>(&ciphertextStr[0]), ciphertextStr.size());
        std::string recovered;

        CBC_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);

        StringSource s(ciphertext.BytePtr(), ciphertext.size(), true, 
            new StreamTransformationFilter(d,
                new StringSink(recovered)
            ) // StreamTransformationFilter
        ); // StringSource

        return recovered;
    } catch(const Exception& e) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
            std::cout << "Expected [1] argument, got [" << argc - 1 << "]." << std::endl;
            return 1;
    } else if (strcmp(argv[1], "encrypt") != 0 && strcmp(argv[1], "decrypt") != 0 && strcmp(argv[1], "1") != 0 && strcmp(argv[1], "2") != 0) {
            std::cout << "Please enter either:\n(1) encrypt\n(2) decrypt" << std::endl;
            std::cout << argv[1];
            return 1;
    } 
    
    if (strcmp(argv[1], "1") == 0 || strcmp(argv[1], "encrypt") == 0) {
        std::string plaintext;

        while (plaintext == "") {
            std::cout << "Enter a message to encrypt: ";
            std::getline(std::cin, plaintext);
        }

        EncryptStringToBytes_Aes(plaintext);
    } else {
        std::string recovered = DecryptStringFromBytes_Aes();
        std::cout << "Recovered plaintext: " << recovered << std::endl;
    }

    return 0;
}
