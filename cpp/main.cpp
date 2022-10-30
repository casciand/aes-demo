#include "rsa.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"

#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>

using namespace CryptoPP;

std::string separator() {
    #ifdef _WIN32
        return "\\";
    #else
        return "/";
    #endif
}

// constants
AutoSeededRandomPool rng;

std::string path = ".." + separator() + ".." + separator() + ".." + separator() + "message.txt";
const char* FILE_PATH = path.c_str();

// helper function
std::string hexToASCII(std::string hex) {
    std::string ascii;

    for (int i = 0; i < hex.length(); i += 2) {
        ascii += (int) std::stoul(hex.substr(i, 2), nullptr, 16);
    }

    return ascii;
}

// encryption/decryption functions
void RSAEncrypt(const std::string& plaintext) {
    Integer n("0x9BA04B03B8380EE352323DB2235BC6529E34B5B03D1440F67FAF6055B4900A5DE73ECDD1682260DEA537DBE3D1268468319C348E069456F9A883EA1A17FB0D35");
    Integer e("0x10001");

    RSA::PublicKey pubKey;
    pubKey.Initialize(n, e);

    HexEncoder encoder(new FileSink(FILE_PATH), true, 0, ":", "\n");

    RSAES_OAEP_SHA_Encryptor enc(pubKey);
    std::string ciphertext;

    StringSource ss(plaintext, true,
        new PK_EncryptorFilter(rng, enc,
            new StringSink(ciphertext)
        ) // PK_EncryptorFilter
    ); // StringSource

    encoder.Put((const byte*) &ciphertext[0], ciphertext.size());
    encoder.MessageEnd();
}

std::string RSADecrypt() {
    std::ifstream file(FILE_PATH);
    std::string ciphertext;
    std::string recovered;

    file >> ciphertext;

    Integer n("0xC98D2988771B0C1BFDBDA9147026A4B3856E249224DB027FA45BB1F9931E54D165DC63867BA20F67CBAD46C9685849721EE7A74E237C0E0598EA5FA704EA8165");
    Integer e("0x10001");
    Integer d("0x36807FACB158950BB4AFE6DAEA00E924CA7E20518CB9D49123A6D017C71ABAA0725DCFBE98B05D50BDCD81AB4591CA0CE9C4F6540F692EE92156D9FBFEBE0E39");
    
    RSA::PrivateKey privKey;
    privKey.Initialize(n, e, d);

    RSAES_OAEP_SHA_Decryptor dec(privKey);

    StringSource ss(hexToASCII(ciphertext), true,
        new PK_DecryptorFilter(rng, dec,
            new StringSink(recovered)
    ) // PK_DecryptorFilter
    ); // StringSource

    return recovered;
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

        RSAEncrypt(plaintext);
    } else {
        std::string recovered = RSADecrypt();
        std::cout << "Recovered plaintext: " << recovered << std::endl;
    }

    return 0;
}
