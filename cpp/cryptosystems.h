#ifndef CRYPTOSYSTEMS_H
#define CRYPTOSYSTEMS_H

#include "cryptlib.h"
#include "rsa.h"
#include "rijndael.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"
#include <string>

using namespace CryptoPP;

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
	std::string decrypt(char* buffer, int size) {
		std::string plaintext;
		// SecByteBlock ciphertextBB(reinterpret_cast<const byte*>(&ciphertext[0]), ciphertext.size());

		try {
			CBC_Mode<AES>::Decryption d;
			d.SetKeyWithIV(key, key.size(), iv);

			StringSource s(reinterpret_cast<const byte*>(buffer), size, true, 
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

#endif // CRYPTOSYSTEMS_H
