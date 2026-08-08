#pragma once

#include "Common.h"

class Wallet {
	unsigned char sk[crypto_sign_SECRETKEYBYTES];
	unsigned char pk[crypto_sign_PUBLICKEYBYTES];

	unsigned char sig[crypto_sign_BYTES];
	char pk_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];

	static inline const std::string DB_PATH = "database/publickey.vld";

	bool savePublicKey(std::string _pk_hex);

	bool loadPublicKey();

	bool controlMessage();

	public:

		bool signSignature(std::vector<unsigned char>& _message);

		Wallet();

		Wallet(std::string& _pk);

		std::string bin_hex(unsigned char* _bin, size_t bin_len);

		void hex_bin(std::string& _hex, unsigned char* out_bin, size_t out_le);

		bool verify(std::vector<unsigned char>& _message);

		std::string getPublicKey();

};