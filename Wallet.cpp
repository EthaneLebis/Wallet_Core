#include "Wallet.h"
#include "Common.h"

//	Private

bool Wallet::savePublicKey(std::string _pk_hex) {
	std::ofstream File(DB_PATH, std::ios::out);

	if (!File) 
		throw std::runtime_error("Couldn't open file.");

	File << std::string(_pk_hex);

	File.close();

	return true;
}

bool Wallet::loadPublicKey() {
	std::ifstream File(DB_PATH, std::ios::in);
	std::string hex_file;

	if (!File) 
		throw std::runtime_error("Couldn't open file.");

	File >> hex_file;

	File.close();

	// Secret key should load from different methods. Don't save in file.

	hex_bin(hex_file, pk, sizeof(pk));
}


bool Wallet::controlMessage() {
	// Can write controller based on json data.

	return true;
}

//	Public

Wallet::Wallet() {
	if (sodium_init() < 0)
		throw std::runtime_error("libsodium initialization failed.");

	if (crypto_sign_keypair(pk, sk) != 0)
		throw std::runtime_error("Couldn't initialize public key and secret key.");

	savePublicKey(bin_hex(pk, sizeof(pk)));
}

Wallet::Wallet(std::string& _pk_hex) {
	if (sodium_init() < 0)
		throw std::runtime_error("libsodium initialization failed.");

	hex_bin(_pk_hex, pk, sizeof(pk));
}

bool Wallet::signSignature(std::vector<unsigned char>& _message) {
	unsigned long long signlen_p;
	std::fill(sig, sig + sizeof(sig), 0);

	if (crypto_sign_detached(sig, &signlen_p, _message.data(), _message.size(), sk))
		throw std::runtime_error("Couldn't create signature.");

	return true;
}

std::string Wallet::bin_hex(unsigned char* _bin, size_t bin_len) {
	std::vector<char> hex_buf(bin_len * 2 + 1);

	if (sodium_bin2hex(hex_buf.data(), hex_buf.size(), _bin, bin_len) == NULL)
		throw std::runtime_error("Couldn't convert to hex format.");

	return std::string(hex_buf.data());
}

void Wallet::hex_bin(std::string& _hex, unsigned char* out_bin, size_t out_len) {
	if (sodium_hex2bin(out_bin, out_len, _hex.c_str(), _hex.size(), NULL, NULL, NULL))
		throw std::runtime_error("Couldn't convert from hex.");
}

bool Wallet::verify(std::vector<unsigned char>& _message) {
	loadPublicKey();

	if (crypto_sign_verify_detached(sig, _message.data(), _message.size(), pk)) 
		throw std::runtime_error("Signature is incorrect.");

	return true;
}

std::string Wallet::getPublicKey() {
	return bin_hex(pk, sizeof(pk));
}