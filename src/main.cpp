#include "Common.h"
#include "Wallet.h"

int main() {

	try {
		Wallet wallet;

		std::cout << wallet.getPublicKey() << std::endl;

		std::string payload = "{ ... }";
		std::vector<unsigned char> message(payload.begin(), payload.end());

		if (wallet.signSignature(message))
			std::cout << "Signature created." << std::endl;

		if (wallet.verify(message))
			std::cout << "Signature is correct." << std::endl;
		else
			std::cout << "Signature is not correct." << std::endl;

		std::string temp = "{ . a . }";
		std::vector<unsigned char> temp_message(temp.begin(), temp.end());

		if (wallet.verify(temp_message))
			std::cout << "Signature is correct." << std::endl;
		else
			std::cout << "Signature is not correct." << std::endl;

	} catch (const std::exception& error) {
		std::cerr << error.what() << std::endl;

		return 1;
	}

	return 0;
}