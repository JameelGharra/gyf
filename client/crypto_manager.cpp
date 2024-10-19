#include "crypto_manager.h"
#include <base64.h>
#include <iomanip>
#include "aes_wrapper.h"

CryptoManager& CryptoManager::get_instance()
{
	static CryptoManager instance;
	return instance;
}

std::string CryptoManager::encode(const std::string& str) const
{
	std::string encoded;
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Encoder(
			new CryptoPP::StringSink(encoded)
		) // Base64Encoder
	); // StringSource

	return encoded;
}

std::string CryptoManager::decode(const std::string& str) const
{
	std::string decoded;
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Decoder(
			new CryptoPP::StringSink(decoded)
		) // Base64Decoder
	); // StringSource

	return decoded;
}
std::string CryptoManager::hexify(const char* buffer, unsigned int length) const
{
	std::ostringstream oss;
	oss << std::hex;
	for (size_t i = 0; i < length; i++)
	{
		oss << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]) << (((i + 1) % 16 == 0) ? "\n" : "");
	}
	return oss.str();
}
std::string CryptoManager::dehexify(const std::string& hexString) const {
	std::string result;
	unsigned int byte;

	for (size_t i = 0; i < hexString.size(); i += 2) {
		std::istringstream iss(hexString.substr(i, 2));
		if (!(iss >> std::hex >> byte)) {
			throw std::runtime_error("Invalid client id: not a hexadecimal string");
		}
		result.push_back(static_cast<char>(byte));
	}

	return result;
}
std::string CryptoManager::aes_encrypt(const std::string& aes_key, std::string& plain) const {
	AESWrapper aes_wrapper(aes_key.c_str(), aes_key.length());
	std::string encrypted = aes_wrapper.encrypt(plain.c_str(), plain.length());
	return encrypted;
}
