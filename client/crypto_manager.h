#pragma once

#include <mutex>

// CryptoManager is a singleton class that provides encoding and decoding functions
class CryptoManager {
private:
	CryptoManager() = default;

public:
	CryptoManager(const CryptoManager&) = delete;
	CryptoManager& operator=(const CryptoManager&) = delete;
	static CryptoManager& get_instance();

	std::string encode(const std::string& str) const;
	std::string decode(const std::string& str) const;
	std::string hexify(const char* buffer, unsigned int length) const;
	std::string dehexify(const std::string& hex_str) const;
	std::string aes_encrypt(const std::string& aes_key, std::string& plain) const;
};