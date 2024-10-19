#include "crc_handler.h"
#include <filesystem>
#include <fstream>


std::future<unsigned long> CRCHandler::calculate(const std::string& file_path) const {
	return std::async(&CRCHandler::read_and_calculate, this, file_path);
}
unsigned long CRCHandler::read_and_calculate(const std::string& file_path) const {
	if (std::filesystem::exists(file_path)) {
		std::filesystem::path fpath = file_path;
		std::ifstream f1(file_path.c_str(), std::ios::binary);
		if (!f1.is_open()) {
			std::cerr << "Cannot open input file " << file_path << std::endl;
			return 0;
		}
		size_t size = static_cast<size_t>(std::filesystem::file_size(fpath));
		char* b = new char[size];
		f1.seekg(0, std::ios::beg);
		f1.read(b, size);
		return memcrc(b, size);
	}
	else {
		std::cerr << "Cannot open input file " << file_path << std::endl;
		return 0;
	}
}

unsigned long CRCHandler::memcrc(char* b, size_t n) const {
	unsigned int v = 0, c = 0;
	unsigned long s = 0;
	unsigned int tabidx;

	for (size_t i = 0; i < n; i++) {
		tabidx = (s >> 24) ^ (unsigned char)b[i];
		s = UNSIGNED((s << 8)) ^ crctab[0][tabidx];
	}

	while (n) {
		c = n & 0377;
		n = n >> 8;
		s = UNSIGNED(s << 8) ^ crctab[0][(s >> 24) ^ c];
	}
	delete[] b;
	return (unsigned long)UNSIGNED(~s);
}
