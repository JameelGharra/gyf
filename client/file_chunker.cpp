#include "file_chunker.h"
#include <fstream>
#include "crypto_manager.h"
#include <filesystem>


FileChunker::FileChunker(const std::string& path, const std::string& aes_key) : path(path), aes_key(aes_key) {
	chunked_file = read_content();
    encrypt_content();
}

std::string FileChunker::read_content() {
    std::ifstream file_to_read(path, std::ios::binary);
    if (!file_to_read) {
        throw std::runtime_error("Could not open the file required to send: " + path);
	}
    std::string result((std::istreambuf_iterator<char>(file_to_read)),
        std::istreambuf_iterator<char>());
	original_size = result.size();
    return result;
}
void FileChunker::encrypt_content() {
	CryptoManager& crypto_manager = CryptoManager::get_instance();
    chunked_file = crypto_manager.aes_encrypt(aes_key, chunked_file);
}

size_t FileChunker::total_chunks() const {
	return chunked_file.length() / CHUNK_SIZE + 1; // +1 to account for the last chunk (to be a separate partial packet)
}

size_t FileChunker::get_original_size() const
{
	return original_size;
}

std::string FileChunker::get_next() {
	if (pos >= chunked_file.length()) {
		return "";
	}
	size_t chunk_size = std::min(CHUNK_SIZE, chunked_file.length() - pos);
	std::string chunk = chunked_file.substr(pos, chunk_size);
	pos += chunk_size;
	++total_reads;
	return chunk;
}

std::string FileChunker::get_file_name() const {
	std::filesystem::path file_path(path);
	return file_path.filename().string();
}

bool FileChunker::is_finished() const {
	return pos >= chunked_file.length();
}

size_t FileChunker::get_total_reads() const {
	return total_reads;
}

size_t FileChunker::get_size() const {
	return chunked_file.length();
}