#pragma once

#include <string>

// FileChunker is a class that is responsible for reading a file and splitting it into chunks appropriate for sending over the network
class FileChunker {
private:
	const std::string path;
	std::string chunked_file;
	size_t pos = 0; // serves as an iterator in the sense of knowing where we are in the buffer
	const std::string aes_key;
	size_t original_size;
	size_t total_reads = 0;

	static constexpr size_t CHUNK_SIZE = 4096; // 4 KB for memory management efficiency

	std::string read_content(); // part of the loading process
	void encrypt_content();
public:
	FileChunker(const std::string& path, const std::string& aes_key);
	std::string get_next(); // getting the next chunk in the file
	bool is_finished() const; // checking if we are done with the file
	size_t total_chunks() const;
	size_t get_original_size() const;
	size_t get_size() const;
	size_t get_total_reads() const;
	std::string get_file_name() const; // gets the file name from the path
};