#pragma once

#include <cstdint>
#include <array>
#include <vector>
#include <string>

//encapsulates a request header in a request packet
struct RequestHeader {

	// header field sizes (in bytes)
	constexpr static uint8_t SIZE_CLIENT_ID = 16;
	constexpr static uint8_t SIZE_VERSION = 1;
	constexpr static uint8_t SIZE_CODE = 2;
	constexpr static uint8_t SIZE_PAYLOAD_SIZE = 4;

	std::string client_id;
	uint8_t version;
	uint16_t code;
	uint32_t payload_size;

	RequestHeader(std::string client_id, uint8_t version, uint16_t code, uint32_t payload_size);

	std::vector<uint8_t> pack() const;
};

class Request {
private:
	const RequestHeader header;
	mutable std::vector<uint8_t> cached_packet;
protected:
	Request(const RequestHeader& header);
	std::vector<uint8_t>& get_cached_packet() const;
public:
	virtual ~Request() = default;
	const RequestHeader& get_header() const;
	virtual const std::vector<uint8_t>& create_packet() const = 0;
};

class RegisterRequest : public Request {
private:
	std::string name;
public:
	constexpr static uint8_t SIZE_CLIENT_NAME = 255; // including '\0'
	constexpr static uint16_t CODE = 825;
	RegisterRequest(const RequestHeader& header, const std::string& name);
	const std::vector<uint8_t>& create_packet() const override;
};

class SendPublicKeyRequest : public Request {
	std::string name;
	std::string public_key;

public:
	constexpr static uint8_t SIZE_CLIENT_NAME = 255; // including '\0'
	constexpr static uint8_t SIZE_PUBLIC_KEY = 160;
	constexpr static uint16_t CODE = 826;
	SendPublicKeyRequest(const RequestHeader& header, const std::string& name, const std::string& public_key);
	const std::vector<uint8_t>& create_packet() const override;
};

class ReconnectRequest : public Request {
private:
	std::string name;
public:
	constexpr static uint8_t SIZE_CLIENT_NAME = 255; // including '\0'
	constexpr static uint16_t CODE = 827;
	ReconnectRequest(const RequestHeader& header, const std::string& name);
	const std::vector<uint8_t>& create_packet() const override;
};

class SendFileRequest : public Request {
private:
	uint32_t encrypted_file_size;
	uint32_t original_file_size;
	uint16_t packet_number;
	uint16_t total_packets;
	std::string file_name;
	std::string message_content; // encrypted file content

public:
	constexpr static uint16_t CODE = 828;
	constexpr static uint8_t SIZE_ENCRYPTED_FILE_SIZE = 4;
	constexpr static uint8_t SIZE_ORIGINAL_FILE_SIZE = 4;
	constexpr static uint8_t SIZE_PACKET_NUMBER = 2;
	constexpr static uint8_t SIZE_TOTAL_PACKETS = 2;
	constexpr static uint8_t SIZE_FILE_NAME = 255; // including '\0'

	SendFileRequest(
		const RequestHeader& header,
		const uint32_t& encrypted_file_size,
		const uint32_t& original_file_size,
		const uint16_t& packet_number,
		const uint16_t& total_packets,
		const std::string& file_name,
		const std::string& message_content
	);

	const std::vector<uint8_t>& create_packet() const override;
};

class SendCRCStateRequest : public Request {
	std::string file_name;
public:
	constexpr static uint16_t CODE_CORRECT = 900;
	constexpr static uint16_t CODE_INCORRECT = 901;
	constexpr static uint16_t CODE_ELIMINATE = 902;
	constexpr static uint8_t SIZE_FILE_NAME = 255; // including '\0'

	SendCRCStateRequest(const RequestHeader& header, const std::string& file_name);
	const std::vector<uint8_t>& create_packet() const override;
};
