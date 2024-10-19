#pragma once

#include <cstdint>
#include <string>

class ResponseHeader {
public:

	// header field sizes (in bytes)
	constexpr static uint8_t SIZE_VERSION = 1;
	constexpr static uint8_t SIZE_CODE = 2;
	constexpr static uint8_t SIZE_PAYLOAD_SIZE = 4;
	constexpr static uint8_t SIZE = ResponseHeader::SIZE_VERSION + ResponseHeader::SIZE_CODE + ResponseHeader::SIZE_PAYLOAD_SIZE;

	uint8_t version;
	uint16_t code;
	uint32_t payload_size;

	ResponseHeader(uint8_t version, uint16_t code, uint32_t payload_size);
};

namespace ResponsePayload {
	constexpr uint8_t SIZE_CLIENT_ID = 16;
	constexpr uint8_t SIZE_CONTENT = 4; // size of the file after encryption
	constexpr uint8_t SIZE_FILE_NAME = 255;
	constexpr uint8_t SIZE_CRC = 4;
};

namespace ResponseCode {
	constexpr uint16_t REGISTER_SUCCESS = 1600;
	constexpr uint16_t REGISTER_FAILURE = 1601;
	constexpr uint16_t AES_KEY = 1602;
	constexpr uint16_t SEND_FILE_SUCCESS = 1603;
	constexpr uint16_t MESSAGE_CONFIRM = 1604;
	constexpr uint16_t RECONNECT_SUCCESS = 1605;
	constexpr uint16_t RECONNECT_REJECTED = 1606;
	constexpr uint16_t GENERAL_FAILURE = 1607;
};