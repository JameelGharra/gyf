#pragma once

#include "request.h"
#include "response.h"
#include <mutex>
#include <map>

// ProtcolHandler is a singleton class that is responsible for creating requests and unpacking responses.
class ProtocolHandler {
private:
	ProtocolHandler() = default;
	const std::map<uint16_t, std::string> response_code_map = {
		{ResponseCode::REGISTER_SUCCESS, "Registration success"},
		{ResponseCode::REGISTER_FAILURE, "Registration failed"},
		{ResponseCode::AES_KEY, "AES key sending"},
		{ResponseCode::SEND_FILE_SUCCESS, "File sending success"},
		{ResponseCode::RECONNECT_SUCCESS, "Reconnection success"},
		{ResponseCode::RECONNECT_REJECTED, "Reconnection failed"},
		{ResponseCode::MESSAGE_CONFIRM, "Message confirmed"},
		{ResponseCode::GENERAL_FAILURE, "General failure"},
	};
public:
	// number of attempts in total to send a request
	static constexpr uint8_t NUMBER_OF_ATTEMPTS = 4;

	ProtocolHandler(const ProtocolHandler&) = delete;
	ProtocolHandler& operator=(const ProtocolHandler&) = delete;
	static ProtocolHandler& get_instance();

	Request* create_registration_request(const std::string& name) const;
	Request* create_send_public_key_request(std::string id, std::string name, std::string public_key) const;
	Request* create_reconnect_request(const std::string& id, const std::string& name) const;
	Request* create_send_file_request(
		const std::string& id,
		const uint32_t& encrypted_file_size,
		const uint32_t& original_file_size,
		const uint16_t& packet_number,
		const uint16_t& total_packets,
		const std::string& file_name,
		const std::string& message_content
	) const;
	Request* create_crc_state_request(const std::string& id, const std::string& file_name, const uint8_t& state) const;
	ResponseHeader unpack_response_header(const std::vector<uint8_t>& raw_data) const;
	std::string get_response_code_description(uint16_t code) const;

};