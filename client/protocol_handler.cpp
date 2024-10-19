#include "protocol_handler.h"
#include "client.hpp"

ProtocolHandler& ProtocolHandler::get_instance()
{
	static ProtocolHandler instance;
	return instance;
}

Request* ProtocolHandler::create_registration_request(const std::string& name) const
{
	RequestHeader header = RequestHeader(
		std::string(RequestHeader::SIZE_CLIENT_ID, '0'), // server will neglect this anyway for registration
		Client::CLIENT_VERSION,
		RegisterRequest::CODE,
		RegisterRequest::SIZE_CLIENT_NAME
	);
	return new RegisterRequest(header, name);
}
Request* ProtocolHandler::create_reconnect_request(const std::string& id, const std::string& name) const
{
	RequestHeader header = RequestHeader(
		id,
		Client::CLIENT_VERSION,
		ReconnectRequest::CODE,
		ReconnectRequest::SIZE_CLIENT_NAME
	);
	return new ReconnectRequest(header, name);
}

Request* ProtocolHandler::create_send_file_request(
	const std::string& id,
	const uint32_t& encrypted_file_size,
	const uint32_t& original_file_size,
	const uint16_t& packet_number,
	const uint16_t& total_packets,
	const std::string& file_name,
	const std::string& message_content
) const
{
	RequestHeader header = RequestHeader(
		id,
		Client::CLIENT_VERSION,
		SendFileRequest::CODE,
		SendFileRequest::SIZE_ENCRYPTED_FILE_SIZE +
		SendFileRequest::SIZE_ORIGINAL_FILE_SIZE +
		SendFileRequest::SIZE_PACKET_NUMBER +
		SendFileRequest::SIZE_TOTAL_PACKETS +
		SendFileRequest::SIZE_FILE_NAME +
		message_content.size()
	);
	return new SendFileRequest(
		header,
		encrypted_file_size,
		original_file_size,
		packet_number,
		total_packets,
		file_name,
		message_content
	);
}

Request* ProtocolHandler::create_send_public_key_request(std::string id, std::string name, std::string public_key) const
{
	RequestHeader header = RequestHeader(
		id,
		Client::CLIENT_VERSION,
		SendPublicKeyRequest::CODE,
		SendPublicKeyRequest::SIZE_CLIENT_NAME + SendPublicKeyRequest::SIZE_PUBLIC_KEY // I was scared that this will integer overflow, but the compiler will promote to int
	);
	return new SendPublicKeyRequest(header, name, public_key);
}
Request* ProtocolHandler::create_crc_state_request(const std::string& id, const std::string& file_name, const uint8_t& state) const
{
	RequestHeader header = RequestHeader(
		id,
		Client::CLIENT_VERSION,
		static_cast<uint16_t>(SendCRCStateRequest::CODE_CORRECT+state),
		SendCRCStateRequest::SIZE_FILE_NAME
	);
	return new SendCRCStateRequest(header, file_name);
}

ResponseHeader ProtocolHandler::unpack_response_header(const std::vector<uint8_t>& raw_data) const
{
	constexpr size_t min_expected_size = ResponseHeader::SIZE_VERSION + ResponseHeader::SIZE_CODE + ResponseHeader::SIZE_PAYLOAD_SIZE;
	if (raw_data.size() < min_expected_size) {
		throw std::runtime_error("<Error>: Packet is too small to unpack ResponseHeader");
	}
	uint8_t version = raw_data[0];
	uint16_t code; uint32_t payload_size;
	memcpy(&code, &raw_data[ResponseHeader::SIZE_VERSION], sizeof(code));
	memcpy(&payload_size, &raw_data[ResponseHeader::SIZE_VERSION + ResponseHeader::SIZE_CODE], sizeof(payload_size));
	return ResponseHeader(version, code, payload_size);
}
std::string ProtocolHandler::get_response_code_description(uint16_t code) const
{
	auto it = response_code_map.find(code);
	if (it == response_code_map.end()) {
		return "Unknown response code";
	}
	return it->second;
}
