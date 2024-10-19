#include "request.h"
#include <iostream>
#include <stdexcept>
#include "packet_utils.h"

// =========== RequestHeader ===========

RequestHeader::RequestHeader(std::string client_id, uint8_t version, uint16_t code, uint32_t payload_size) :
	client_id(client_id), version(version), code(code), payload_size(payload_size)
{
}

const RequestHeader& Request::get_header() const
{
	return header;
}
std::vector<uint8_t> RequestHeader::pack() const {
	std::vector<uint8_t> packet;
	try {
		packet.insert(packet.end(), client_id.begin(), client_id.end());
		packet.push_back(version);
		PacketUtils::insert_to_packet(packet, &code, sizeof(code));
		PacketUtils::insert_to_packet(packet, &payload_size, sizeof(payload_size));
	}
	catch (std::exception& e) {
		throw std::runtime_error("<Error>: Failed to pack the request header: " + std::string(e.what()));
	}
	return packet;
}

// =========== Request ===========

Request::Request(const RequestHeader& header) : header(header)
{
}

std::vector<uint8_t>& Request::get_cached_packet() const
{
	return cached_packet;
}

RegisterRequest::RegisterRequest(const RequestHeader& header, const std::string& name) : Request(header), name(name)
{
}
const std::vector<uint8_t>& RegisterRequest::create_packet() const {
	std::vector<uint8_t>& cached_packet = get_cached_packet();
	if (cached_packet.empty()) {
		cached_packet = get_header().pack();
		std::string client_name = name; // I decided to not change the original client name (in-case data loss for packet creation)
		PacketUtils::terminate_payload_string(client_name, SIZE_CLIENT_NAME);
		cached_packet.insert(cached_packet.end(), client_name.begin(), client_name.end());
	}
	return cached_packet;
}

SendPublicKeyRequest::SendPublicKeyRequest(const RequestHeader& header, const std::string& name, const std::string& public_key) :
	Request(header), name(name), public_key(public_key)
{
}

const std::vector<uint8_t>& SendPublicKeyRequest::create_packet() const
{
	std::vector<uint8_t>& cached_packet = get_cached_packet();
	if (cached_packet.empty()) {
		cached_packet = get_header().pack();
		std::string client_name = name; // I decided to not change the original client name (in-case data loss for packet creation)
		PacketUtils::terminate_payload_string(client_name, SIZE_CLIENT_NAME); // will take care in-case name is longer :-)
		cached_packet.insert(cached_packet.end(), client_name.begin(), client_name.end());
		cached_packet.insert(cached_packet.end(), public_key.begin(), public_key.end()); // guaranteed to be 160 bytes
	}
	return cached_packet;
}

ReconnectRequest::ReconnectRequest(const RequestHeader& header, const std::string& name) : Request(header), name(name)
{
}

const std::vector<uint8_t>& ReconnectRequest::create_packet() const
{
	std::vector<uint8_t>& cached_packet = get_cached_packet();
	if (cached_packet.empty()) {
		cached_packet = get_header().pack();
		std::string client_name = name; // I decided to not change the original client name (in-case data loss for packet creation)
		PacketUtils::terminate_payload_string(client_name, SIZE_CLIENT_NAME); // will take care in-case name is longer :-)
		cached_packet.insert(cached_packet.end(), client_name.begin(), client_name.end());
	}
	return cached_packet;
}

SendFileRequest::SendFileRequest(
	const RequestHeader& header,
	const uint32_t& encrypted_file_size,
	const uint32_t& original_file_size,
	const uint16_t& packet_number,
	const uint16_t& total_packets,
	const std::string& file_name,
	const std::string& message_content
) :
	Request(header),
	encrypted_file_size(encrypted_file_size),
	original_file_size(original_file_size),
	packet_number(packet_number),
	total_packets(total_packets),
	file_name(file_name),
	message_content(message_content)
{

}

const std::vector<uint8_t>& SendFileRequest::create_packet() const
{
	std::vector<uint8_t>& cached_packet = get_cached_packet();
	if (cached_packet.empty()) {
		cached_packet = get_header().pack();
		PacketUtils::insert_to_packet(cached_packet, &encrypted_file_size, sizeof(encrypted_file_size));
		PacketUtils::insert_to_packet(cached_packet, &original_file_size, sizeof(original_file_size));
		PacketUtils::insert_to_packet(cached_packet, &packet_number, sizeof(packet_number));
		PacketUtils::insert_to_packet(cached_packet, &total_packets, sizeof(total_packets));
		std::string file_name_str = file_name;
		PacketUtils::terminate_payload_string(file_name_str, SIZE_FILE_NAME);
		cached_packet.insert(cached_packet.end(), file_name_str.begin(), file_name_str.end());
		cached_packet.insert(cached_packet.end(), message_content.begin(), message_content.end());
	}
	return cached_packet;
}

SendCRCStateRequest::SendCRCStateRequest(const RequestHeader& header, const std::string& file_name) : Request(header), file_name(file_name) {

}

const std::vector<uint8_t>& SendCRCStateRequest::create_packet() const {
	std::vector<uint8_t>& cached_packet = get_cached_packet();
	if (cached_packet.empty()) {
		cached_packet = get_header().pack();
		std::string file_name_str = file_name;
		PacketUtils::terminate_payload_string(file_name_str, SIZE_FILE_NAME);
		cached_packet.insert(cached_packet.end(), file_name_str.begin(), file_name_str.end());
	}
	return cached_packet;
}
