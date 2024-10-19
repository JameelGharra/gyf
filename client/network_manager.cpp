#include "network_manager.h"
#include <fstream>
#include <regex>
#include <boost/asio.hpp>
#include <iostream>
#include "request.h"
#include "response.h"

NetworkManager::NetworkManager(): resolver(io_context), socket(io_context)
{
}
void NetworkManager::send_request(Request *request) {
	std::vector<uint8_t> packet = request->create_packet();
	std::cout << "<Debug>: Sending a request of size " << packet.size() << " bytes." << std::endl;
	boost::asio::write(socket, boost::asio::buffer(packet, packet.size()));
}
ResponseHeader NetworkManager::receive_response_header() {
	std::vector<uint8_t> packet(ResponseHeader::SIZE);
	boost::asio::read(socket, boost::asio::buffer(packet, ResponseHeader::SIZE));
	return proto_handler.unpack_response_header(packet);
}
std::string NetworkManager::receive_register_payload(const ResponseHeader& header)
{
	std::vector<uint8_t> packet(ResponsePayload::SIZE_CLIENT_ID);
	boost::asio::read(socket, boost::asio::buffer(packet, ResponsePayload::SIZE_CLIENT_ID));
	std::string client_id(packet.begin(), packet.end());
	return client_id;
}
void NetworkManager::receive_reconnect_failure_payload(const ResponseHeader& header)
{
	std::vector<uint8_t> packet(ResponsePayload::SIZE_CLIENT_ID);
	boost::asio::read(socket, boost::asio::buffer(packet, ResponsePayload::SIZE_CLIENT_ID));
}
void NetworkManager::receive_confirm_message_payload() {
	std::vector<uint8_t> packet(ResponsePayload::SIZE_CLIENT_ID);
	boost::asio::read(socket, boost::asio::buffer(packet, ResponsePayload::SIZE_CLIENT_ID));
	std::string client_id(packet.begin(), packet.end());
}
std::string NetworkManager::receive_aes_key(uint32_t aes_key_size)
{
	std::vector<uint8_t> packet(aes_key_size);
	boost::asio::read(socket, boost::asio::buffer(packet, aes_key_size));
	std::string client_id = std::string(packet.begin(), packet.begin()+ResponsePayload::SIZE_CLIENT_ID);
	std::string aes_key = std::string(packet.begin() + ResponsePayload::SIZE_CLIENT_ID, packet.end());
	return aes_key;
}
uint32_t NetworkManager::receive_send_file_payload() {

	size_t packet_size = 
		ResponsePayload::SIZE_CLIENT_ID + 
		ResponsePayload::SIZE_CONTENT + 
		ResponsePayload::SIZE_FILE_NAME + 
		ResponsePayload::SIZE_CRC
	;
	std::vector<uint8_t> packet(packet_size);
	boost::asio::read(socket, boost::asio::buffer(packet, packet_size));
	std::string client_id(packet.begin(), packet.begin() + ResponsePayload::SIZE_CLIENT_ID);
	std::string content(packet.begin() + ResponsePayload::SIZE_CLIENT_ID, packet.begin() + ResponsePayload::SIZE_CLIENT_ID + ResponsePayload::SIZE_CONTENT);
	std::string file_name(packet.begin() + ResponsePayload::SIZE_CLIENT_ID + ResponsePayload::SIZE_CONTENT, packet.begin() + ResponsePayload::SIZE_CLIENT_ID + ResponsePayload::SIZE_CONTENT + ResponsePayload::SIZE_FILE_NAME);
	uint32_t crc = *(uint32_t*)(packet.data() + ResponsePayload::SIZE_CLIENT_ID + ResponsePayload::SIZE_CONTENT + ResponsePayload::SIZE_FILE_NAME);
	return crc;
}
void NetworkManager::establish(std::string host, std::string port)
{
	try {
		boost::asio::connect(socket, resolver.resolve(host, port));
		std::cout << "<Info>: Successfully connected to the server (" << host << ":" << port << ")" << std::endl;
	}
	catch (const boost::system::system_error& exception) {
		throw std::runtime_error(std::string("<Error>: Could not establish connection: ") + exception.what());
	}
}