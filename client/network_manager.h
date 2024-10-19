#pragma once
#include <boost/asio.hpp>
#include "request.h"
#include "protocol_handler.h"

// acts as the doorway to the server (encapsulates the connection)
class NetworkManager {
private:

	// fields for connection
	boost::asio::io_context io_context;
	boost::asio::ip::tcp::socket socket;
	boost::asio::ip::tcp::resolver resolver;

	// for creating requests, unpacking responses
	ProtocolHandler& proto_handler = ProtocolHandler::get_instance();

public:
	NetworkManager();
	void establish(std::string host, std::string port);
	void send_request(Request* request);
	ResponseHeader receive_response_header();
	std::string receive_register_payload(const ResponseHeader& header);
	std::string receive_aes_key(uint32_t aes_key_size);
	void receive_reconnect_failure_payload(const ResponseHeader& header);
	uint32_t receive_send_file_payload();
	void receive_confirm_message_payload();
};