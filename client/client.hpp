#pragma once

#include "network_manager.h"
#include "protocol_handler.h"
#include "crypto_manager.h"
#include <iostream>
#include "file_chunker.h"

class Client {

private:
	//responsible for establishing the connection
	NetworkManager net_manager;

	// number of lines required to be in transfer.info
	static constexpr uint8_t NUMBER_LINES_TRANSFER_INFO = 3;
	static constexpr uint8_t NUMBER_LINES_ME_INFO = 3;

	// to represent the state for CRC request type
	static constexpr uint8_t STATE_CORRECT = 0;
	static constexpr uint8_t STATE_BAD = 1;
	static constexpr uint8_t STATE_TERMINATE = 2;

	//fields for transfer.info
	std::string host;
	uint16_t port;
	std::string name;
	std::string file_path;

	// fields for me.info
	std::string id;

	// aes key
	std::string aes_key;

	// reconnecting
	bool is_registered;

	// for creating requests, unpacking responses
	const ProtocolHandler& proto_handler = ProtocolHandler::get_instance();

	// for crypto stuff
	const CryptoManager& crypto_manager = CryptoManager::get_instance();

	//transfer.info handling
	void get_transfer_info_content(); // retrieves the content of transfer.info
	void parse_transfer_info_line(const int& line_number, const std::string& line); // parses specific line from transfer.info
	bool check_host(const std::string& address) const; 	// checks if the address is valid
	void get_address(std::string line); // gets the address from the line

	//me.info handling
	void get_me_info_content();
	void parse_me_info_line(const int& line_number, const std::string& line);
	void output_to_me_info();

	// public key handling
	std::string create_public_key(); // creates the public key
	void output_to_priv_key(std::string private_key_64); // outputs the private key to priv.key
	void output_key_to_me_info(std::string private_key_64); // outputs the private key to me.info

	// retrieves and validates the required info, then sets up the connection
	void setup();
	
	// registeration process
	bool get_register_response(std::string& response_error_str);
	Request* create_register();

	// reconnection process
	bool get_reconnect_response(std::string& response_error_str, uint32_t& response_return);

	// sending public key process
	Request* create_public_key_request(); // creates the request for sending the public key
	bool get_send_public_key_response(std::string& response_error_str, uint32_t& response_return); // gets the response for sending the public key
	std::string get_private_key_from_priv_key(); // gets the private key from priv.key in base 64

	// aes key receiving
	void retrieve_aes_key(const std::string& aes_string); // gets the aes key from server
	void get_aes_key(uint32_t aes_key_size); // starts the operation of retrieving the aes key

	// sending file process
	void send_file_chunks(FileChunker& chunker);
	void print_file_info(const FileChunker& chunker) const;
	bool get_send_file_response(std::string& response_error_str, unsigned long& server_crc);
	bool check_crc(const unsigned long& server_crc, const uint32_t& client_crc) const;
	bool get_message_confirm_response(std::string& response_error_str);

	//void op_reconnect();
	//void op_send_file();

	// operations
	void perform_register();
	uint32_t perform_send_public_key();
	uint32_t perform_attempt_reconnect(); // checks whether the client from me.info really exists in server and reconnects in
	void perform_send_file();
	void perform_send_crc_correct(const std::string& file_name);
	void perform_send_crc_bad(const std::string& file_name);
	void perform_send_crc_terminate(const std::string& file_name);

public:
	//client version
	static constexpr uint8_t CLIENT_VERSION = 3;

	Client();
	~Client();

	void start();

	// template for performing operations
	template<typename ReturnType, typename RequestFunc, typename ResponseHandler>
	static ReturnType perform_operation(NetworkManager& net_manager, RequestFunc request_creator, ResponseHandler response_handler);
	// for the case if there is no response return
	template<typename RequestFunc, typename ResponseHandler>
	static void perform_operation(NetworkManager& net_manager, RequestFunc request_creator, ResponseHandler response_handler);
};

template<typename ReturnType, typename RequestFunc, typename ResponseHandler>
ReturnType Client::perform_operation(NetworkManager& net_manager, RequestFunc request_creator, ResponseHandler response_handler) {
	std::cout << "--------" << std::endl;
	std::unique_ptr<Request> request(request_creator()); // pre + request
	std::string response_error_str;
	ReturnType response_return{};
	for (auto attempt = 1; attempt <= ProtocolHandler::NUMBER_OF_ATTEMPTS; ++attempt) {
		std::cout << "<Info>: Doing attempt #" << attempt << ".." << std::endl;
		net_manager.send_request(request.get());
		if (response_handler(response_error_str, response_return)) { // post if succeed
			//std::cout << "<Info>: Operation successful." << std::endl;
			std::cout << "--------" << std::endl;
			return response_return;
		}
		std::cerr << "<Error>: server responded with error" << std::endl;
	}
	throw std::runtime_error("<Error>: Fatal! Server responded with " + response_error_str + "\n");
}
template<typename RequestFunc, typename ResponseHandler>
void Client::perform_operation(NetworkManager& net_manager, RequestFunc request_creator, ResponseHandler response_handler) {
	std::cout << "--------" << std::endl;
	std::unique_ptr<Request> request(request_creator()); // pre + request
	std::string response_error_str;
	for (auto attempt = 1; attempt <= ProtocolHandler::NUMBER_OF_ATTEMPTS; ++attempt) {
		std::cout << "<Info>: Doing attempt #" << attempt << ".." << std::endl;
		net_manager.send_request(request.get());
		if (response_handler(response_error_str)) { // post if succeed
			std::cout << "<Info>: Operation successful." << std::endl;
			std::cout << "--------" << std::endl;
			return;
		}
		std::cerr << "<Error>: server responded with error" << std::endl;
	}
	throw std::runtime_error("<Error>: Fatal! Server responded with " + response_error_str + "\n");
}