#include "client.hpp"
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <regex>
#include "request.h"
#include "rsa_wrapper.h"
#include "file_chunker.h"
#include "crc_handler.h"

Client::Client() : port(0), is_registered(false) // just more like added to avoid warnings, but they used after being assigned anyway
{
}

Client::~Client()
{
}
void Client::parse_me_info_line(const int& line_number, const std::string& line) {
	switch (line_number) {
	case 1:
		name = line;
		std::cout << "<Info>: Client name: " << name << std::endl;
		break;
	case 2:
		std::cout << "<Info>: Client ID: " << line << std::endl; // hexified
		id = crypto_manager.dehexify(line);
		break;

	default:
		throw std::runtime_error("<Error>: Invalid amount of lines in me.info file.");
	}
}
void Client::get_me_info_content() {
	std::cout << "--------" << std::endl;
	std::ifstream me_info_file("me.info");
	if (!me_info_file.is_open()) {
		is_registered = false; // I added this for clarity, but is_registered is false at construction anyway
		std::cout << "<Info>: me.info file not found, client is not registered." << std::endl;
		return;
	}
	std::cout << "<Info>: me.info file found, retrieving data.." << std::endl;
	std::string line;
	int line_number = 1;
	while (line_number <= NUMBER_LINES_ME_INFO - 1) {
		if (!std::getline(me_info_file, line)) {
			std::cerr << "<Error>: me.info file is corrupt/wrong form, moving to register.." << std::endl;
		}
		parse_me_info_line(line_number, line);
		++line_number;
	}
	is_registered = true;
	me_info_file.close();
	std::cout << "--------" << std::endl;
}
bool Client::check_host(const std::string& address) const
{
	std::regex ipv4_pattern(
		R"(^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$)"
	);
	return std::regex_match(host, ipv4_pattern);
}
void Client::get_address(std::string line) {
	std::istringstream ss(line);
	if (!std::getline(ss, host, ':') || !check_host(host)) {
		throw std::runtime_error("<Error>: Invalid or missing address in transfer.info file.");
	}
	std::string port_str;
	if (!std::getline(ss, port_str)) {
		throw std::runtime_error("<Error>: Missing port in transfer.info file.");
	}
	try {
		int converted_port = std::stoi(port_str);

		if (converted_port < 0 || converted_port > 65535) {
			throw std::out_of_range("<Error>: Invalid port in transfer.info file.");
		}
		port = static_cast<uint16_t>(converted_port);
	}
	catch (std::invalid_argument&) {
		throw std::runtime_error("<Error>: Could not convert port from transfer.info file.");
	}
	catch (std::out_of_range&) {
		throw std::runtime_error("<Error>: Failed to convert port: out of range.");
	}
}
void Client::parse_transfer_info_line(const int& line_number, const std::string& line) {
	switch (line_number) {
	case 1:
		get_address(line);
		break;
	case 2:
		if (!is_registered) { // in the case of being registered, we are not using the name in transfer.info, but the one in me.info
			if (line.size() > static_cast<size_t>(RegisterRequest::SIZE_CLIENT_NAME - 1)) { // the fact that \0 is not in the file itself
				name = line.substr(0, static_cast<size_t>(RegisterRequest::SIZE_CLIENT_NAME - 1));
				std::cerr << "<Warning>: Client name in transfer.info is longer than " << RegisterRequest::SIZE_CLIENT_NAME - 1 << " characters. Truncating.." << std::endl;
			}
			else {
				name = line;
			}
		}
		break;
	case 3:
		file_path = line;
		break;
	default:
		throw std::runtime_error("<Error>: Invalid amount of lines in transfer.info file.");
	}
}
void Client::get_transfer_info_content()
{
	std::ifstream file_transfer_info("transfer.info");
	if (!file_transfer_info.is_open()) {
		throw std::runtime_error("<Error>: transfer.info file could not be found.");
	}
	std::string line;
	int line_number = 1;
	while (line_number <= NUMBER_LINES_TRANSFER_INFO) {
		if (!std::getline(file_transfer_info, line)) {
			throw std::runtime_error("<Error>: transfer.info file is not in the expected form.");
		}
		parse_transfer_info_line(line_number, line);
		++line_number;
	}
	std::cout << "--------" << std::endl;
	std::cout << "<Info>: Retrieved transfer.info content:" << std::endl;
	std::cout << "<Info>: Address at: " << host << ":" << port << std::endl;
	std::cout << "<Info>: Client name: " << name << std::endl;
	std::cout << "<Info>: File path: " << file_path << std::endl;
	std::cout << "--------" << std::endl;
	file_transfer_info.close(); // not necessary, because of the RAII, but just for clarity
}
void Client::output_to_me_info() {
	std::cout << "<Info>: Doing changes to me.info.." << std::endl;
	std::ofstream me_info_file("me.info");
	if (!me_info_file.is_open()) {
		throw std::runtime_error("<Error>: Could not open me.info file.");
	}
	me_info_file << name << "\n" << crypto_manager.hexify(id.c_str(), 16);
	me_info_file.close();
}
bool Client::get_register_response(std::string& response_error_str) {
	ResponseHeader header = net_manager.receive_response_header();
	if (header.code != ResponseCode::REGISTER_SUCCESS) {
		response_error_str = proto_handler.get_response_code_description(header.code);
		return false;
	}
	std::cout << "<Info>: Registration accepted, getting client ID.." << std::endl;
	id = net_manager.receive_register_payload(header);
	std::cout << "<Info>: Client ID: " << crypto_manager.hexify(id.c_str(), 16) << std::endl;
	output_to_me_info();
	return true;
}
Request* Client::create_register()
{
	std::cout << "<Info> Started registeration process.." << std::endl;
	Request* request = proto_handler.create_registration_request(name);
	std::cout << "<Info> Created registration request.." << std::endl;
	return request;
}
void Client::output_to_priv_key(std::string private_key_64) {
	std::ofstream priv_key_file("priv.key");
	if (!priv_key_file.is_open()) {
		throw std::runtime_error("<Error>: Could not open priv.key file.");
	}
	priv_key_file << private_key_64;
	priv_key_file.close();
}
void Client::output_key_to_me_info(std::string private_key_64) {
	std::ofstream me_info_file("me.info", std::ios::app);
	if (!me_info_file.is_open()) {
		throw std::runtime_error("<Error>: Could not open me.info file.");
	}
	me_info_file << private_key_64;
	me_info_file.close();
}
std::string Client::create_public_key() {
	std::cout << "<Info>: Creating public and private key.." << std::endl;
	RSAPrivateWrapper rsa_private;
	std::string private_key_64 = crypto_manager.encode(rsa_private.getPrivateKey());
	std::cout << "<Info>: Updating priv.key and me.info with new private key.." << std::endl;
	output_to_priv_key(private_key_64);
	output_key_to_me_info(private_key_64);
	return rsa_private.getPublicKey();
}
std::string Client::get_private_key_from_priv_key() {
	std::ifstream priv_key_file("priv.key");
	std::string line, private_key_64;
	if (!priv_key_file.is_open()) {
		throw std::runtime_error("<Error>: Could not open priv.key file.");
	}
	while (std::getline(priv_key_file, line)) {
		private_key_64 += line;
	}
	return private_key_64;
}
void Client::retrieve_aes_key(const std::string& aes_string) {
	std::string private_key = crypto_manager.decode(get_private_key_from_priv_key());
	RSAPrivateWrapper rsa_private(private_key);
	aes_key = rsa_private.decrypt(aes_string);
	std::cout << "<Debug>: AES key length is " << aes_key.length() << std::endl;
	//std::cout << "<Debug>: AES key is " << crypto_manager.hexify(aes_key.c_str(), aes_key.length() + 1) << std::endl;
	std::cout << "<Info>: AES key retrieved and decrypted successfully." << std::endl;
	std::cout << "--------" << std::endl;
}
bool Client::get_send_public_key_response(std::string& response_error_str, uint32_t& response_return) {
	ResponseHeader header = net_manager.receive_response_header();

	if (header.code != ResponseCode::AES_KEY) {
		response_error_str = proto_handler.get_response_code_description(header.code);
		return false;
	}
	else {
		std::cout << "<Info>: Server received the public key successfully." << std::endl;
		std::cout << "<Info>: Checking the AES key from server.." << std::endl;
		if (header.payload_size <= 0) {
			throw std::runtime_error("<Error>: Server sent an invalid AES key size.");
		}
		std::cout << "<Info>: AES key seems fine!" << std::endl;
		std::cout << "--------" << std::endl;
		response_return = header.payload_size;
		return true;
	}
}
Request* Client::create_public_key_request() {
	std::string public_key = create_public_key();
	Request* request = proto_handler.create_send_public_key_request(id, name, public_key);
	return request;
}
uint32_t Client::perform_send_public_key() {
	return perform_operation<uint32_t>(
		net_manager,
		[this]() -> Request* { return create_public_key_request(); },
		[this](std::string& response_error_str, uint32_t& response_return) { return get_send_public_key_response(response_error_str, response_return); }
	);
}
void Client::get_aes_key(uint32_t aes_key_size) {
	std::cout << "<Info>: Attempt to receive AES key from server.." << std::endl;
	std::string aes_string = net_manager.receive_aes_key(aes_key_size);
	retrieve_aes_key(aes_string);
}
void Client::setup() {
	std::cout << "<Info>: Setting up the client.." << std::endl;
	get_me_info_content();
	get_transfer_info_content();
}
void Client::perform_register() {
	perform_operation(
		net_manager,
		[this]() -> Request* { return create_register(); },
		[this](std::string& response_error_str) { return get_register_response(response_error_str); }
	);
}
bool Client::get_reconnect_response(std::string& response_error_str, uint32_t& response_return) {
	ResponseHeader header = net_manager.receive_response_header();

	if (header.code == ResponseCode::RECONNECT_REJECTED) {
		std::cerr << "<Info>: Server rejected reconnection request." << std::endl;
		is_registered = false;
		response_error_str = proto_handler.get_response_code_description(header.code);
		net_manager.receive_reconnect_failure_payload(header);
		response_return = 0;
		return true; // to avoid another attempt, but reconnection has been rejected and proceed to register
	}
	else if (header.code == ResponseCode::RECONNECT_SUCCESS) { // AES key is sent
		std::cout << "<Info>: Server accepted reconnection request." << std::endl;
		std::cout << "<Info>: Checking the AES key from server.." << std::endl;
		if (header.payload_size <= 0) {
			throw std::runtime_error("<Error>: Server sent an invalid AES key size.");
		}
		std::cout << "<Info>: AES key seems fine!" << std::endl;
		std::cout << "--------" << std::endl;
		response_return = header.payload_size;
		return true;
	}
	else {
		response_error_str = proto_handler.get_response_code_description(header.code);
		return false;
	}
}
uint32_t Client::perform_attempt_reconnect() {
	std::cout << "<Info>: Attempting to reconnect to the server.." << std::endl;
	return perform_operation<uint32_t>(
		net_manager,
		[this]() -> Request* { return proto_handler.create_reconnect_request(id, name); },
		[this](std::string& response_error_str, uint32_t& response_return) { return get_reconnect_response(response_error_str, response_return); }
	);
}

void Client::send_file_chunks(FileChunker& chunker) {
	while (!chunker.is_finished()) {
		std::string chunk = chunker.get_next();
		Request* request = proto_handler.create_send_file_request(
			id,
			chunker.get_size(),
			chunker.get_original_size(),
			static_cast<uint16_t>(chunker.get_total_reads()),
			static_cast<uint16_t>(chunker.total_chunks()),
			chunker.get_file_name(),
			chunk
		);
		net_manager.send_request(request);
		std::cout << "<Info>: Packet " << chunker.get_total_reads() << " out of " << chunker.total_chunks() << " sent." << std::endl;
		delete request;
	}
}
void Client::print_file_info(const FileChunker& chunker) const {
	std::cout << "<Info>: Processing the file.." << std::endl;
	std::cout << "<Info>: Original file size: " << chunker.get_original_size() << " bytes" << std::endl;
	std::cout << "<Info>: Encrypted file size: " << chunker.get_size() << " bytes" << std::endl;
	std::cout << "<Info>: Total packets to send: " << chunker.total_chunks() << std::endl;
}
bool Client::get_send_file_response(std::string& response_error_str, unsigned long& server_crc) {
	ResponseHeader header = net_manager.receive_response_header();
	if (header.code != ResponseCode::SEND_FILE_SUCCESS) {
		response_error_str = proto_handler.get_response_code_description(header.code);
		return false;
	}
	server_crc = net_manager.receive_send_file_payload();
	return true;
}
bool Client::check_crc(const unsigned long& client_crc, const uint32_t& server_crc) const {
	std::cout << "<Info>: Client CRC: " << client_crc << std::endl;
	std::cout << "<Info>: Server CRC: " << server_crc << std::endl;
	if (client_crc == server_crc) {
		std::cout << "<Info>: CRC check passed." << std::endl;
		return true;
	}
	std::cerr << "<Error>: CRC check failed." << std::endl;
	return false;

}
bool Client::get_message_confirm_response(std::string& response_error_str) {
	ResponseHeader header = net_manager.receive_response_header();
	if (header.code != ResponseCode::MESSAGE_CONFIRM) {
		response_error_str = proto_handler.get_response_code_description(header.code);
		return false;
	}
	std::cout << "<Info>: Server confirmed the message." << std::endl;
	net_manager.receive_confirm_message_payload();
	return true;
}
void Client::perform_send_crc_correct(const std::string& file_name) {
	std::cout << "<Info>: Sending CRC correct state to server.." << std::endl;
	perform_operation(
		net_manager,
		[this, file_name]() -> Request* { return proto_handler.create_crc_state_request(id, file_name, Client::STATE_CORRECT); },
		[this](std::string& response_error_str) { return get_message_confirm_response(response_error_str); }
	);
}
void Client::perform_send_crc_bad(const std::string& file_name) {
	std::cout << "<Info>: Sending CRC bad state to server.." << std::endl;
	perform_operation(
		net_manager,
		[this, file_name]() -> Request* { return proto_handler.create_crc_state_request(id, file_name, Client::STATE_BAD); },
		[this](std::string& response_error_str) { return true; } // not expecting a response from server
	);
}
void Client::perform_send_crc_terminate(const std::string& file_name) {
	std::cout << "<Info>: Sending CRC terminate state to server.." << std::endl;
	perform_operation(
		net_manager,
		[this, file_name]() -> Request* { return proto_handler.create_crc_state_request(id, file_name, Client::STATE_TERMINATE); },
		[this](std::string& response_error_str) { return get_message_confirm_response(response_error_str); }
	);
}
void Client::perform_send_file() {
	std::cout << "<Info>: Starting the process of sending the file " << file_path << std::endl;
	CRCHandler crc_handler;
	std::future<unsigned long> future_crc = crc_handler.calculate(file_path);
	FileChunker chunker(file_path, aes_key);
	print_file_info(chunker);
	std::string file_name = chunker.get_file_name();
	unsigned long calculated_crc = future_crc.get(), server_crc{}; // client, server CRCs
	std::string response_error_str;
	for (auto attempt = 1; attempt <= ProtocolHandler::NUMBER_OF_ATTEMPTS; ++attempt) {
		std::cout << "<Info>: Attempt #" << attempt << " to send the file.." << std::endl;
		send_file_chunks(chunker);
		if (!get_send_file_response(response_error_str, server_crc)) {
			std::cerr << "<Error>: server responded with error" << std::endl;
		}
		else {
			std::cout << "<Info>: Server received the file, checking CRC.." << std::endl;
			if (check_crc(calculated_crc, server_crc)) {
				perform_send_crc_correct(file_name);
				return;
			}
			else if (attempt <= ProtocolHandler::NUMBER_OF_ATTEMPTS-1) {
				perform_send_crc_bad(file_name);
			}
			else {
				// in-case of a last attempt
				perform_send_crc_terminate(file_name);
			}
		}
	}
}
void Client::start()
{
	setup();
	net_manager.establish(host, std::to_string(port));
	uint32_t aes_key_size{};
	if (is_registered) {
		aes_key_size = perform_attempt_reconnect(); // attempts to check if the me.info data valid server-side wise
	}
	if (!is_registered) { // if registered was flagged true and reconnect failed, will be flagged false again
		perform_register();
		aes_key_size = perform_send_public_key();
	}
	get_aes_key(aes_key_size);
	perform_send_file();
}