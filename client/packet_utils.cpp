#include "packet_utils.h"
#include <iostream>

void PacketUtils::insert_to_packet(std::vector<uint8_t>& packet, const void* data, size_t size)
{
	std::vector<uint8_t> bytes(size);
	memcpy_s(bytes.data(), size, data, size);
	packet.insert(packet.end(), bytes.begin(), bytes.end());
}
void PacketUtils::terminate_payload_string(std::string& field_str, size_t field_size)
{
	if (field_str.length() >= field_size) { // equals cause we considering the null terminator
		std::cerr << "<Warning>: the naming field is too long, there is going to be a data loss." << std::endl;
		field_str = field_str.substr(0, field_size - 1);
	}
	while (field_str.length() != field_size) {
		field_str.push_back('\0');
	}
}