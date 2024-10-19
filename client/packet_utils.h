#pragma once

#include <vector>
#include <cstdint>
#include <string>

namespace PacketUtils {

	// inserts the bytes of the data into the packet
	void insert_to_packet(std::vector<uint8_t>& packet, const void* data, size_t size);

	// terminates the string with null terminators to match the field size
	void terminate_payload_string(std::string& field_name, size_t field_size);
}