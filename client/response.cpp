#include "response.h"

ResponseHeader::ResponseHeader(uint8_t version, uint16_t code, uint32_t payload_size)
	: version(version), code(code), payload_size(payload_size)
{
}
