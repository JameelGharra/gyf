import struct

from crypto_manager import SingletonMeta
from request import RequestHeader
from response import FailureResponse, ResponseHeader, Response


class ProtocolHandler(metaclass=SingletonMeta):
    def remove_null(self, data: bytes) -> bytes:
        """Remove null bytes from the data."""
        return data[:data.find(b'\0')]

    def is_valid_request_code(self, code: int) -> bool:
        """Check if the request code is valid."""
        return code in RequestHeader.possible_codes

    def unpack_request_header(self, header_raw_data: bytes) -> RequestHeader | None:
        """Unpack the header data into a RequestHeader object."""
        client_id = header_raw_data[:RequestHeader.SIZE_CLIENT_ID]
        client_version, code, payload_size = struct.unpack(RequestHeader.UNPACK_HEADER_STRUCT,
                                                           header_raw_data[RequestHeader.SIZE_CLIENT_ID:])

        return RequestHeader(client_id, client_version, code, payload_size)

    def create_failure_response(self) -> Response:
        """Create a failure response."""
        from server import Server  # Did this to avoid circular import
        return FailureResponse(ResponseHeader(Server.VERSION, ResponseHeader.CODE_FAILURE, 0))
