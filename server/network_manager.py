import socket
import struct
from selectors import DefaultSelector

from crypto_manager import CryptoManager
from protocol_handler import ProtocolHandler
from request import Request, RequestHeader, RegisterRequest, SendPublicKeyRequest, ReconnectRequest, SendFileRequest, \
    CRCOkRequest, CRCNotOkRequest, CRCTerminateRequest
from response import Response
from transferred_file import TransferredFile


class NetworkManager:

    def __init__(self):
        self._protocol_handler = ProtocolHandler()
        self._crypto_manager = CryptoManager()

    def close_connection(self, selector: DefaultSelector, connection: socket.socket, reason: str):
        """Handle connection closure and cleanup."""
        print(f"<Info>: A connection is being closed, reason: {reason}")
        print(f"<Info>: Connection closed: {connection}")
        selector.unregister(connection)
        connection.close()

    def is_valid_header(self, header: RequestHeader) -> bool:
        """Check if the request header is valid."""
        return self._protocol_handler.is_valid_request_code(header.code)

    def get_header(self, selector: DefaultSelector, connection: socket.socket) -> RequestHeader | None:
        """Retrieve and unpack the request header from a connection."""
        try:
            header_raw_data = connection.recv(RequestHeader.SIZE)

            if not header_raw_data[:RequestHeader.SIZE_CLIENT_ID]:
                self.close_connection(selector, connection, "Client left the server (no data received)")
                return None

            return self._protocol_handler.unpack_request_header(header_raw_data)

        except (ConnectionResetError, ConnectionAbortedError):
            self.close_connection(selector, connection, "Connection error")
            return None

    def create_failure_response(self) -> Response:
        return self._protocol_handler.create_failure_response()

    def send_response(self, connection: socket.socket, response: Response) -> None:
        """Send a response to the client."""
        connection.send(response.create_packet())

    def get_register_payload(self, connection: socket.socket, header: RequestHeader) -> Request:
        raw_data = connection.recv(RegisterRequest.SIZE_CLIENT_NAME)
        client_name = self._protocol_handler.remove_null(raw_data).decode()
        return RegisterRequest(header, client_name)

    def get_public_key_payload(self, connection: socket.socket, header: RequestHeader) -> Request:
        raw_data = connection.recv(SendPublicKeyRequest.SIZE_CLIENT_NAME)
        client_name = self._protocol_handler.remove_null(raw_data).decode()
        public_key = connection.recv(SendPublicKeyRequest.SIZE_PUBLIC_KEY)
        return SendPublicKeyRequest(header, client_name, public_key)

    def get_reconnect_payload(self, connection: socket.socket, header: RequestHeader) -> Request:
        raw_data = connection.recv(RegisterRequest.SIZE_CLIENT_NAME)
        client_name = self._protocol_handler.remove_null(raw_data).decode()
        return ReconnectRequest(header, client_name)

    def get_send_file_payload(self, connection: socket.socket, header: RequestHeader) -> Request:
        pre_file_name_and_content_size = (SendFileRequest.SIZE_CONTENT_SIZE +
                                          SendFileRequest.SIZE_ORIGINAL_FILE_SIZE +
                                          SendFileRequest.SIZE_PACKET_NUMBER +
                                          SendFileRequest.SIZE_TOTAL_PACKETS)
        raw_data = connection.recv(pre_file_name_and_content_size)
        (content_size,
         original_file_size,
         packet_number,
         total_packets) = struct.unpack(SendFileRequest.UNPACK_PRE_FILE_NAME_AND_CONTENT_STRUCT, raw_data)
        raw_data = connection.recv(SendFileRequest.SIZE_FILE_NAME)
        file_name = self._protocol_handler.remove_null(raw_data).decode()
        encrypted_file_size = header.payload_size - pre_file_name_and_content_size - SendFileRequest.SIZE_FILE_NAME
        file_content_encrypted = connection.recv(encrypted_file_size)
        return SendFileRequest(
            header,
            content_size,
            original_file_size,
            packet_number,
            total_packets,
            file_name,
            file_content_encrypted
        )

    def get_crc_ok_payload(self, connection: socket.socket, header: RequestHeader) -> Request:
        raw_data = connection.recv(CRCOkRequest.SIZE_FILE_NAME)
        file_name = self._protocol_handler.remove_null(raw_data).decode()
        return CRCOkRequest(header, file_name)

    def bad_crc_requests(self, connection: socket.socket, header: RequestHeader, send_confirm: bool) -> Request:
        raw_data = connection.recv(TransferredFile.SIZE_FILE_NAME)
        file_name = self._protocol_handler.remove_null(raw_data).decode()
        if send_confirm:
            return CRCNotOkRequest(header, file_name)
        return CRCTerminateRequest(header, file_name)

    def infer_payload(self, connection: socket.socket, header: RequestHeader) -> Request:
        if header.code == RequestHeader.OPCODE_REGISTER:
            return self.get_register_payload(connection, header)
        elif header.code == RequestHeader.OPCODE_SEND_PUBLIC_KEY:
            return self.get_public_key_payload(connection, header)
        elif header.code == RequestHeader.OPCODE_RECONNECT:
            return self.get_reconnect_payload(connection, header)
        elif header.code == RequestHeader.OPCODE_SEND_FILE:
            return self.get_send_file_payload(connection, header)
        elif header.code == RequestHeader.OPCODE_CRC_OK:
            return self.get_crc_ok_payload(connection, header)
        elif header.code == RequestHeader.OPCODE_CRC_NOT_OK or header.code == RequestHeader.OPCODE_CRC_TERMINATE:
            return self.bad_crc_requests(connection, header, False)
