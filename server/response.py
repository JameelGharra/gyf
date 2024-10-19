import struct


class ResponseHeader:
    # Response codes
    CODE_REGISTER_SUCCESS = 1600
    CODE_REGISTER_FAILURE = 1601
    CODE_SEND_AES = 1602
    CODE_ACCEPTED_FILE = 1603
    CODE_MESSAGE_CONFIRM = 1604
    CODE_RECONNECT_SUCCESS = 1605
    CODE_RECONNECT_FAILURE = 1606
    CODE_FAILURE = 1607

    RESPONSE_HEADER_STRUCT = "<BHI"

    def __init__(self, version, code, payload_size):
        self.version = version
        self.code = code
        self.payload_size = payload_size

    def pack(self):
        return struct.pack(ResponseHeader.RESPONSE_HEADER_STRUCT, self.version, self.code, self.payload_size)


class Response:
    def __init__(self, header: ResponseHeader):
        self._header = header

    def create_packet(self) -> bytes:
        return self._header.pack()

    def get_name(self):
        pass


class PayloadResponse(Response):
    SIZE_CLIENT_ID = 16

    def __init__(self, header: ResponseHeader, client_id: str):
        super().__init__(header)
        self.client_id = client_id

    def create_packet(self) -> bytes:
        return super().create_packet() + bytes.fromhex(self.client_id)


class FailureResponse(Response):
    def __init__(self, header: ResponseHeader):
        super().__init__(header)
        print("<Error>: Server failed to retrieve correct data.")

    def get_name(self):
        return "failure"

    def create_packet(self) -> bytes:
        return super().create_packet()


class RegisterSuccessResponse(PayloadResponse):
    def __init__(self, header: ResponseHeader, client_id: str):
        super().__init__(header, client_id)

    def get_name(self):
        return "registration success"

    def create_packet(self) -> bytes:
        return super().create_packet()


class RegisterFailureResponse(Response):
    def __init__(self, header: ResponseHeader):
        super().__init__(header)

    def get_name(self):
        return "registration failure"

    def create_packet(self) -> bytes:
        return super().create_packet()


class AESKeyResponse(PayloadResponse):

    def __init__(self, header: ResponseHeader, client_id: str, aes_key_encrypted: bytes):
        super().__init__(header, client_id)
        self.aes_key_encrypted = aes_key_encrypted

    def get_name(self):
        return "sending AES key"

    def create_packet(self) -> bytes:
        return super().create_packet() + self.aes_key_encrypted


class ReconnectResponse(AESKeyResponse):  # same as AESKeyResponse, but just separating concerns
    def __init__(self, header: ResponseHeader, client_id: str, aes_key_encrypted: bytes):
        super().__init__(header, client_id, aes_key_encrypted)

    def get_name(self):
        return "reconnect success"


class ReconnectResponseFailure(PayloadResponse):
    def __init__(self, header: ResponseHeader, client_id: str):
        super().__init__(header, client_id)

    def get_name(self):
        return "reconnect failure"

    def create_packet(self) -> bytes:
        return super().create_packet()


class AcceptedFileResponse(PayloadResponse):
    SIZE_CONTENT_SIZE = 4
    SIZE_FILE_NAME = 255
    SIZE_CRC = 4

    def __init__(self, header: ResponseHeader, client_id: str, content_size: int, file_name: str, checksum: int):
        super().__init__(header, client_id)
        self.content_size = content_size
        self.file_name = file_name
        self.checksum = checksum

    def get_name(self):
        return "accepted file, sent crc"

    def create_packet(self) -> bytes:
        return (super().create_packet() +
                struct.pack("<I", self.content_size) +
                self.file_name.encode().ljust(AcceptedFileResponse.SIZE_FILE_NAME, b'\0') +
                struct.pack("<I", self.checksum)
                )

class MessageConfirmResponse(PayloadResponse):

    def __init__(self, header: ResponseHeader, client_id: str):
        super().__init__(header, client_id)

    def get_name(self):
        return "message confirmed"

    def create_packet(self) -> bytes:
        return super().create_packet()

