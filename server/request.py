from datetime import datetime

import check_sum
from response import Response, RegisterSuccessResponse, ResponseHeader, RegisterFailureResponse, PayloadResponse, \
    AESKeyResponse, ReconnectResponse, ReconnectResponseFailure, AcceptedFileResponse, MessageConfirmResponse
from crypto_manager import CryptoManager


class RequestHeader:
    # Header field sizes
    SIZE = 23
    SIZE_CLIENT_ID = 16
    SIZE_CLIENT_VERSION = 1
    SIZE_CODE = 2
    SIZE_PAYLOAD_SIZE = 4

    # Request codes
    OPCODE_REGISTER = 825
    OPCODE_SEND_PUBLIC_KEY = 826
    OPCODE_RECONNECT = 827
    OPCODE_SEND_FILE = 828
    OPCODE_CRC_OK = 900
    OPCODE_CRC_NOT_OK = 901
    OPCODE_CRC_TERMINATE = 902

    # Valid request codes
    possible_codes = {
        OPCODE_REGISTER,
        OPCODE_SEND_PUBLIC_KEY,
        OPCODE_RECONNECT,
        OPCODE_SEND_FILE,
        OPCODE_CRC_OK,
        OPCODE_CRC_NOT_OK,
        OPCODE_CRC_TERMINATE,
    }

    # Header field unpacking struct
    UNPACK_HEADER_STRUCT = '<BHI'

    def __init__(self, client_id: bytes, client_version: int, code: int, payload_size: int):
        self.client_id = client_id
        self.client_version = client_version
        self.code = code
        self.payload_size = payload_size


class Request:
    def __init__(self, header: RequestHeader):
        self._header = header

    def execute(self) -> Response:
        pass

    def get_name(self):
        pass


class RegisterRequest(Request):
    SIZE_CLIENT_NAME = 255

    def __init__(self, header: RequestHeader, name: str):
        super().__init__(header)
        self.name = name

    def get_name(self):
        return "registration"

    def execute(self) -> Response:
        from server import Server
        from database_manager import DatabaseManager
        print(f"<Info>: Attempting to registering new client named: {self.name}")
        client_id = DatabaseManager().create_client(self.name, str(datetime.now()))
        if client_id:
            print(f"<Info>: New client named: {self.name} was given id: {client_id}")
            return RegisterSuccessResponse(
                ResponseHeader(
                    Server.VERSION,
                    ResponseHeader.CODE_REGISTER_SUCCESS,
                    PayloadResponse.SIZE_CLIENT_ID
                ),
                client_id
            )

        else:
            return RegisterFailureResponse(
                ResponseHeader(
                    Server.VERSION,
                    ResponseHeader.CODE_REGISTER_FAILURE,
                    0
                )
            )


class SendPublicKeyRequest(Request):
    SIZE_CLIENT_NAME = 255
    SIZE_PUBLIC_KEY = 160

    def __init__(self, header: RequestHeader, name: str, public_key: bytes):
        super().__init__(header)
        self.name = name
        self.public_key = public_key

    def get_name(self):
        return "sending public key"

    def execute(self) -> Response:
        from server import Server
        from database_manager import DatabaseManager
        db = DatabaseManager()
        client = db.get_client(self._header.client_id.hex(), self.name)
        if client:
            db.update_last_seen(self._header.client_id.hex(), str(datetime.now()))
            new_aes_key = CryptoManager().generate_aes()
            encrypted_aes = CryptoManager().rsa_encrypt(self.public_key, new_aes_key)
            db.update_rsa_public_key(self._header.client_id.hex(), self.public_key)
            if encrypted_aes:
                db.update_aes_key(self._header.client_id.hex(), new_aes_key)
                return AESKeyResponse(
                    ResponseHeader(
                        Server.VERSION,
                        ResponseHeader.CODE_SEND_AES,
                        RequestHeader.SIZE_CLIENT_ID + len(encrypted_aes)
                    ),
                    self._header.client_id.hex(),
                    encrypted_aes
                )
        return RegisterFailureResponse(
            ResponseHeader(
                Server.VERSION,
                ResponseHeader.CODE_REGISTER_FAILURE,
                0
            )
        )


class ReconnectRequest(Request):
    SIZE_CLIENT_NAME = 255

    def __init__(self, header: RequestHeader, name: str):
        super().__init__(header)
        self.name = name

    def get_name(self):
        return "reconnecting"

    def execute(self) -> Response:
        from server import Server
        from database_manager import DatabaseManager

        db = DatabaseManager()
        client_id_hexified = self._header.client_id.hex()
        client = db.get_client(client_id_hexified, self.name)
        if client:
            # Only update the last seem if the client is found
            db.update_last_seen(client_id_hexified, str(datetime.now()))
            public_key = client.get_public_key()
            if public_key:
                new_aes_key = CryptoManager().generate_aes()
                db.update_aes_key(client_id_hexified, new_aes_key)
                encrypted_aes = CryptoManager().rsa_encrypt(public_key, new_aes_key)
                if encrypted_aes:
                    return ReconnectResponse(
                        ResponseHeader(
                            Server.VERSION,
                            ResponseHeader.CODE_RECONNECT_SUCCESS,
                            RequestHeader.SIZE_CLIENT_ID + len(encrypted_aes)
                        ),
                        client_id_hexified,
                        encrypted_aes
                    )
        return ReconnectResponseFailure(
            ResponseHeader(
                Server.VERSION,
                ResponseHeader.CODE_RECONNECT_FAILURE,
                RequestHeader.SIZE_CLIENT_ID
            ),
            client_id_hexified
        )


class SendFileRequest(Request):
    SIZE_CONTENT_SIZE = 4
    SIZE_ORIGINAL_FILE_SIZE = 4
    SIZE_PACKET_NUMBER = 2
    SIZE_TOTAL_PACKETS = 2
    SIZE_FILE_NAME = 255

    # struct unpacking format for pre-content data
    UNPACK_PRE_FILE_NAME_AND_CONTENT_STRUCT = '<IIHH'

    def __init__(
            self, header: RequestHeader,
            content_size: int,
            original_file_size: int,
            packet_number: int,
            total_packets: int,
            file_name: str,
            content: bytes
    ):
        super().__init__(header)
        self.content_size = content_size
        self.original_file_size = original_file_size
        self.file_name = file_name
        self.packet_number = packet_number
        self.total_packets = total_packets
        self.content = content

    def get_name(self):
        return "sending file"

    def execute(self) -> Response | None:
        from server import Server
        from database_manager import DatabaseManager
        from protocol_handler import ProtocolHandler
        from file_handler import FileHandler
        proto_handler = ProtocolHandler()
        file_handler = FileHandler()
        db = DatabaseManager()
        client_id_hexified = self._header.client_id.hex()
        db.update_last_seen(client_id_hexified, str(datetime.now()))
        if self.content_size <= 0:
            print("<Error>: File content size is not correct.")
            return proto_handler.create_failure_response()
        print(
            f"<Info>: ID: {client_id_hexified} sent packet {self.packet_number} of {self.total_packets} "
            f"for file name: {self.file_name}.."
        )
        file_handler.save_in_dir(client_id_hexified, self.file_name, self.content,
                                 "wb" if self.packet_number == 1 else "ab")

        if self.packet_number == self.total_packets:
            # time to decrypt the file and store it in the db
            file_path = file_handler.get_path(client_id_hexified, self.file_name)  # joined proper path
            aes_key = db.get_aes_key(client_id_hexified)
            file_handler.decrypt_file(file_path, aes_key)
            db.create_file(client_id_hexified, self.file_name)
            calculated_crc = check_sum.calculate(file_path)
            print(f"<Info>: ID: {client_id_hexified} has fully sent the file: {self.file_name}")
            return AcceptedFileResponse(
                ResponseHeader(
                    Server.VERSION,
                    ResponseHeader.CODE_ACCEPTED_FILE,
                    RequestHeader.SIZE_CLIENT_ID +
                    AcceptedFileResponse.SIZE_CONTENT_SIZE +
                    AcceptedFileResponse.SIZE_FILE_NAME +
                    AcceptedFileResponse.SIZE_CRC
                ),
                client_id_hexified,
                self.content_size,
                self.file_name,
                calculated_crc
            )
        return None  # packet number != total packets


class CRCOkRequest(Request):
    SIZE_FILE_NAME = 255

    def __init__(self, header: RequestHeader, file_name: str):
        super().__init__(header)
        self.file_name = file_name

    def get_name(self):
        return "CRC OK"

    def execute(self) -> Response:
        from database_manager import DatabaseManager
        from file_handler import FileHandler
        from server import Server
        db = DatabaseManager()
        file_handler = FileHandler()
        db.update_last_seen(self._header.client_id.hex(), str(datetime.now()))
        db.verify_file(file_handler.get_path(self._header.client_id.hex(), self.file_name))
        print(f"<Info>: ID: {self._header.client_id.hex()} verified file: {self.file_name}")
        return MessageConfirmResponse(
            ResponseHeader(
                Server.VERSION,
                ResponseHeader.CODE_MESSAGE_CONFIRM,
                RequestHeader.SIZE_CLIENT_ID
            ),
            self._header.client_id.hex()
        )

class CRCNotOkRequest(Request):
    def __init__(self, header: RequestHeader, file_name: str):
        super().__init__(header)
        self.file_name = file_name

    def get_name(self):
        return "CRC NOT OK"

    def execute(self) -> None:
        from database_manager import DatabaseManager
        db = DatabaseManager()
        db.update_last_seen(self._header.client_id.hex(), str(datetime.now()))
        return None

class CRCTerminateRequest(Request):
    def __init__(self, header: RequestHeader, file_name: str):
        super().__init__(header)
        self.file_name = file_name

    def get_name(self):
        return "CRC TERMINATE"

    def execute(self) -> Response:
        from database_manager import DatabaseManager
        from server import Server
        db = DatabaseManager()
        db.update_last_seen(self._header.client_id.hex(), str(datetime.now()))
        return MessageConfirmResponse(
            ResponseHeader(
                Server.VERSION,
                ResponseHeader.CODE_MESSAGE_CONFIRM,
                RequestHeader.SIZE_CLIENT_ID
            ),
            self._header.client_id.hex()
        )