import socket
import selectors

from database_manager import DatabaseManager
from network_manager import NetworkManager
from request import RequestHeader, Request
from response import Response


class Server:
    """Server class for handling all server operations and delegating them to responsible instances."""

    # current server version
    VERSION = 3

    def __init__(self, host: str, port: int):
        self._host = host
        self._port = port
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._net_manager = NetworkManager()
        self._db_manager = DatabaseManager()

    def _print_request_info(self, header: RequestHeader, request: Request):
        if header.code != RequestHeader.OPCODE_REGISTER:
            print(f"<Info>: ID: {header.client_id.hex()} "
                  f"{f"({request.name})" if header.code < RequestHeader.OPCODE_SEND_FILE else ""} "
                  f"has sent a {request.get_name()} request..")
        else:
            print(f"<Info>: A client "
                  f"{f"({request.name})" if header.code < RequestHeader.OPCODE_SEND_FILE else ""} "
                  f"has sent a {request.get_name()} request..")

    def _print_response_info(self, header: RequestHeader, response: Response):
        response_name = response.get_name()
        if header.code != RequestHeader.OPCODE_REGISTER:
            print(f"<Info>: Responding to client ID: {header.client_id.hex()} with a {response.get_name()} response..")
        else:
            print(f"<Info>: Responding to a client with a {response.get_name()} response..")

    def _read(self, connection, mask):
        try:
            header: RequestHeader = self._net_manager.get_header(self._selector, connection)
            if not header:
                return
            if not self._net_manager.is_valid_header(header):
                response = self._net_manager.create_failure_response()
                self._net_manager.send_response(connection, response)
                return
            request = self._net_manager.infer_payload(connection, header)
            self._print_request_info(header, request)
            response = request.execute()
            if response:
                self._print_response_info(header, response)
                self._net_manager.send_response(connection, response)

        except (ConnectionResetError, ConnectionAbortedError):
            self._net_manager.close_connection(self._selector, connection, "Connection error")

    def _accept(self, sock, mask):
        connection, addr = sock.accept()
        print('<Info>: A client incoming from:', addr, "..")
        self._selector.register(connection, selectors.EVENT_READ, self._read)

    def _internal_initialize(self):
        # Bind the socket to the host and port
        self._socket.bind((self._host, self._port))
        self._socket.listen()
        self._socket.setblocking(False)

        # selector setting up
        self._selector = selectors.DefaultSelector()
        self._selector.register(self._socket, selectors.EVENT_READ, self._accept)

        # Load up the database (inc. connection, data, etc..)
        self._db_manager.load_up()

    def start(self):
        print('Server started at', self._port)
        self._internal_initialize()
        print("<Info>: Server fully initialized and waiting for requests..")

        while True:
            events = self._selector.select()
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)
