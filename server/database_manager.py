from sqlite3 import *
from threading import Lock

from client import Client
from crypto_manager import SingletonMeta, CryptoManager
from request import RequestHeader, RegisterRequest
from transferred_file import TransferredFile


class DatabaseManager(metaclass=SingletonMeta):
    """ Database class for handling all database operations with facade pattern """

    # Database file name
    DB_FILE_NAME = 'defensive.db'
    # Size of the last seen field in bytes
    SIZE_LAST_SEEN = 100

    # Create table query for clients
    DB_CREATE_TABLE_CLIENTS_QUERY = f"""
        CREATE TABLE IF NOT EXISTS clients (
        id VARCHAR({RequestHeader.SIZE_CLIENT_ID}) PRIMARY KEY,
        name VARCHAR({RegisterRequest.SIZE_CLIENT_NAME}) NOT NULL,
        last_seen VARCHAR({SIZE_LAST_SEEN}),
        rsa_public_key BLOB,
        aes_key BLOB
    );
    """
    # Create table query for files
    DB_CREATE_TABLE_FILES_QUERY = f"""
        CREATE TABLE IF NOT EXISTS files (
            id VARCHAR({RequestHeader.SIZE_CLIENT_ID}) NOT NULL,
            name VARCHAR({TransferredFile.SIZE_FILE_NAME}) NOT NULL,
            path_name VARCHAR({TransferredFile.SIZE_FILE_PATH}) PRIMARY KEY,
            verified BOOLEAN
        );
    """

    def __init__(self):
        self.clients = {}
        self.transferred_files = {}
        self._sql_connection = None

    def _connect(self):
        """Connect to the database."""
        self._sql_connection = connect(
            DatabaseManager.DB_FILE_NAME,
            check_same_thread=False
        )

    def _create_tables(self) -> None:
        """Create tables if they don't exist."""

        cursor = self._sql_connection.cursor()
        cursor.execute(DatabaseManager.DB_CREATE_TABLE_CLIENTS_QUERY)
        cursor.execute(DatabaseManager.DB_CREATE_TABLE_FILES_QUERY)
        cursor.close()
        self._sql_connection.commit()

    def _load_clients(self) -> None:
        """Load all clients from the database."""
        query = "SELECT id, name, last_seen, rsa_public_key, aes_key FROM clients"
        cursor = self._sql_connection.cursor()
        clients_table = cursor.execute(query).fetchall()

        for client_id, client_name, last_seen, rsa_public_key, aes_key in clients_table:
            self.clients[client_id] = Client(client_id, client_name, last_seen, rsa_public_key, aes_key)

    def _load_files(self) -> None:
        """Load all files from the database."""
        query = "SELECT id, name, path_name, verified FROM files"

        # Using context manager for the cursor
        cursor = self._sql_connection.cursor()
        files_table = cursor.execute(query).fetchall()

        for client_id, file_name, path_name, verified in files_table:
            self.transferred_files[path_name] = TransferredFile(client_id, file_name, path_name, verified)

    def _get_all_data(self) -> None:
        """Getting all the data from the database"""
        self._load_clients()
        self._load_files()

    def load_up(self) -> None:
        """Load up the database"""
        self._connect()
        self._create_tables()
        self._get_all_data()
        self.print_clients()
        self.print_files()

    def _client_exists(self, client_id: str) -> bool:
        return client_id in self.clients

    def get_client(self, id: str, name: str) -> Client | None:
        """Matches a client from the database using its name and ID together."""
        if id in self.clients and name == self.clients[id].get_name():
            return self.clients[id]
        return None

    def _check_client_name_exists(self, name: str) -> bool:
        """Check if a client name exists in the database."""
        for client in self.clients.values():
            if client.get_name() == name:
                return True
        return False

    def create_client(self, name: str, last_seen: str) -> str | None:
        """Create a new client in the database."""

        if self._check_client_name_exists(name):  # 2 clients cannot have same name
            return None

        new_id = CryptoManager().generate_uuid()

        # There might be a small, yet effective, chance of collision, generate a new ID by then
        while self._client_exists(new_id):
            new_id = CryptoManager().generate_uuid()

        self.clients[new_id] = Client(new_id, name, last_seen)
        cursor = self._sql_connection.cursor()
        cursor.execute(
            "INSERT INTO clients (id, name, last_seen, rsa_public_key, aes_key) VALUES (?, ?, ?, ?, ?)",
            (new_id, name, last_seen, None, None)
        )
        cursor.close()
        self._sql_connection.commit()
        return new_id

    def create_file(self, id: str, file_name: str) -> bool:
        """Create a new file in the database."""
        from file_handler import FileHandler
        file_path = FileHandler().get_path(id, file_name)
        if not self._client_exists(id):
            return False
        self.transferred_files[file_path] = TransferredFile(id, file_name, file_path)
        cursor = self._sql_connection.cursor()
        # this "replace" in-case something goes wrong and the file was already in the db
        cursor.execute("INSERT OR REPLACE INTO files (id, name, path_name, verified) VALUES (?, ?, ?, ?)",
                       (id, file_name, file_path, False))
        cursor.close()
        self._sql_connection.commit()
        return True

    def print_clients(self) -> None:
        msg = "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
        msg += "~~~~~~~ Current clients in database ~~~~~~~\n"
        msg += "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
        for client in list(self.clients.values()):
            msg += str(client)
            msg += "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
        msg += "Printed all clients in the database.\n"
        print(msg)

    def print_files(self) -> None:
        msg = "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
        msg += "~~~~~~~ Current files in database ~~~~~~~\n"
        msg += "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
        for file in list(self.transferred_files.values()):
            msg += str(file)
            msg += "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
        msg += "Printed all files in the database.\n"
        print(msg)

    def verify_file(self, path_name: str) -> None:
        """Verify a file in the database."""
        if path_name in self.transferred_files:
            self.transferred_files[path_name].set_verified(True)
            cursor = self._sql_connection.cursor()
            cursor.execute("UPDATE files SET verified = ? WHERE path_name = ?", (True, path_name))
            cursor.close()
            self._sql_connection.commit()

    def update_aes_key(self, id: str, aes_key: bytes) -> None:
        """Update the AES key of a client."""
        if self._client_exists(id):
            self.clients[id].set_aes_key(aes_key)
            cursor = self._sql_connection.cursor()
            cursor.execute("UPDATE clients SET aes_key = ? WHERE id = ?", (aes_key, id))
            cursor.close()
            self._sql_connection.commit()

    def get_aes_key(self, id: str) -> bytes | None:
        if id in self.clients:
            return self.clients[id].get_aes_key()
        return None

    def update_rsa_public_key(self, id: str, rsa_public_key: bytes) -> None:
        """Update the RSA public key of a client."""
        if self._client_exists(id):
            self.clients[id].set_public_key(rsa_public_key)
            cursor = self._sql_connection.cursor()
            cursor.execute("UPDATE clients SET rsa_public_key = ? WHERE id = ?", (rsa_public_key, id))
            cursor.close()
            self._sql_connection.commit()

    def update_last_seen(self, id: str, last_seen: str) -> None:
        """Update the last seen of a client."""
        if self._client_exists(id):
            self.clients[id].set_last_seen(last_seen)
            cursor = self._sql_connection.cursor()
            cursor.execute("UPDATE clients SET last_seen = ? WHERE id = ?", (last_seen, id))
            cursor.close()
            self._sql_connection.commit()
