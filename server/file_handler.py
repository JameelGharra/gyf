from crypto_manager import SingletonMeta
import os


class FileHandler(metaclass=SingletonMeta):
    # root directory where transferred files are stored
    ROOT_DIR = 'transferred_files'

    def get_path(self, clientid: str, file_name: str):
        """Get the path of the file."""
        return os.path.join(FileHandler.ROOT_DIR, clientid, file_name)

    def save_in_dir(self, client_id: str, file_name: str, content: bytes, mode: str = "wb") -> None:
        """Save the file in the directory."""

        # protection against directory traversal attacks for e.g. ../../../../some/important/file, will take file
        file_name = os.path.basename(file_name)
        os.makedirs(FileHandler.ROOT_DIR, exist_ok=True)

        client_dir_path = os.path.join(FileHandler.ROOT_DIR, client_id)
        os.makedirs(client_dir_path, exist_ok=True)

        file_path = os.path.join(client_dir_path, file_name)
        with open(file_path, mode) as file:
            file.write(content)

    def decrypt_file(self, file_path: str, aes_key: bytes) -> None:
        """Decrypt the file and override encrypted content with decrypted content."""
        from crypto_manager import CryptoManager
        crypto_manager = CryptoManager()
        with open(file_path, "rb") as file:
            content = file.read()
            decrypted = crypto_manager.aes_decrypt(content, aes_key)
            with open(file_path, "wb") as final_file:
                final_file.write(decrypted)
