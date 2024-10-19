
# Represents a transferred file from a client to the server
class TransferredFile:
    # Size of the file name in bytes
    SIZE_FILE_NAME = 255
    # Size of the file path in bytes
    SIZE_FILE_PATH = 255

    def __init__(self, client_id: str, name: str, path_name: str, verified: bool = False):
        self.client_id = client_id
        self.name = name
        self.path_name = path_name
        self.verified = verified


    def set_verified(self, verified: bool) -> None:
        """Set the verified status of the file"""
        self.verified = verified

    def __str__(self) -> str:
        return (
            f"Client ID: {self.client_id}\nName: {self.name}\nPath Name: {self.path_name}\n"
            f"Verified?: {"Yes" if self.verified else "No"}"
        )