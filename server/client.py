# Nothing special, just a wrapper class for the client info
class Client:
    """Encapsulates client info in memory when loading the database"""

    def __init__(self, id: str, name: str, last_seen: str, public_key: bytes = None, aes_key: bytes = None):
        self._id = id
        self._name = name
        self._public_key = public_key
        self._last_seen = last_seen
        self._aes_key = aes_key

    def get_public_key(self) -> bytes:
        """Get the public key of the client."""
        return self._public_key

    def set_public_key(self, public_key: bytes):
        """ sets the public key of the client"""
        self._public_key = public_key

    def get_aes_key(self) -> bytes:
        """Get the AES key of the client."""
        return self._aes_key

    def set_aes_key(self, aes_key: bytes):
        """ sets the AES key of the client"""
        self._aes_key = aes_key

    def get_name(self) -> str:
        """Get the name of the client."""
        return self._name

    def set_last_seen(self, last_seen: str):
        """ sets the last seen of the client"""
        self._last_seen = last_seen

    def __str__(self) -> str:
        return (
            f"ID: {self._id}\nName: {self._name}\nLast Seen: {self._last_seen}\n"
            f"Public Key?: {"Yes" if self._public_key else "No"}"
            f"\nAES Key?: {"Yes" if self._aes_key else "No"}"
        )
