import secrets
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import unpad, pad


class SingletonMeta(type):
    """
    This is a thread-safe implementation of singleton design pattern.
    """
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]


class CryptoManager(metaclass=SingletonMeta):
    # Length of a UUID in bytes
    LENGTH_UUID = 16

    # Length of an AES key in bytes
    LENGTH_AES = 32

    def generate_uuid(self) -> str:
        """Generate a UUID."""
        random_bytes = secrets.token_bytes(CryptoManager.LENGTH_UUID)
        return random_bytes.hex()

    def generate_aes(self) -> bytes:
        """Generate an AES key with 256 bit long."""
        aes_key = secrets.token_bytes(CryptoManager.LENGTH_AES)
        return aes_key

    def rsa_encrypt(self, public_key: bytes, data: bytes) -> bytes | None:
        """Encrypt data with RSA."""
        try:
            cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
            encrypted_data = cipher.encrypt(data)
            return encrypted_data
        except ValueError:
            print("Error: RSA encryption failed.")
            return None

    def aes_decrypt(self, encrypted_data: bytes, aes_key: bytes) -> bytes:
        cipher = AES.new(aes_key, AES.MODE_CBC, bytes(AES.block_size))
        decrypted = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        return decrypted
