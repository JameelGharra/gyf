# gyf: A secure file transfer system

## Project Overview
This project is a client-server file transfer system designed with strong security principles. It demonstrates end-to-end encryption to safeguard files during transmission and ensures data integrity. The aim of the project to simulate real-world secure communication protocols.

## Features
- Client-Server Architecture: Supports multiple clients interacting with the server.
- Secure Registration and Authentication: Ensures only valid users can access services.
Encryption:
- RSA for secure key exchange.
- AES for encrypting files during transfer.
- Checksum Verification: Confirms the integrity of transmitted files.
- Multi-threaded Server: Concurrently handles multiple clients.
- Persistent Storage: SQLite database to store user information and transferred files.

## Encryption Process: Asymmetric and Symmetric Keys
This project utilizes a **hybrid encryption model**, combining the strengths of **asymmetric (RSA)** and **symmetric (AES)** encryption. RSA is used during the **initial handshake** to exchange a secure session key, ensuring that sensitive data, such as the AES key, is transmitted safely.

Once the **AES key** is exchanged, all subsequent file transmissions are encrypted with AES, which offers high-speed encryption ideal for large files. This approach ensures both **security and efficiency**: RSA protects the key exchange from interception, while AES handles the actual file encryption to ensure fast, reliable data transfer.

Keys are generated dynamically during client-server communication. The client stores the private RSA key securely in the `priv.key` file, and the server uses the client’s public key to encrypt the AES session key. This **hybrid model** guarantees that even if the file transmission is intercepted, the attacker cannot decrypt it without the AES key, which is protected by RSA.

## Technologies Used
The server-side was implemented in Python, and used selectors to handle clients concurrently as well as cryptodome for cryptographic operations.
The client-side was implemented in C++, used boost for networking and CryptoPP for cryptography.

## Project Structure
- `server/`: Contains all server-side Python scripts
- `client/`: Contains all client-side C++ files
- `docs/`: Project documentation and protocol specifications

## Setup and Running
### Server
1. Ensure Python 3.12.1 is installed
2. Install required packages: `pip install pycryptodome`
3. Run the server: `python server/main.py`

### Client
1. Ensure you have Visual Studio 2022 with C++17 support
2. Open the project in Visual Studio
3. Build and run the client application

## Security Analysis
A detailed security analysis of the communication protocol is available in the `docs/vulnerability analysis.pdf` file. This includes potential vulnerabilities, attack vectors, and proposed improvements.

## Acknowledgments
- Roy Mimran for providing the project requirements and guidance
- The open-source community for the encryption libraries used in this project

