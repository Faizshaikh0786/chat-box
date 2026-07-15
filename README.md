# Secure Chat Box: Alice and Bob Talking Securely

A Python-based secure chat application that allows Alice and Bob to communicate through a central server using encrypted messages. The clients use RSA and AES through PyCryptodome, while the server only relays ciphertext between connected users.

## Overview

This project demonstrates a simple secure messaging system built with Python sockets and threads. It uses a hybrid encryption approach where RSA is used to securely exchange a session key, and AES is used to encrypt the actual chat messages during the session.

The system consists of three main parts:

- `generate_keys.py` creates RSA key pairs for Alice and Bob.
- `server.py` runs a TCP relay server that forwards encrypted messages between clients.
- `client.py` runs as either Alice or Bob and handles key loading, session setup, encryption, decryption, and local message logging.

## Features

- Secure chat between two users: Alice and Bob.
- RSA 2048-bit key generation for both users.
- RSA-OAEP used to encrypt the AES session key.
- AES used to encrypt chat messages.
- Length-prefixed message framing using `struct` for reliable socket communication.
- Multi-threaded message receiving so sending and receiving can happen at the same time.
- Separate JSON logs for Alice and Bob.

## Project Structure

```text
.
├── alice_messages.json
├── alice_private.pem
├── alice_public.pem
├── bob_messages.json
├── bob_private.pem
├── bob_public.pem
├── client.py
├── generate_keys.py
└── server.py
```

## File Description

| File | Description |
|------|-------------|
| `generate_keys.py` | Generates 2048-bit RSA key pairs for Alice and Bob and saves them as `.pem` files. |
| `server.py` | Accepts client connections, relays encrypted data between clients, and logs ciphertext bytes to the terminal. |
| `client.py` | Runs as Alice or Bob, loads keys, establishes the session key, encrypts/decrypts chat messages, and stores logs in JSON format. |
| `alice_public.pem` / `bob_public.pem` | Public RSA keys used for secure key exchange. |
| `alice_private.pem` / `bob_private.pem` | Private RSA keys used to decrypt the shared AES session key. |
| `alice_messages.json` / `bob_messages.json` | Stores encrypted and decrypted message history for each user separately. |

## Technologies Used

- Python
- Socket programming
- Multithreading
- JSON
- Base64
- Struct-based framing
- RSA encryption
- AES encryption
- PyCryptodome

## How the System Works

1. RSA key pairs are generated for Alice and Bob using `generate_keys.py`.
2. The server starts and waits for both clients to connect.
3. Alice and Bob connect to the server using TCP sockets.
4. Alice generates a random AES session key using `get_random_bytes(16)`.
5. Alice encrypts that session key using Bob’s public RSA key and sends it through the server.
6. Bob receives the encrypted session key and decrypts it using his private RSA key.
7. After the shared session key is established, both users exchange AES-encrypted messages through the relay server.
8. Each client logs the ciphertext and plaintext into its own JSON file.

## Installation

Make sure Python is installed, then install PyCryptodome:

```bash
pip install pycryptodome
```

## How to Run

### 1. Generate RSA keys

```bash
python generate_keys.py
```

### 2. Start the server

```bash
python server.py
```

### 3. Start Alice in a new terminal

```bash
python client.py alice
```

### 4. Start Bob in another terminal

```bash
python client.py bob
```

After both clients are connected, Alice and Bob can exchange encrypted messages through the server.

## Example Workflow

- Alice starts the chat and creates a random AES session key.
- Alice encrypts the session key with Bob’s public RSA key.
- Bob decrypts the session key with his private RSA key.
- Alice and Bob then send encrypted messages using AES.
- The server forwards only encrypted bytes and does not decrypt message content.

## Logging

Each client writes chat activity to its own JSON file:

- `alice_messages.json`
- `bob_messages.json`

Every log entry stores:

- `ciphertext`
- `plaintext`

This makes it easier to demonstrate both the encrypted transmission and the decrypted result locally on each client.

## Security Notes

This project uses a hybrid encryption design, which is a common pattern in secure communication systems: RSA protects the session key, and AES handles message encryption efficiently.

The server acts only as a relay and does not decrypt user messages, so message confidentiality is handled on the client side.

One implementation detail is important: the client uses AES in EAX mode with `encrypt_and_digest()`, but the transmitted payload contains the nonce and ciphertext only, not the authentication tag. This means the project demonstrates encrypted messaging but does not fully verify message integrity in its current form.

## Limitations

- Designed for two users only: Alice and Bob.
- Command-line interface only.
- Uses localhost configuration by default.
- Message integrity verification is incomplete because the AES authentication tag is not transmitted and verified.
- Intended as a learning project, not a production-ready secure messaging system.

## Future Improvements

- Add AES tag transmission and verification for full authenticated encryption.
- Build a graphical user interface.
- Support more than two users.
- Add timestamps to message logs.
- Improve error handling and connection recovery.
- Move from localhost to configurable network deployment.

## Learning Outcomes

This project demonstrates:

- socket-based client-server communication in Python,
- reliable framing of variable-length messages over TCP,
- RSA key generation and key exchange,
- AES-based message encryption,
- JSON-based local message logging,
- the structure of a basic end-to-end style secure chat system.
