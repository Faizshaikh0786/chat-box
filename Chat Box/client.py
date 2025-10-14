import socket
import threading
import sys
import base64
import struct
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432

def send_frame(sock, ftype: bytes, payload: bytes):
    assert len(ftype) == 1
    body = ftype + payload
    length = struct.pack('>I', len(body))
    sock.sendall(length + body)

def recv_frame(sock):
    raw_len = recvall(sock, 4)
    if not raw_len:
        return None, None
    total = struct.unpack('>I', raw_len)[0]
    body = recvall(sock, total)
    if not body or len(body) == 0:
        return None, None
    return body[:1], body[1:]  # (ftype, payload)

def recvall(sock, n):
    data = b''
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            return None
        data += part
    return data

def log_message(filename, ciphertext, plaintext):
    entry = {"ciphertext": ciphertext, "plaintext": plaintext}
    try:
        with open(filename, "r") as f:
            messages = json.load(f)
    except FileNotFoundError:
        messages = []
    messages.append(entry)
    with open(filename, "w") as f:
        json.dump(messages, f, indent=2)

def load_keys(name):
    with open(f"{name}_public.pem", "r") as f:
        public_key = RSA.import_key(f.read())
    with open(f"{name}_private.pem", "r") as f:
        private_key = RSA.import_key(f.read())
    return public_key, private_key

def receive_messages(sock, aes_key, log_file):
    while True:
        try:
            ftype, payload = recv_frame(sock)
            if ftype is None:
                print("\nConnection closed by server")
                break
            if ftype == b"M":
                print(f"\nReceived encrypted: {payload.decode()}")
                data = base64.b64decode(payload)
                nonce, ciphertext = data[:16], data[16:]
                cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
                plaintext = cipher_aes.decrypt(ciphertext)
                print(f"Decrypted message: {plaintext.decode()}")
                log_message(log_file, payload.decode(), plaintext.decode())
                print("Enter message: ", end="", flush=True)
            else:
                pass
        except Exception as e:
            print(f"\nReceive error: {e}")
            break

def send_messages(sock, aes_key, log_file):
    while True:
        try:
            plaintext = input("Enter message: ")
            cipher_aes = AES.new(aes_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext.encode())
            b64 = base64.b64encode(cipher_aes.nonce + ciphertext)
            send_frame(sock, b"M", b64)
            log_message(log_file, b64.decode(), plaintext)
        except Exception as e:
            print(f"\nSend error: {e}")
            break

def main(role):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((SERVER_HOST, SERVER_PORT))
    except ConnectionRefusedError:
        print("Cannot connect to the server. Make sure the server is running.")
        return

    alice_pub, alice_priv = load_keys("alice")
    bob_pub, bob_priv = load_keys("bob")

    # Select log file name based on user role
    log_file = f"{role}_messages.json"

    if role == "alice":
        aes_key = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(bob_pub)
        rsa_ct = cipher_rsa.encrypt(aes_key)
        send_frame(sock, b"K", base64.b64encode(rsa_ct))
        print("Sent session key to Bob; waiting to chat...")
    elif role == "bob":
        aes_key = None
        while aes_key is None:
            ftype, payload = recv_frame(sock)
            if ftype is None:
                print("Connection closed before receiving session key.")
                return
            if ftype == b"K":
                decoded = base64.b64decode(payload)
                cipher_rsa = PKCS1_OAEP.new(bob_priv)
                aes_key = cipher_rsa.decrypt(decoded)
                break
            else:
                print("DEBUG: Ignored non-key frame before key setup")
        print("Session key received and decrypted.")
    else:
        print("Usage: python client.py [alice|bob]")
        sock.close()
        return

    print(f"Session key established for {role}")
    threading.Thread(target=receive_messages, args=(sock, aes_key, log_file), daemon=True).start()
    send_messages(sock, aes_key, log_file)
    sock.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python client.py [alice|bob]")
    else:
        main(sys.argv[1])
