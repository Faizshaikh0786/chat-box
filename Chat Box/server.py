import socket
import threading

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432
clients = []

def handle_client(conn):
    while True:
        try:
            message = conn.recv(4096)
            if not message:
                break
            # Log the ciphertext for every message received
            print(f"Server log - Encrypted message (bytes): {message[:100]}")
            for c in clients:
                if c != conn:
                    c.send(message)
        except Exception as e:
            print(f"Server error: {e}")
            break
    if conn in clients:
        clients.remove(conn)
    conn.close()
    print("Client disconnected.")

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((SERVER_HOST, SERVER_PORT))
    server.listen(2)
    print("Server started and listening.")
    while len(clients) < 2:
        client, addr = server.accept()
        clients.append(client)
        print(f"Client connected from {addr}")
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()
    print("Two clients connected; server will now relay messages.")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        for c in clients:
            c.close()
        server.close()

if __name__ == "__main__":
    start_server()
