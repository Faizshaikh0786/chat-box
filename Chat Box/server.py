import socket
import threading
# Defining the IP address and port the server will listen on.
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432
clients = []

def handle_client(conn):
    # This function runs in a separate thread for each client.
    # It receives incoming encrypted messages from one client and forwards them to all other connected clients.
    while True:
        try:
            message = conn.recv(4096)
            if not message:
                break
            # It log the ciphertext for every message received
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
# This initializes and runs the socket server.
# It waits for two clients (Alice and Bob) to connect and then relays encrypted messages between them.
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
