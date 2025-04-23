import socket
import threading

registry = {}  # username -> (IP, port)
REGISTRY_PORT = 6000


def handle_registry_client(client_socket):
    try:
        while True:
            command = client_socket.recv(1024).decode()
            if not command:
                break

            if command.startswith("REGISTER_PEER"):
                _, uname, ip, port = command.split()
                registry[uname] = (ip, int(port))
                client_socket.send(b"REGISTERED")

            elif command.startswith("GET_PEER"):
                _, uname = command.split()
                if uname in registry:
                    ip, port = registry[uname]
                    client_socket.send(f"{ip}:{port}".encode())
                else:
                    client_socket.send(b"UNKNOWN_USER")

            else:
                client_socket.send(b"INVALID_COMMAND")
    except Exception as e:
        print(f"[-] Error handling registry client: {e}")
    finally:
        client_socket.close()


def start_registry_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", REGISTRY_PORT))
    server_socket.listen(5)
    print(f"[*] Registry server listening on port {REGISTRY_PORT}")

    while True:
        client_socket, _ = server_socket.accept()
        threading.Thread(target=handle_registry_client, args=(client_socket,)).start()


if __name__ == "__main__":
    start_registry_server()
