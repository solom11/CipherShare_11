import socket
import threading
import os

SHARED_FOLDER = "shared_files"
PEER_PORT = 5001

if not os.path.exists(SHARED_FOLDER):
    os.makedirs(SHARED_FOLDER)

def handle_client_connection(client_socket, client_address):
    print(f"[+] Connected to {client_address}")
    try:
        while True:
            command = client_socket.recv(1024).decode()
            if not command:
                break

            if command == "LIST":
                files = os.listdir(SHARED_FOLDER)
                file_list = "\n".join(files) if files else "No files available"
                client_socket.send(file_list.encode())

            elif command.startswith("DOWNLOAD"):
                _, filename = command.split()
                filepath = os.path.join(SHARED_FOLDER, filename)
                if os.path.exists(filepath):
                    client_socket.send(b"FOUND")
                    with open(filepath, "rb") as f:
                        while chunk := f.read(1024):
                            client_socket.send(chunk)
                    client_socket.send(b"EOF")
                else:
                    client_socket.send(b"NOTFOUND")

            else:
                client_socket.send(b"INVALID")

    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        client_socket.close()


def start_peer():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", PEER_PORT))
    server_socket.listen(5)
    print(f"[*] Peer listening on port {PEER_PORT}")

    while True:
        client_socket, client_address = server_socket.accept()
        threading.Thread(target=handle_client_connection, args=(client_socket, client_address)).start()


def connect_to_peer():
    peer_ip = input("Enter peer IP: ")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((peer_ip, PEER_PORT))

        while True:
            print("\n1. List files\n2. Download file\n3. Exit")
            choice = input("Select option: ")

            if choice == "1":
                s.send(b"LIST")
                data = s.recv(4096).decode()
                print("Available files:\n" + data)

            elif choice == "2":
                filename = input("Enter filename to download: ")
                s.send(f"DOWNLOAD {filename}".encode())
                status = s.recv(1024)
                if status == b"FOUND":
                    with open(filename, "wb") as f:
                        while True:
                            chunk = s.recv(1024)
                            if chunk.endswith(b"EOF"):
                                f.write(chunk[:-3])
                                break
                            f.write(chunk)
                    print("Download complete.")
                else:
                    print("File not found on peer.")

            elif choice == "3":
                break
            else:
                print("Invalid choice.")


if __name__ == "__main__":
    print("1. Start as peer server")
    print("2. Connect to another peer")
    option = input("Choose mode: ")

    if option == "1":
        start_peer()
    elif option == "2":
        connect_to_peer()
    else:
        print("Invalid option.")
