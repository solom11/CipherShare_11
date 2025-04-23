import socket
import threading
import os
import hashlib
import secrets

SHARED_FOLDER = "shared_files"
DEFAULT_PEER_PORT = 5001
REGISTRY_IP = "127.0.0.1"
REGISTRY_PORT = 6000

if not os.path.exists(SHARED_FOLDER):
    os.makedirs(SHARED_FOLDER)

users = {}  # username -> (hashed_password, salt)
logged_in_users = set()
local_port = None
logged_in_user = None 


def hash_password(password, salt=None):
    if not salt:
        salt = secrets.token_bytes(16)
    hashed = hashlib.sha256(salt + password.encode()).hexdigest()
    return hashed, salt


def register_with_registry(username, ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((REGISTRY_IP, REGISTRY_PORT))
        s.send(f"REGISTER_PEER {username} {ip} {port}".encode())
        return s.recv(1024).decode()


def get_peer_info(username):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((REGISTRY_IP, REGISTRY_PORT))
        s.send(f"GET_PEER {username}".encode())
        return s.recv(1024).decode()


def handle_client_connection(client_socket, client_address):
    print(f"[+] Connected to {client_address}")
    try:
        while True:
            command = client_socket.recv(1024).decode()
            if not command:
                break

            if command.startswith("LOGIN"):
                _, uname, passwd = command.split()
                if uname not in users:
                    client_socket.send(b"NO_USER")
                else:
                    stored_hash, salt = users[uname]
                    input_hash, _ = hash_password(passwd, salt)
                    if input_hash == stored_hash:
                        logged_in_users.add(uname)
                        client_socket.send(b"LOGIN_SUCCESS")
                    else:
                        client_socket.send(b"LOGIN_FAIL")

            elif command.startswith("CHECK_ONLINE"):
                _, uname = command.split()
                if uname in logged_in_users:
                    client_socket.send(b"ONLINE")
                else:
                    client_socket.send(b"OFFLINE")

            elif command.startswith("LIST"):
                if not logged_in_users:
                    client_socket.send(b"NOT_LOGGED_IN")
                    continue
                files = os.listdir(SHARED_FOLDER)
                file_list = "\n".join(files) if files else "No files available"
                client_socket.send(file_list.encode())

            elif command.startswith("DOWNLOAD"):
                if not logged_in_users:
                    client_socket.send(b"NOT_LOGGED_IN")
                    continue
                try:
                    _, filename = command.split(maxsplit=1)
                except ValueError:
                    client_socket.send(b"INVALID")
                    return
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
    global local_port
    local_port = int(input("Enter your peer's listening port: "))
    threading.Thread(target=start_peer_server, args=(local_port,)).start()
    connect_to_peers()


def start_peer_server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", port))
    server_socket.listen(5)
    print(f"[*] Peer listening on port {port}")

    while True:
        client_socket, client_address = server_socket.accept()
        threading.Thread(target=handle_client_connection, args=(client_socket, client_address)).start()


def check_peer_online(ip, port, username):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            s.send(f"CHECK_ONLINE {username}".encode())
            return s.recv(1024).decode() == "ONLINE"
    except:
        return False


def connect_to_peers():
    global logged_in_user
    while True:
        print(
            "\n1. Register\n2. Login\n3. Connect to another peer by username\n4. List files\n5. Download file\n6. "
            "Logout\n7. Exit")
        choice = input("Select option: ")

        if choice == "1":
            uname = input("Username: ")
            passwd = input("Password: ")
            hashed, salt = hash_password(passwd)
            users[uname] = (hashed, salt)
            result = register_with_registry(uname, "127.0.0.1", local_port)
            print(result)

        elif choice == "2":
            uname = input("Username: ")
            passwd = input("Password: ")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(("127.0.0.1", local_port))
                s.send(f"LOGIN {uname} {passwd}".encode())
                resp = s.recv(1024)
                print(resp.decode())
                if resp == b"LOGIN_SUCCESS":
                    logged_in_user = uname

        elif choice == "3":
            if not logged_in_user:
                print("You must login first.")
                continue

            peer_username = input("Enter peer's username: ")
            response = get_peer_info(peer_username)

            if response == "UNKNOWN_USER":
                print("Peer not found.")
                continue

            peer_ip, peer_port = response.split(":")
            peer_port = int(peer_port)

            if not check_peer_online(peer_ip, peer_port, peer_username):
                print("Peer is offline or not logged in.")
                continue

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ps:
                ps.connect((peer_ip, peer_port))

                while True:
                    print("\nConnected to peer.\n1. List files\n2. Download file\n3. Disconnect")
                    sub_choice = input("Select option: ")

                    if sub_choice == "1":
                        if not logged_in_user:
                            print("You must login first.")
                            continue
                        ps.send(b"LIST")
                        data = ps.recv(4096).decode()
                        print("Files:\n" + data)

                    elif sub_choice == "2":
                        if not logged_in_user:
                            print("You must login first.")
                            continue
                        filename = input("Filename to download: ")
                        ps.send(f"DOWNLOAD {filename}".encode())
                        status = ps.recv(1024)
                        if status == b"FOUND":
                            with open(filename, "wb") as f:
                                while True:
                                    chunk = ps.recv(1024)
                                    if chunk.endswith(b"EOF"):
                                        f.write(chunk[:-3])
                                        break
                                    f.write(chunk)
                            print("Download complete.")
                        else:
                            print("File not found.")

                    elif sub_choice == "3":
                        break

        elif choice == "4":
            if not logged_in_user:
                print("You must login first.")
                continue
            files = os.listdir(SHARED_FOLDER)
            print("Local shared files:\n" + "\n".join(files))

        elif choice == "5":
            print("Use option 3 to connect to a peer first to download.")

        elif choice == "6":
            if logged_in_user:
                print(f"User '{logged_in_user}' logged out.")
                logged_in_users.discard(logged_in_user)
                logged_in_user = None
            else:
                print("No user is currently logged in.")

        elif choice == "7":
            print("Exiting...")
            os._exit(0)

        else:
            print("Invalid choice.")


if __name__ == "__main__":
    start_peer()
