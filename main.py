import socket
import threading
import os
import hashlib
import secrets
import shutil
from tkinter import Tk, filedialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

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
file_hashes = {}  # filename -> sha256 hash

# For Diffie-Hellman key exchange
DH_PRIME = 0xFFFFFFFB
DH_GENERATOR = 5
file_keys = {}  # filename -> AES key


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def hash_password(password, salt=None):
    if not salt:
        salt = secrets.token_bytes(16)
    hashed = hashlib.sha256(salt + password.encode()).hexdigest()
    return hashed, salt


def encrypt_file(filepath, key):
    backend = default_backend()
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    with open(filepath, "rb") as f:
        data = f.read()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    with open(filepath, "wb") as f:
        f.write(iv + encrypted)


def decrypt_file(filepath, key):
    backend = default_backend()
    with open(filepath, "rb") as f:
        iv = f.read(16)
        encrypted = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted) + unpadder.finalize()

    with open(filepath, "wb") as f:
        f.write(unpadded_data)


def hash_file(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def select_and_upload_file():
    root = Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename()
    if file_path:
        filename = os.path.basename(file_path)
        dest_path = os.path.join(SHARED_FOLDER, filename)
        shutil.copy(file_path, dest_path)

        # Store hash for integrity verification
        original_hash = hash_file(dest_path)
        file_hashes[filename] = original_hash

        # Generate and store a random AES key for this file
        aes_key = secrets.token_bytes(32)
        file_keys[filename] = aes_key

        # Encrypt using the file-specific key
        encrypt_file(dest_path, aes_key)

        print(f"File '{filename}' uploaded, encrypted with unique key, and hash stored.")


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
                    # --- Diffie-Hellman key exchange with the requester ---
                    private = secrets.randbelow(DH_PRIME)
                    public = pow(DH_GENERATOR, private, DH_PRIME)
                    client_socket.send(str(public).encode().ljust(64))
                    peer_pub = int(client_socket.recv(64).strip())
                    shared = pow(peer_pub, private, DH_PRIME)
                    shared_key = hashlib.sha256(str(shared).encode()).digest()

                    # --- Encrypt the AES file key and send it ---
                    filename = os.path.basename(filepath)
                    file_key = file_keys.get(filename)
                    encrypted_file_key = xor_bytes(file_key, shared_key)
                    client_socket.send(encrypted_file_key)

                    filesize = os.path.getsize(filepath)
                    client_socket.send(str(filesize).encode().ljust(16))
                    with open(filepath, "rb") as f:
                        while chunk := f.read(1024):
                            client_socket.send(chunk)
                    filename = os.path.basename(filepath)
                    file_hash = file_hashes.get(filename, "0" * 64)
                    client_socket.send(file_hash.encode())
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
        print("\n1. Register")
        print("2. Login")
        print("3. Connect to another peer")
        print("4. Upload a file")
        print("5. List shared files")
        print("6. Download file")
        print("7. Logout")
        print("8. Exit")

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
                            # --- Diffie-Hellman key exchange ---
                            private = secrets.randbelow(DH_PRIME)
                            peer_pub = int(ps.recv(64).strip())
                            public = pow(DH_GENERATOR, private, DH_PRIME)
                            ps.send(str(public).encode().ljust(64))
                            shared = pow(peer_pub, private, DH_PRIME)
                            shared_key = hashlib.sha256(str(shared).encode()).digest()

                            # --- Receive and decrypt AES file key ---
                            encrypted_file_key = ps.recv(32)
                            file_key = xor_bytes(encrypted_file_key, shared_key)

                            size_data = b""
                            while len(size_data) < 16:
                                size_data += ps.recv(16 - len(size_data))
                            filesize = int(size_data.strip())
                            received = 0
                            with open(filename, "wb") as f:
                                while received < filesize:
                                    chunk = ps.recv(min(1024, filesize - received))
                                    if not chunk:
                                        break
                                    f.write(chunk)
                                    received += len(chunk)
                            if received == filesize:
                                try:
                                    decrypt_file(filename, file_key)
                                    downloaded_hash = hash_file(filename)
                                    expected_hash = b""
                                    while len(expected_hash) < 64:
                                        expected_hash += ps.recv(64 - len(expected_hash))
                                    expected_hash = expected_hash.decode()
                                    if downloaded_hash == expected_hash:
                                        print("Download complete, file decrypted, and integrity verified.")
                                    else:
                                        print("Download complete and decrypted, but WARNING: integrity check failed!")
                                except ValueError as e:
                                    print("Decryption failed:", e)
                            else:
                                print("Download incomplete. File may be corrupted.")
                        else:
                            print("File not found.")

                    elif sub_choice == "3":
                        break

        elif choice == "4":
            if not logged_in_user:
                print("You must login first.")
                continue
            select_and_upload_file()

        elif choice == "5":
            if not logged_in_user:
                print("You must login first.")
                continue
            files = os.listdir(SHARED_FOLDER)
            print("Local shared files:\n" + "\n".join(files))

        elif choice == "6":
            print("Use option 3 to connect to a peer first to download.")

        elif choice == "7":
            if logged_in_user:
                print(f"User '{logged_in_user}' logged out.")
                logged_in_users.discard(logged_in_user)
                logged_in_user = None
            else:
                print("No user is currently logged in.")

        elif choice == "8":
            print("Exiting...")
            os._exit(0)

        else:
            print("Invalid choice.")


if __name__ == "__main__":
    start_peer()
