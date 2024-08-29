# Importing the socket library, to handle the communication
import socket
# Importing the threading library, to handle multiple clients simultaneously
import threading
# Importing the os module, to interact with the operating system to check if database files exist
import os
# Importing the json module, to maintain persistent data storage implemented by json files
import json
# Importing cryptography modules, to handle encrypted communication
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Defining constants
# Defining the paths to the database files - one for users credentials and one for messages sent
USERS_CREDENTIALS_DB = "users_credentials_db.json"
MESSAGES_DB = "messages_db.json"
# Defining the IP address of the server to be the IPv4 address of my computer inside my local network
SERVER_IP_ADDRESS = socket.gethostbyname(socket.gethostname())
# Defining a port number, using an arbitrary and unused port number
PORT = 5050
# Defining the maximum number of clients that can be connected to the server simultaneously
MAX_CLIENTS_SIMULTANEOUSLY = 10
# Defining the format of the messages
FORMAT = "utf-8"
# Defining the maximum size of a received fragment
SIZE = 1024
# Defining the number of allowed sign-in tries
ALLOWED_TRIES = 3

# Defining fixed messages to set a protocol between client and server
DISCONNECT_MESSAGE = "!disconnect!"
BAN_MESSAGE = "You have been banned. You can re-connect to the chat when the ban is removed"
KICK_MESSAGE = "You have been kicked out from the chat. You can try and re-connect"
FAILED_SIGN_IN = "Wrong username or password, please try again"
FAILED_SIGN_UP = "This username is taken, please choose another one"
SEND_PREVIOUS_MESSAGES = "!User connected send all rooms previous messages!"
FILE_ALERT_MESSAGE = "FILE_ALERT_MESSAGE:FILE_INCOMING"
NEW_PASSWORD = "NEW_PASSWORD_ALERT"
SHOW_ALL_CONNECTED_USERS = "SHOW_ALL_CONNECTED_USERS_ALERT"

# Generate a key and IV (Initialization Vector)
SERVER_KEY = b'\x04\x03|\xeb\x8dSh\xe0\xc5\xae\xe5\xe1l9\x0co\xca\xb1"\r-Oo\xbaiYa\x1e\xd1\xf7\xa2\xdf'
IV = b'#\xb59\xee\xa7\xc4@n\xe5r\xac\x97lV\xff\xf1'


# Function to encrypt plaintext using AES-CBC
def encrypt(plaintext):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode(FORMAT)) + padder.finalize()
    cipher = Cipher(algorithms.AES(SERVER_KEY), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext


# Function to decrypt ciphertext using AES-CBC
def decrypt(ciphertext):
    cipher = Cipher(algorithms.AES(SERVER_KEY), modes.CBC(IV), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data.decode(FORMAT)


class Server:
    def __init__(self):
        print("[STARTING SERVER...]")
        print("[CHECKING FOR DATABASES...]")
        self.check_for_existing_db()
        self.clients_credentials1 = self.load_users_credentials()
        self.initialize_system_administrator()
        self.messages = self.load_messages()
        self.address = SERVER_IP_ADDRESS
        self.port = PORT
        # Defining an object of type socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Connecting the socket to a specific ip-port tuple
        self.server_socket.bind((self.address, self.port))
        # Listening to requests
        self.server_socket.listen(MAX_CLIENTS_SIMULTANEOUSLY)
        print(f"[SERVER IS LISTENING ON ADDRESS: {self.address}]")
        # Initializing a lock object to prevent races between clients
        self.clients_lock = threading.Lock()
        # Defining a dictionary to hold all connected clients
        self.connected_clients = {}

    def check_for_existing_db(self):
        # Checking if the users credentials DB exists, if not, create it
        if not os.path.exists(USERS_CREDENTIALS_DB):
            print("Initializing database: USERS_CREDENTIALS_DB")
            with open(USERS_CREDENTIALS_DB, "w") as file:
                json.dump({}, file)

        # Checking if the users credentials DB exists, if not, create it
        if not os.path.exists(MESSAGES_DB):
            print("Initializing database: MESSAGES_DB")
            with open(MESSAGES_DB, "w") as file:
                json.dump({'1': [], '2': [], '3': []}, file)

    def initialize_system_administrator(self):
        if self.clients_credentials1 == {}:
            self.clients_credentials1['admin'] = {'password': 'admin', 'user_type': 'admin', 'is_banned': 'free'}
            with open(USERS_CREDENTIALS_DB, 'w') as file:
                json.dump(self.clients_credentials1, file, indent=4, sort_keys=True)

    def load_users_credentials(self):
        with open(USERS_CREDENTIALS_DB, "r") as file:
            return json.load(file)

    def load_messages(self):
        with open(MESSAGES_DB, "r") as file:
            return json.load(file)

    def save_user_credentials(self):
        with open(USERS_CREDENTIALS_DB, "w") as file:
            json.dump(self.clients_credentials1, file, indent=4)

    def save_messages(self):
        with open(MESSAGES_DB, "w") as file:
            json.dump(self.messages, file, indent=4)

    def start(self):
        # Initiate an infinite loop (while the server is up), to handle new clients
        while True:
            # Initiate connection with a client
            client_socket, client_address = self.server_socket.accept()
            # Defining a new thread to handle the new client
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address))
            # Starting the thread
            client_thread.start()

    def handle_client(self, client_socket, client_address):
        print(f"[NEW CLIENT HAS REQUESTED TO CONNECT: {client_address}]")
        # Receive client's details
        try:
            # Receive whether it is a new or registered user
            sign_in_or_sign_up = client_socket.recv(SIZE).decode(FORMAT)
            if sign_in_or_sign_up == 'SIGN_IN':
                # it is a registered user, verify the credentials
                authentication_status, client_username, client_password = self.sign_in_user(client_socket)
                if authentication_status == 0:
                    # credentials are valid, check if user is banned
                    client_ban_status, client_user_type = self.check_user_ban(client_socket, client_username)
                    if client_ban_status != "free":
                        # user is banned
                        authentication_status = -1
            else:
                # it is a new user
                authentication_status = 0
                client_username, client_password = self.sign_up_user(client_socket)
                client_ban_status, client_user_type = 'free', 'basic'
            if authentication_status == -1:
                client_socket.close()
                return

            valid_chatroom, client_chatroom = self.verify_chatroom(client_socket)

            # client_socket.send((credentials_date).encode(FORMAT))

            print(
                f"[ACCESS GRANTED] username:{client_username}, password:{client_password}, chatroom:{client_chatroom}")
            with self.clients_lock:
                self.connected_clients[client_username] = \
                    {'socket': client_socket, 'password': client_password, 'chatroom': client_chatroom}
            new_client_alert = f"the user {client_username} has entered the chatroom"
            self.broadcast_message(client_username, new_client_alert, 1)
        # Implementing an 'except' block, to handle any unexpected errors
        except Exception:
            pass
        try:
            self.receive_message(client_socket, client_username, client_chatroom)
            leaving_client_alert = f"the user {client_username} has left the chatroom"
            self.broadcast_message(client_username, leaving_client_alert, 1)
            if client_username in self.connected_clients.keys():
                with self.clients_lock:
                    del self.connected_clients[client_username]
                client_socket.close()
        except Exception:
            pass

    def receive_message(self, client_socket, client_username, client_chatroom):
        while True:
            # Implementing a 'try' block, to test tha occurrence of any unexpected errors
            try:
                message = (client_socket.recv(SIZE).decode(FORMAT))
                # Checking the message is not empty
                if not message:
                    break
                # incase want to disconnect
                elif message == SEND_PREVIOUS_MESSAGES:
                    self.send_previous_messages(client_username, client_chatroom)
                elif message == DISCONNECT_MESSAGE:
                    client_socket.sendall(DISCONNECT_MESSAGE.encode(FORMAT))
                    break
                elif message.startswith(NEW_PASSWORD):
                    new_password = message.split()[1]
                    self.clients_credentials1[client_username]['password'] = new_password
                    self.save_user_credentials()
                elif message == SHOW_ALL_CONNECTED_USERS:
                    room_connected_users = f"{SHOW_ALL_CONNECTED_USERS} "
                    for c in self.connected_clients.keys():
                        if self.connected_clients[client_username]['chatroom'] == self.connected_clients[c]['chatroom']:
                            room_connected_users += \
                                f"Username: {c}   |   Authorizations: {self.clients_credentials1[c]['user_type']}\n"
                    client_socket.sendall(room_connected_users.encode(FORMAT))
                elif message.startswith(FILE_ALERT_MESSAGE):
                    file_size = message.split()[1]
                    file_name = message.split()[2]
                    file_contents = self.receive_file(client_socket, file_size, file_name)
                    client_socket.send(
                        f"{FILE_ALERT_MESSAGE} {file_size} {file_name} {client_username}".encode(FORMAT))
                    # self.broadcast_file(client_username, file_contents)

                elif message.startswith("CHANGE_ROOM"):
                    valid_chatroom, client_chatroom = self.verify_chatroom(client_socket)
                    self.send_previous_messages(client_username, client_chatroom)
                elif message.startswith("KICK_USER"):
                    user_to_kick = message.split()[1]
                    self.kick_out_user(client_username, user_to_kick)
                elif message.startswith("BAN_USER"):
                    user_to_ban = message.split()[1]
                    self.ban_user(client_username, user_to_ban)
                elif message.startswith("UNBAN_USER"):
                    user_to_unban = message.split()[1]
                    self.unban_user(client_username, user_to_unban)
                else:
                    self.broadcast_message(client_username, message)
            # Implementing an 'except' block, to handle any unexpected errors
            except Exception:
                break

    def receive_file(self, client_socket, file_size, file_name):
        data = b""
        done = False
        while not done:
            partial_data = client_socket.recv(SIZE)
            if partial_data.endswith(b'<END_OF_FILE>'):
                data += partial_data[:-len(b'<END_OF_FILE>')]
                done = True
            else:
                data += partial_data
        with open(f"received_{file_name.split('.')[0]}.{file_name.split('.')[1]}", 'wb') as file:
            file.write(data)
        return data

    def broadcast_message(self, sender_username, message, administrative_message=0):
        # Acquire the lock
        with self.clients_lock:
            for uname, client in self.connected_clients.items():
                if self.connected_clients[sender_username]['chatroom'] == self.connected_clients[uname]['chatroom'] and \
                        self.connected_clients[sender_username]['chatroom'] != '0':
                    try:
                        if administrative_message == 0:
                            to_send = f"{sender_username}: {message}"
                        else:
                            to_send = f"{message}"
                        self.connected_clients[uname]['socket'].sendall((to_send).encode(FORMAT))
                    except Exception:
                        del self.connected_clients[uname]
            self.messages[self.connected_clients[sender_username]['chatroom']].append(to_send)
            self.save_messages()

    """def broadcast_file(self, sender_username, file_contents):
        # Acquire the lock
        with self.clients_lock:
            for uname, client in self.connected_clients.items():
                if self.connected_clients[sender_username]['chatroom'] == self.connected_clients[uname]['chatroom'] and \
                        self.connected_clients[sender_username]['chatroom'] != '0':
                    try:
                        if administrative_message == 0:
                            to_send = f"{sender_username}: {message}"
                        else:
                            to_send = f"{message}"
                        self.connected_clients[uname]['socket'].sendall(file_contents)
                    except Exception:
                        del self.connected_clients[uname]
            self.messages[self.connected_clients[sender_username]['chatroom']].append(to_send)
            self.save_messages()"""

    def send_previous_messages(self, client_username, client_chatroom):
        with self.clients_lock:
            for msg in self.messages[client_chatroom]:
                try:
                    try:
                        sender, msg1 = msg.split(":")
                        if sender == client_username:
                            self.connected_clients[client_username]['socket'].sendall((f"You: {msg1}\n").encode(FORMAT))
                        else:
                            self.connected_clients[client_username]['socket'].sendall((msg + "\n").encode(FORMAT))
                    except Exception:
                        self.connected_clients[client_username]['socket'].sendall((msg + "\n").encode(FORMAT))
                except Exception:
                    del self.connected_clients[client_username]

    def check_credentials(self, username, password):
        if (self.clients_credentials1.get(username) == None) or (
                self.clients_credentials1[username]['password'] != password):
            return -1
        return 0

    def sign_in_user(self, client_socket):
        counter = 1
        try:
            enc = client_socket.recv(SIZE)
            client_username, client_password = (enc).decode(FORMAT).split()
            # client_username, client_password = decry,pt(client_socket.recv(SIZE)).split()
        except Exception:
            client_socket.sendall((FAILED_SIGN_IN).encode(FORMAT))
            return -1, None, None
        if client_username == None or client_password == None:
            credentials_status = -1
        else:
            credentials_status = self.check_credentials(client_username, client_password)
        while credentials_status == -1 and counter < ALLOWED_TRIES:
            client_socket.sendall((FAILED_SIGN_IN).encode(FORMAT))
            try:
                client_username, client_password = (client_socket.recv(SIZE)).decode(FORMAT).split()
            except Exception:
                return
            if client_username == None or client_password == None:
                credentials_status = -1
            else:
                credentials_status = self.check_credentials(client_username, client_password)
            counter += 1
        if credentials_status == 0:
            client_socket.sendall(("sign in successfully").encode(FORMAT))
            return 0, client_username, client_password
        client_socket.sendall((FAILED_SIGN_IN).encode(FORMAT))
        return -1, None, None

    def check_user_ban(self, client_socket, client_username):
        client_ban_status = self.clients_credentials1[client_username]['is_banned']
        client_user_type = self.clients_credentials1[client_username]['user_type']
        client_socket.sendall((client_ban_status).encode(FORMAT))
        return client_ban_status, client_user_type

    def sign_up_user(self, client_socket):
        client_username, client_password = (client_socket.recv(SIZE)).decode(FORMAT).split()
        while self.clients_credentials1.get(client_username) != None:
            client_socket.sendall((FAILED_SIGN_UP).encode(FORMAT))
            client_username, client_password = (client_socket.recv(SIZE)).decode(FORMAT).split()
        with self.clients_lock:
            self.clients_credentials1[client_username] = {
                'password': client_password, 'user_type': 'basic', 'is_banned': 'free'}
            self.save_user_credentials()
        client_socket.sendall(("success").encode(FORMAT))
        return client_username, client_password

    def verify_chatroom(self, client_socket):
        client_chatroom = (client_socket.recv(SIZE)).decode(FORMAT)
        while not (client_chatroom in ['1', '2', '3']):
            client_socket.sendall(("-1").encode(FORMAT))
            client_chatroom = (client_socket.recv(SIZE)).decode(FORMAT)
        client_socket.sendall(("0").encode(FORMAT))
        return 0, client_chatroom

    def kick_out_user(self, client_username, user_to_kick):
        if self.clients_credentials1[client_username]['user_type'] == 'admin':
            if user_to_kick in self.connected_clients.keys():
                if self.connected_clients[client_username]['chatroom'] == self.connected_clients[user_to_kick][
                    'chatroom']:
                    self.connected_clients[user_to_kick]['socket'].sendall((KICK_MESSAGE).encode(FORMAT))
                    self.connected_clients[user_to_kick]['chatroom'] = '0'
                    self.broadcast_message(client_username,
                                           f"[System Administrator]: The user {user_to_kick} has benn kicked out from the chat",
                                           1)
                else:
                    self.connected_clients[client_username]['socket'].sendall((
                                                                                  f"To kick {user_to_kick} please connect to the same chatroom").encode(
                        FORMAT))
            else:
                self.connected_clients[client_username]['socket'].sendall((
                                                                              f"the username: {user_to_kick} was not found in the clients database, try check your spelling").encode(
                    FORMAT))
        else:
            self.connected_clients[client_username]['socket'].sendall((
                                                                          "You don't have permissions to kick out users.").encode(
                FORMAT))

    def ban_user(self, client_username, user_to_ban):
        if self.clients_credentials1[client_username]['user_type'] == 'admin':
            if user_to_ban in self.clients_credentials1.keys():
                if self.clients_credentials1[user_to_ban]['is_banned'] == 'banned':
                    self.connected_clients[client_username]['socket'].sendall((
                                                                                  f"the username: {user_to_ban} in already banned").encode(
                        FORMAT))
                elif user_to_ban in self.connected_clients.keys():
                    self.connected_clients[user_to_ban]['socket'].sendall((BAN_MESSAGE).encode(FORMAT))
                    self.clients_credentials1[user_to_ban]['is_banned'] = 'banned'
                    self.save_user_credentials()
                    self.connected_clients[user_to_ban]['chatroom'] = '0'
                    self.broadcast_message(client_username,
                                           f"[System Administrator]: The user {user_to_ban} has benn banned from the chat",
                                           1)
                else:
                    self.clients_credentials1[user_to_ban]['is_banned'] = 'banned'
                    self.save_user_credentials()
                    self.connected_clients[client_username]['socket'].sendall((
                                                                                  f"the username: {user_to_ban} was banned").encode(
                        FORMAT))
            else:
                self.connected_clients[client_username]['socket'].sendall((
                                                                              f"the username: {user_to_ban} was not found in the clients database, try check your spelling").encode(
                    FORMAT))
        else:
            self.connected_clients[client_username]['socket'].sendall((
                                                                          "You don't have permissions to ban users.").encode(
                FORMAT))

    def unban_user(self, client_username, user_to_unban):
        if self.clients_credentials1[client_username]['user_type'] == 'admin':
            if user_to_unban in self.clients_credentials1.keys():
                if self.clients_credentials1[user_to_unban]['is_banned'] == 'banned':
                    self.clients_credentials1[user_to_unban]['is_banned'] = 'free'
                    self.save_user_credentials()
                    self.broadcast_message(client_username,
                                           f"[System Administrator]: The user {user_to_unban} has been unbanned",
                                           1)
                else:
                    self.connected_clients[client_username]['socket'].sendall((
                                                                                  f"the username: {user_to_unban} in not banned").encode(
                        FORMAT))
            else:
                self.connected_clients[client_username]['socket'].sendall((
                                                                              f"the username: {user_to_unban} was not found in the clients database, try check your spelling").encode(
                    FORMAT))
        else:
            self.connected_clients[client_username]['socket'].sendall((
                                                                          "You don't have permissions to unban users.").encode(
                FORMAT))


def main():
    server = Server()
    server.start()


if __name__ == '__main__':
    main()
