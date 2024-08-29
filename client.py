# Importing the socket library, to handle the communication
import socket
import time
import threading
import os
# Importing the tkinter library and some relevant moduls, to implement the GUI
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
import webbrowser
import time
# Importing cryptography modules, to handle encrypted communication
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Defining constants
# Defining the IP address of the server to be the IPv4 address of my computer inside my local network
SERVER_IP_ADDRESS = socket.gethostbyname(socket.gethostname())
# Defining a port number, using an arbitrary and unused port number
PORT = 5050
# Defining the format of the messages
FORMAT = "utf-8"
# Defining the maximum size of a received fragment
SIZE = 1024
# Defining the number of allowed sign-in tries
ALLOWED_TRIES = 3

# Generate a key and IV (Initialization Vector)
CLIENT_KEY = b'\x04\x03|\xeb\x8dSh\xe0\xc5\xae\xe5\xe1l9\x0co\xca\xb1"\r-Oo\xbaiYa\x1e\xd1\xf7\xa2\xdf'
IV = b'#\xb59\xee\xa7\xc4@n\xe5r\xac\x97lV\xff\xf1'

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


# Function to encrypt plaintext using AES-CBC
def encrypt(plaintext):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode(FORMAT)) + padder.finalize()
    cipher = Cipher(algorithms.AES(CLIENT_KEY), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext


# Function to decrypt ciphertext using AES-CBC
def decrypt(ciphertext):
    cipher = Cipher(algorithms.AES(CLIENT_KEY), modes.CBC(IV), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data.decode(FORMAT)

# Client class: Initializing a client instance - setting connection to the server, entering the chat etc...
class Client:
    def __init__(self):
        # Initializing a GUI instance to handle all gui windows
        gui = GUI()
        self.rate_limiter = RateLimiter(capacity=10, rate_limit=0.5)  # Allow 20 message every 1 second
        self.connected_users = ""
        try:
            # Welcome window: sign in or sign up
            gui.welcome_window()
        except Exception:
            return
        sign_in_or_sign_up = gui.welcome_result
        self.client_socket = self.connect_to_server()
        try:
            self.client_socket.send(sign_in_or_sign_up.encode(FORMAT))
        except Exception:
            return
        # According to selection, go to sign in or sign up
        sign_in_status, sign_up_status = -1, -1
        if sign_in_or_sign_up == 'SIGN_IN':
            sign_in_status = self.sign_in_user(gui)
            if sign_in_status == 0:
                is_banned = (self.client_socket.recv(SIZE)).decode(FORMAT)
                if is_banned == "free":
                    pass
                else:
                    sign_in_status = -1
                    gui.banned_user_window()

            elif sign_in_status == 1:
                return
            else:
                gui.show_times_window()
        else:
            sign_up_status = self.sign_up_user(gui)
            if sign_up_status == 1:
                return
        if sign_in_status == 0 or sign_up_status == 0:
            self.choose_chatroom(gui)
            # All is set, start the client
            self.system_messages = 0
            self.start(gui)

    def connect_to_server(self):
        # Initiating a TCP socket for the client
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Connecting to the server
        client_socket.connect((SERVER_IP_ADDRESS, PORT))
        return client_socket

    def sign_in_user(self, gui):
        gui.sign_in_window(1)
        self.username = gui.username_entry
        self.password = gui.password_entry
        try:
            username_and_password = self.username + " " + self.password
        except Exception:
            return 1
        counter = 1
        if self.username == "" or self.password == "":
            authentication_status = FAILED_SIGN_IN
        else:
            self.client_socket.send(username_and_password.encode(FORMAT))
            authentication_status = (self.client_socket.recv(SIZE)).decode(FORMAT)
        while authentication_status == FAILED_SIGN_IN and counter < ALLOWED_TRIES:
            gui.sign_in_window(0)
            self.username = gui.username_entry
            self.password = gui.password_entry
            try:
                username_and_password = self.username + " " + self.password
            except Exception:
                return 1
            if self.username == "" or self.password == "":
                authentication_status = FAILED_SIGN_IN
            else:
                self.client_socket.send(username_and_password.encode(FORMAT))
                authentication_status = (self.client_socket.recv(SIZE)).decode(FORMAT)
            counter += 1
        if authentication_status == FAILED_SIGN_IN:
            return -1
        return 0

    def sign_up_user(self, gui):
        gui.sign_up_window(1)
        self.username = gui.username_entry
        self.password = gui.password_entry
        try:
            username_and_password = self.username + " " + self.password
        except Exception:
            return 1
        if self.username == "" or self.password == "":
            authentication_status = FAILED_SIGN_UP
        else:
            self.client_socket.send(username_and_password.encode(FORMAT))
            authentication_status = (self.client_socket.recv(SIZE)).decode(FORMAT)
        while authentication_status == FAILED_SIGN_UP:
            gui.sign_up_window(0)
            self.username = gui.username_entry
            self.password = gui.password_entry
            try:
                username_and_password = self.username + " " + self.password
            except Exception:
                return 1
            if self.username == "" or self.password == "":
                authentication_status = FAILED_SIGN_UP
            else:
                self.client_socket.send(username_and_password.encode(FORMAT))
                authentication_status = (self.client_socket.recv(SIZE)).decode(FORMAT)
        return 0

    def choose_chatroom(self, gui):
        gui.choose_chatroom_window(1)
        self.chatroom = gui.chatroom_entry
        self.client_socket.send(self.chatroom.encode(FORMAT))
        valid_chatroom = (self.client_socket.recv(SIZE)).decode(FORMAT)
        while valid_chatroom != "0":
            gui.choose_chatroom_window(0)
            self.chatroom = gui.chatroom_entry
            self.client_socket.send(self.chatroom.encode(FORMAT))
            valid_chatroom = (self.client_socket.recv(SIZE)).decode(FORMAT)

    def start(self, gui):
        try:
            gui.chat_window2(self)
        except Exception:
            pass


class GUI:

    def welcome_window(self):
        self.welcome_result = None
        self.welcome_root = tk.Tk()
        self.welcome_root.config(bg="#f0f0f0")
        self.center_window(self.welcome_root)
        self.welcome_root.title("Welcome to Yuval Disatnik's chat rooms!")

        self.label = tk.Label(self.welcome_root, text="Choose an option:", bg="#f0f0f0", fg="#333")
        self.label.pack(pady=10)

        self.sign_in_button = tk.Button(self.welcome_root, text="Sign In", command=self.welcome_sign_in)
        self.sign_in_button.pack(pady=5)

        self.sign_up_button = tk.Button(self.welcome_root, text="Sign Up", command=self.welcome_sign_up)
        self.sign_up_button.pack(pady=5)
        self.welcome_root.mainloop()

    def welcome_sign_in(self):
        self.welcome_result = "SIGN_IN"
        self.welcome_root.destroy()

    def welcome_sign_up(self):
        self.welcome_result = "SIGN_UP"
        self.welcome_root.destroy()

    def sign_in_window(self, is_first_attempt):
        self.username_entry = None
        self.password_entry = None

        self.signin_root = tk.Tk()
        self.center_window(self.signin_root)
        self.signin_root.title("Signin Window")
        if is_first_attempt == 1:
            self.label = tk.Label(self.signin_root, text="Please enter your username and password:", bg="#f0f0f0", fg="#333")
        else:
            self.label = tk.Label(self.signin_root, text="Wrong username or password. Please try again:",
                                  bg="#f0f0f0", fg="#333")
        self.label.grid(row=0, column=0, columnspan=2, padx=10, pady=(10, 5))
        tk.Label(self.signin_root).grid(row=1)
        # Username label and entry

        username_label = tk.Label(self.signin_root, text="Username:", bg="#f0f0f0", fg="#333")
        username_label.grid(row=2, column=0, padx=10, pady=5, sticky="e")
        username_entry = tk.Entry(self.signin_root)
        username_entry.grid(row=2, column=1, padx=10, pady=5, sticky="ew")

        # Password label and entry

        password_label = tk.Label(self.signin_root, text="Password:", bg="#f0f0f0", fg="#333")
        password_label.grid(row=3, column=0, padx=10, pady=5, sticky="e")
        password_entry = tk.Entry(self.signin_root, show="*")
        password_entry.grid(row=3, column=1, padx=10, pady=5, sticky="ew")

        # Sign-in button

        sign_in_button = tk.Button(self.signin_root, text="Sign In",
                                   command=lambda: self.set_credentials(self.signin_root, username_entry.get(),
                                                                        password_entry.get()))
        sign_in_button.grid(row=4, column=0, columnspan=2, pady=(20, 10))

        self.signin_root.mainloop()

    def set_credentials(self, window, username, password):
        self.username_entry = username
        self.password_entry = password
        window.destroy()

    def sign_up_window(self, is_first_attempt):
        self.username_entry = None
        self.password_entry = None

        self.signup_root = tk.Tk()
        self.center_window(self.signup_root)
        self.signup_root.title("Signup Window")
        if is_first_attempt == 1:
            self.label = tk.Label(self.signup_root, text="Please choose your username and password:\n\n\n")
        else:
            self.label = tk.Label(self.signup_root, text="Invalid username or password. Please try again:\n\n\n")
        self.label.grid(pady=10)
        # Username label and entry
        username_label = tk.Label(self.signup_root, text="Username:")
        username_label.grid(row=0, column=0, padx=10, pady=5, sticky="ew")
        username_entry = tk.Entry(self.signup_root)
        username_entry.grid(row=0, column=1, padx=10, pady=5)

        # Password label and entry
        password_label = tk.Label(self.signup_root, text="Password:")
        password_label.grid(row=1, column=0, padx=10, pady=5, sticky="ew")
        password_entry = tk.Entry(self.signup_root, show="*")
        password_entry.grid(row=1, column=1, padx=10, pady=5)

        # Sign-in button
        sign_in_button = tk.Button(self.signup_root, text="Sign Up",
                                   command=lambda: self.set_credentials(self.signup_root, username_entry.get(),
                                                                        password_entry.get()))
        sign_in_button.grid(row=2, column=0, columnspan=2, pady=10)

        self.signup_root.mainloop()

    def choose_chatroom_window(self, is_first_attempt):
        self.chatroom_entry = None
        self.chatroom_root = tk.Tk()
        self.center_window(self.chatroom_root)
        self.chatroom_root.title("Chatroom Window")
        if is_first_attempt == 1:
            self.label = tk.Label(self.chatroom_root, text="Please choose a chatroom:\n"
                                                           "Chat room 1 (Enter 1), Chat room 2 (Enter 2), Chat room 3 (Enter 3)")
        else:
            self.label = tk.Label(self.chatroom_root, text="Invalid chatroom number. Please try again:\n"
                                                           "Chat room 1 (Enter 1), Chat room 2 (Enter 2), Chat room 3 (Enter 3)")
        self.label.grid(row=0, column=0, columnspan=2, padx=10, pady=(10, 5))
        tk.Label(self.chatroom_root).grid(row=1)
        # Username label and entry
        chatroom_label = tk.Label(self.chatroom_root, text="Chatroom number:")
        chatroom_label.grid(row=2, column=0, padx=10, pady=5, sticky="e")
        chatroom_entry = tk.Entry(self.chatroom_root)
        chatroom_entry.grid(row=2, column=1, padx=10, pady=5, sticky="ew")

        chatroom_button = tk.Button(self.chatroom_root, text="Enter chat room",
                                    command=lambda: self.set_chatroom(chatroom_entry.get()))
        chatroom_button.grid(row=4, column=0, columnspan=2, pady=(20, 10))

        self.chatroom_root.mainloop()

    def set_chatroom(self, chatroom):
        self.chatroom_entry = chatroom
        self.chatroom_root.destroy()

    def chat_window2(self, client):
        self.chat_window_root = tk.Tk()
        self.center_window(self.chat_window_root, 1)
        self.chat_window_root.title(f"Chat Room {client.chatroom}")
        # Create scrolled text widget to display messages with texture
        self.chat_display = scrolledtext.ScrolledText(self.chat_window_root, width=60, height=20, bg="LavenderBlush2",
                                                      fg="black")
        self.chat_display.grid(row=0, column=0, columnspan=2, padx=10, pady=10)
        self.chat_display.config(insertbackground="black", relief="sunken", borderwidth=2)

        # Create entry widget for typing messages
        self.message_entry = tk.Entry(self.chat_window_root, width=50)
        self.message_entry.grid(row=1, column=0, padx=10, pady=5, sticky="ew")

        # Create send button to send messages
        self.send_button = tk.Button(self.chat_window_root, text="Send",
                                     command=lambda: self.send_message(client, self.message_entry.get()),
                                     bg="royalblue4",
                                     fg="white")
        self.send_button.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        # Create buttons for additional actions with uniform color
        self.create_action_button("Upload File", lambda: self.send_file(client), row=2, column=0)
        self.create_action_button("Change Password", lambda: self.change_password_window(client), row=2, column=1)
        self.create_action_button("Show Connected Users", lambda: self.show_connected_users(client), row=3, column=0)
        self.create_action_button("Leave Room", lambda: self.send_message(client, "DISCONNECT_MESSAGE"), row=3,
                                  column=1, color="red")
        """self.create_action_button("Change Room", lambda: self.change_room(client), row=3, column=1)"""

        self.stop_thread = False
        gui_receive_thread = threading.Thread(target=self.receive_message, args=(self, client))
        gui_receive_thread.start()

        # Sending request to receive all messages
        self.send_message(client, SEND_PREVIOUS_MESSAGES)
        self.chat_window_root.mainloop()

    def create_action_button(self, text, command, row, column, color="lightblue"):
        button = tk.Button(self.chat_window_root, text=text, command=command, bg=color, fg="black")
        button.grid(row=row, column=column, padx=10, pady=5, sticky="ew")

    def change_room(self, client):
        client.choose_chatroom(self)
        client.system_messages = 0
        client.client_socket.send("CHANGE_ROOM".encode(FORMAT))
        client.client_socket.send(f"{client.chatroom}".encode(FORMAT))
        self.chat_window_root.destroy()
        self.chat_window2(client)

    def send_message(self, client, msg):
        try:
            if client.rate_limiter.allow_request():
                if msg == 'DISCONNECT_MESSAGE':
                    # Client want's to quit
                    client.client_socket.send(DISCONNECT_MESSAGE.encode(FORMAT))
                    self.chat_window_root.destroy()
                else:
                    client.client_socket.sendall(msg.encode(FORMAT))
                    self.message_entry.delete(0, tk.END)
            else:
                messagebox.showinfo("System Message", "Sending rate exceeded")
        except Exception:
            self.lost_connection()

    def send_file(self, client):
        try:
            file_path = filedialog.askopenfilename()
            try:
                with open(file_path, 'rb') as file:
                    file_contents = file.read()
            except Exception:
                pass
            # self.message_entry.insert(tk.END, file_path)
            file_details = f"{FILE_ALERT_MESSAGE} {os.path.getsize(file_path)} {file_path.split('/')[-1]}"
            client.client_socket.send((file_details).encode(FORMAT))
            # time.sleep(0.5)
            client.client_socket.sendall(file_contents)
            client.client_socket.send(b'<END_OF_FILE>')
            # self.message_entry.delete(0, tk.END)
        except Exception:
            self.lost_connection()

    def receive_message(self, gui, client):
        try:
            while True:
                try:
                    message = client.client_socket.recv(SIZE).decode(FORMAT)
                    client.system_messages += 1
                    if not message:
                        break
                    elif message == DISCONNECT_MESSAGE:
                        break
                    # Display the message in the chat display
                    # self.chat_display.insert(tk.END, message + '\n')
                    elif client.system_messages > 1:
                        if message.startswith(SHOW_ALL_CONNECTED_USERS):
                            client.connected_users = message
                        elif message.startswith(FILE_ALERT_MESSAGE):
                            file_size = message.split()[1]
                            file_name = message.split()[2]
                            sender = message.split()[3]
                            file_contents = self.receive_file(client.client_socket)
                            if sender == client.username:
                                self.chat_display.insert(tk.END, f"You: {file_name}", 'hyperlink')

                            else:
                                self.chat_display.insert(tk.END, f"{sender}: {file_name}", 'hyperlink')
                            self.chat_display.tag_config('hyperlink', foreground='blue', underline=True)
                            self.chat_display.tag_bind('hyperlink', '<Button-1>', lambda: webbrowser.open(file_name))
                        else:
                            try:
                                sender, msg = message.split(":")
                                if sender == client.username:
                                    to_display = f"You: {msg}"
                                else:
                                    to_display = message
                            except Exception:
                                to_display = message
                            self.chat_display.config(state=tk.NORMAL)
                            self.chat_display.insert(tk.END, to_display + "\n")
                            self.chat_display.yview(tk.END)
                            self.chat_display.config(state=tk.DISABLED)
                except Exception:
                    break
        except Exception:
            self.lost_connection()

    def lost_connection(self):
        self.chat_display.config(state=tk.NORMAL)
        to_display = "The connection with the server was lost due to an unexpected error.\n Please try to re-open the chat to connect\n"
        self.chat_display.insert(tk.END, to_display + "\n")
        self.chat_display.yview(tk.END)
        self.chat_display.config(state=tk.DISABLED)

    def receive_file(self, client_socket):
        data = b""
        done = False
        while not done:
            partial_data = (client_socket.recv(SIZE))
            if partial_data.endswith(b'<END_OF_FILE>'):
                data += partial_data[:-len(b'<END_OF_FILE>')]
                done = True
            else:
                data += partial_data
        return data

    def change_password(self, client, new_password):
        try:
            self.new_password = new_password
            client.client_socket.send(f"{NEW_PASSWORD} {self.new_password}".encode(FORMAT))
            self.root1.destroy()
        except Exception:
            self.lost_connection()

    def change_password_window(self, client):
        try:
            self.new_password = None
            self.root1 = tk.Toplevel(self.chat_window_root)
            self.center_window(self.root1)
            self.root1.title("Change Password Window")

            self.label = tk.Label(self.root1, text="Please enter your new password:", bg="#f0f0f0", fg="#333")
            self.label.grid(row=0, column=0, columnspan=2, padx=10, pady=(10, 5))
            tk.Label(self.root1).grid(row=1)
            new_password_label = tk.Label(self.root1, text="Password:", bg="#f0f0f0", fg="#333")
            new_password_label.grid(row=2, column=0, padx=10, pady=5, sticky="e")
            new_password_entry = tk.Entry(self.root1)
            new_password_entry.grid(row=2, column=1, padx=10, pady=5, sticky="ew")

            # Sign-in button
            new_password_button = tk.Button(self.root1, text="Change Password",
                                            command=lambda: self.change_password(client, new_password_entry.get()))
            new_password_button.grid(row=4, column=0, columnspan=2, pady=(20, 10))

            self.root1.mainloop()
        except Exception:
            self.lost_connection()

    def show_connected_users(self, client):
        try:
            client.client_socket.send(f"{SHOW_ALL_CONNECTED_USERS}".encode(FORMAT))
            time.sleep(0.5)
            self.connected_users_window(client.connected_users)
        except Exception:
            self.lost_connection()

    def connected_users_window(self, message):
        try:
            users_window = tk.Toplevel(self.chat_window_root)
            self.center_window(users_window)
            users_window.title("Connected Users")

            # Display the list of connected users in a label or a scrolled text widget
            label = tk.Label(users_window, text="Connected Users:")
            label.pack()

            connected_users_label = tk.Label(users_window, text=message[len(SHOW_ALL_CONNECTED_USERS) + 1:])
            connected_users_label.pack()

            users_window.mainloop()
        except Exception:
            self.lost_connection()

    def banned_user_window(self):
        ban_window = tk.Tk()
        self.center_window(ban_window, 2)
        ban_window.title("System Message")

        # Display the list of connected users in a label or a scrolled text widget
        label = tk.Label(ban_window, text="\n")
        label.pack()

        ban_window_label = tk.Label(ban_window, text=BAN_MESSAGE)
        ban_window_label.pack()

        ban_window.mainloop()

    def show_times_window(self):
        self.times_window = tk.Tk()
        self.center_window(self.times_window, 2)
        self.times_window.title("System Message")

        # Display the list of connected users in a label or a scrolled text widget
        label = tk.Label(self.times_window, text="\n")
        label.pack()

        ban_window_label = tk.Label(self.times_window, text="Too many wrong tries!")
        ban_window_label.pack()

        self.times_window.mainloop()

    def center_window(self, window, is_chat_window=0):
        # Get the screen width and height
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        if is_chat_window == 0:
            window.geometry("400x300")
            # Calculate the position of the window
            x = (screen_width - window.winfo_reqwidth()) // 2
            y = (screen_height - window.winfo_reqheight()) // 2
        elif is_chat_window == 2:
            window.geometry("500x100")
            # Calculate the position of the window
            x = (screen_width - window.winfo_reqwidth()) // 2
            y = (screen_height - window.winfo_reqheight()) // 2
        else:
            window.geometry("550x500")
            # Calculate the position of the window
            x = (screen_width - window.winfo_reqwidth()) // 4
            y = (screen_height - window.winfo_reqheight()) // 4

        # Set the window's position
        window.geometry("+{}+{}".format(x, y))

class RateLimiter:
    def __init__(self, capacity, rate_limit):
        self.capacity = capacity  # Maximum number of tokens in the bucket
        self.rate_limit = rate_limit  # Tokens added per second
        self.tokens = capacity  # Initially, bucket is full
        self.last_refill_time = time.time()  # Time of last token refill

    def refill_bucket(self):
        current_time = time.time()
        time_passed = current_time - self.last_refill_time
        tokens_to_add = time_passed * self.rate_limit
        self.tokens = min(self.capacity, self.tokens + tokens_to_add)
        self.last_refill_time = current_time

    def allow_request(self):
        self.refill_bucket()
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        else:
            return False

def main():
    client = Client()
    try:
        client.client_socket.send(DISCONNECT_MESSAGE.encode(FORMAT))
    except Exception:
        pass


if __name__ == '__main__':
    main()
