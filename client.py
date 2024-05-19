import socket
import tkinter as tk
from tkinter import messagebox,filedialog
import threading
import os
import subprocess

global message_entry, listening_socket, listening_port
listening_port = 0  # Initialize the listening port

def start_client():
    global chat_window, client_socket, message_entry, chat_log, action_var, username_entry, password_entry, listening_socket

    def send_credentials():
        global username_entry, password_entry
        username = username_entry.get()
        password = password_entry.get()
        action = action_var.get()

        if not username or not password or not action:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        credentials = f"{username},{password},{action}"
        client_socket.send(credentials.encode())

        response = client_socket.recv(1024).decode()
        response_label.config(text=response)

        if "Registration successful" in response:
            response_label.after(2000, lambda: response_label.config(text=""))  # Clear message after 2 seconds
            root.after(2000, restart_client)  # Restart the client after 2 seconds

        elif "successful" in response:
            root.withdraw()  # Hide the login/register window
            open_chat_window(response, username)  # Open the chat window with the appropriate success message

    def restart_client():
        root.deiconify()
        start_client()

    def open_chat_window(success_message, username):
        global chat_window
        global message_entry
        global chat_log,download_button
        chat_window = tk.Toplevel(root)
        chat_window.title("Chat Client")
        
        success_label = tk.Label(chat_window, text=f"Welcome, {username}!")
        success_label.pack()

        success_label = tk.Label(chat_window, text=success_message)
        success_label.pack()

        chat_frame = tk.Frame(chat_window)
        chat_frame.pack()

        message_entry = tk.Entry(chat_frame)  # Define message_entry globally
        message_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)

        send_button = tk.Button(chat_frame, text="Send", command=send_message)
        send_button.pack(side=tk.RIGHT)

        chat_log = tk.Text(chat_window, height=10, width=50)
        chat_log.pack()

        show_users_button = tk.Button(chat_window, text="Show Users", command=request_user_list)
        show_users_button.pack()

        send_file_button = tk.Button(chat_window, text="Send File", command=send_file)
        send_file_button.pack()
        
       

        logout_button = tk.Button(chat_window, text="Logout", command=logout)
        logout_button.pack()

        # Start listening thread
        threading.Thread(target=start_listening).start()

    def logout():
        username = username_entry.get()
        password = password_entry.get()
        credentials = f"{username},{password},logout"
        client_socket.send(credentials.encode())
        chat_window.destroy()
        root.deiconify()
        username_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)
        action_var.set("login")

    def request_user_list():
        client_socket.send("get_clients".encode())
        users = client_socket.recv(1024).decode()
        user_list = users.split(", ")
        select_user_window = tk.Toplevel(chat_window)
        select_user_window.title("Select User")
        
        def start_chat():
            selected_users = [user_var.get() for user_var in user_vars if user_var.get()]
            print(selected_users)
            selected_usernames = [user_list[i] for i, value in enumerate(selected_users) if value]
            print(selected_usernames)

            if not selected_usernames:
                messagebox.showerror("Error", "Please select at least one user.")
            else:
                messagebox.showinfo("Info", f"Starting chat with {', '.join(selected_usernames)}")
                select_user_window.destroy()
                for username in selected_usernames:
                    client_socket.send(f"get_socket_info,{username}".encode())
                    user_info = client_socket.recv(1024).decode()
                    user_ip, user_port = user_info.split(':')
                    connect_to_user(username, user_ip, int(user_port))

        user_vars = []
        for user in user_list:
            user_var = tk.BooleanVar()
            user_check = tk.Checkbutton(select_user_window, text=user, variable=user_var)
            user_check.pack(anchor="w")
            user_vars.append(user_var)
        
        start_button = tk.Button(select_user_window, text="Start Chat", command=start_chat)
        start_button.pack()

    def connect_to_user(username, user_ip, user_port):
        global user_socket
        print("User name for connect to user  to which needs to connect ", username) 
        client_socket.send(f"{username},{user_ip},get_listening_port".encode())
        server__socket = client_socket.recv(1024).decode()
        print(server__socket)
        server_m_socket = client_socket.recv(1024).decode()
        print(server_m_socket)
        print(f"The listening port received from the server for {username} is {server_m_socket}")
        user_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print (f"Connecting to socket {user_ip}, {server_m_socket}")
        user_socket.connect((user_ip, int(server_m_socket)))
        print("User socket connected to ", server_m_socket)
        chat_log.insert(tk.END, f"Connected to {username}\n")
        threading.Thread(target=receive_messages_from_user, args=(user_socket,)).start()

    def send_message():

        message = message_entry.get()
        print("User socket ", user_socket.getsockname())
        user_socket.send(f"text,{message}".encode())
        chat_log.insert(tk.END, f"You: {message}\n")
        message_entry.delete(0, tk.END)

    def receive_messages_from_user(sock):
        while True:
            try:
                data = sock.recv(1024).decode()
                if data:
                    if data.startswith("text,"):
                        chat_log.insert(tk.END, f"Other user: {data[5:]}\n")
                    elif data.startswith("file,"):
                        _, filename, filesize = data.split(",")
                        receive_file(sock, filename, int(filesize))
            except ConnectionResetError:
                break

    def start_listening():
        global listening_socket, listening_port
        listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listening_socket.bind(('localhost', 0))  # Bind to any available port
        listening_port = listening_socket.getsockname()[1]
        listening_socket.listen(5)
        print(f"Listening on port {listening_port}")
        print(f"listening socket --Port: {listening_socket}")
        listening_socket_info =  f"{username_entry.get()},{listening_port},listening_socket"
        client_socket.send(listening_socket_info.encode()) #calling listening socket

        while True:
            conn, addr = listening_socket.accept()
            threading.Thread(target=handle_incoming_connection, args=(conn,addr)).start()

    
    def handle_incoming_connection(conn, addr):
        global receiving_socket
        receiving_socket = conn
        while True:
            try:
                data = conn.recv(1024).decode()
                if data:
                    if data.startswith("text,"):
                        chat_log.insert(tk.END, f"Other user: {data[5:]}\n")
                    elif data.startswith("file,"):
                        _, filename, filesize = data.split(",")
                        rec_fileadd = receive_file(conn, filename, int(filesize))
                        
            except ConnectionResetError:
                break
                    
    def send_file():
        file_path = filedialog.askopenfilename()
        if file_path:
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)
            user_socket.send(f"file,{file_name},{file_size}".encode())
            with open(file_path, "rb") as f:
                while chunk := f.read(1024):
                    user_socket.send(chunk)
            chat_log.insert(tk.END, f"You sent a file: {file_name}\n")

    def receive_file(sock, filename, filesize):
        received_file_path = f"received_{filename}"
        with open(received_file_path, "wb") as f:
            bytes_received = 0
            while bytes_received < filesize:
                chunk = sock.recv(min(1024, filesize - bytes_received))
                if not chunk:
                    break
                f.write(chunk)
                bytes_received += len(chunk)
        chat_log.insert(tk.END, f"Received a file: {filename}\n")
        print("In receive",received_file_path)
        download_and_view_file(received_file_path)
        return received_file_path
    
    def download_and_view_file(received_file_path):
        print("In download and receive",received_file_path)
        file_path = filedialog.asksaveasfilename(defaultextension="", filetypes=[("All Files", "*.*")])
        if file_path and received_file_path:
            _, file_extension = os.path.splitext(received_file_path)
            if not file_extension:
                messagebox.showerror("Error", "File extension not found.")
                return
            with open(received_file_path, "rb") as f:
                with open(file_path + file_extension, "wb") as downloaded_file:
                    for chunk in iter(lambda: f.read(1024), b""):
                        downloaded_file.write(chunk)
            if os.name == "nt":  # Check if the operating system is Windows
                subprocess.Popen(["start", file_path + file_extension], shell=True)
            elif os.name == "posix":  # Check if the operating system is POSIX (e.g., Linux, macOS)
                subprocess.Popen(["xdg-open", file_path + file_extension])
            else:
                messagebox.showerror("Error", "Unsupported operating system.")



    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 9999))

    root = tk.Tk()
    root.title("Login/Register")

    action_var = tk.StringVar()

    welcome_label = tk.Label(root, text=client_socket.recv(1024).decode())
    welcome_label.pack()

    action_frame = tk.Frame(root)
    action_frame.pack()

    action_label = tk.Label(action_frame, text="Choose action:")
    action_label.grid(row=0, column=0)

    action_var.set("login")
    register_radio = tk.Radiobutton(action_frame, text="Register", variable=action_var, value="register")
    register_radio.grid(row=0, column=1)

    login_radio = tk.Radiobutton(action_frame, text="Login", variable=action_var, value="login")
    login_radio.grid(row=0, column=2)

    credentials_frame = tk.Frame(root)
    credentials_frame.pack()

    username_label = tk.Label(credentials_frame, text="Username:")
    username_label.grid(row=0, column=0)
    username_entry = tk.Entry(credentials_frame)
    username_entry.grid(row=0, column=1)

    password_label = tk.Label(credentials_frame, text="Password:")
    password_label.grid(row=1, column=0)
    password_entry = tk.Entry(credentials_frame, show="*")
    password_entry.grid(row=1, column=1)

    submit_button = tk.Button(root, text="Submit", command=send_credentials)
    submit_button.pack()

    response_label = tk.Label(root, text="")
    response_label.pack()

    root.mainloop()

if __name__ == "__main__":
    start_client()
