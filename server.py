import socket
import threading
import sqlite3

DATABASE = 'users.db'

def create_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, password TEXT)''')
    conn.commit()
    conn.close()

def register_user(username, password):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    conn.close()

def authenticate_user(username, password):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username=?", (username,))
    user_data = c.fetchone()
    conn.close()
    if user_data:
        stored_password = user_data[0]
        return stored_password == password
    return False

def send_user_list(client_socket):
    print ("Sending user list",active_usernames)
    active_users = ", ".join(active_usernames)
    print ("Sending user list concatenated",active_users)
    client_socket.send(active_users.encode())

def handle_client(client_socket, client_address):
    print ("Client dictionary --------------- ",clients)

    try:
        client_socket.send("Welcome to the server! Please register or login.".encode())

        while True:
            data = client_socket.recv(1024).decode()
            print ("Data decodedddd: ", data)
            if not data:
                break
            if data.strip() == "get_clients":
                action = "get_clients"
                print("yes action is to get clients")
                send_user_list(client_socket)
                continue
            
              
            
            credentials = data.split(",")  # Split the received data
            if credentials[0]== 'get_socket_info':
                print("credentials [0] is get socket info")
                action = 'get_socket_info'
                selected_user = credentials[1]
                print("selected user", selected_user)
            if len(credentials) == 3:
                username, password, action = credentials

            if action == "register":
                if authenticate_user(username, password):
                    client_socket.send("User already exists. Please choose a different username.".encode())
                else:
                    register_user(username, password)
                    client_socket.send("Registration successful. You can now login.".encode())
            elif action == "login":
                if authenticate_user(username, password):
                    client_socket.send("Login successful.".encode())
                    active_usernames.append(username)  # Add the username to active users list
                    clients[username] = client_address  # Store the client's IP address and port
                    print ("Client dictionary after logging in ",clients)
                else:
                    client_socket.send("Invalid username or password.".encode())
            elif action == "logout":
                print("Logout with 3 credentials ")
                print("Username: %s" % username)
                print("Client: " , clients)
                if username in clients:
                    print("Yes condition works no?")
                    del clients[username]  # Remove the client from active clients
                    print("line 1")
                    del listening_ports[username]  # Remove 
                    print("line 2")
                    print("Listening ports dictionary after logging out",listening_ports)
                    if username in active_usernames:
                        print("line 3")
                        active_usernames.remove(username)  # Remove the username from active users list
                print("Active users: -----------" ,active_usernames)
            elif action == "get_socket_info":
                print("In get socket info")
                print("Client: " , clients)
                
                #current user
                if username in clients:
                    print("Yes username in clients dictionary",username)
                    user_address = clients[username]  # Get the IP address and port of the selected user
                    user_socket_info = f"{user_address[0]}:{user_address[1]}"  # Format the socket info
                    client_socket.send(user_socket_info.encode())  # Send socket info back to the client
                else:
                    print("No username in clients dictionary")
                    client_socket.send("User not found.".encode())  # If user not found, send an error message
                
                #selected user
                print("selected usernames: " , selected_user)
                if selected_user in clients:
                    print("Yes username in clients dictionary",selected_user)
                    user_address = clients[selected_user]  # Get the IP address and port of the selected user
                    user_socket_info = f"{user_address[0]}:{user_address[1]}"  # Format the socket info
                    client_socket.send(user_socket_info.encode())  # Send socket info back to the client
                else:
                    print("No username in clients dictionary")
                    client_socket.send("User not found.".encode())  # If user not found, send an error message
            elif action == "listening_socket" :
                listening_ports[username] = int(password) #password is the second value in credentials for this action in second value listening port is stored
                print ("listening ports dict ", listening_ports)

            elif action == "get_listening_port" :
                print ("username in getting listening ports dict ", username)
                print ("getting listening ports dict ",listening_ports)
                if username in listening_ports :
                    port = str(listening_ports[username])  # Convert port to string before sending
                    client_socket.send(port.encode())
                    print("port in getting listening ports dict ", port)

                
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()
    print ("Client dictionary --------------- ",clients)

def start_server():
    create_db()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 9999))
    server_socket.listen(5)
    print("[*] Server started.")

    while True:
        client_sock, addr = server_socket.accept()
        print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")
        threading.Thread(target=handle_client, args=(client_sock, addr)).start()

if __name__ == "__main__":
    clients = {}  # Dictionary to store active clients with their usernames and IP addresses
    active_usernames = []  # List to store active usernames
    listening_ports ={}
    start_server()
