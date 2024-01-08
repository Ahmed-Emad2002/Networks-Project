import socket
import threading
from peer import peerMain
from peer import PeerServer
import time



def client_thread(user, password, peerServerPort):
    try:
        # Create a new socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Create a new socket
            # print(f"Calling createAccount for user: {user}, password: {password}")
            # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Connect to the server
            s.connect(('192.168.1.2', 15600))  # Replace with your server address and port
            # Call the function
            peer_instance = peerMain()
            peer_instance.createAccount(username=user,password=password)
            peer_instance.login(username=user, password=password, peerServerPort=peerServerPort)
            peer_instance.isOnline = True
            peer_instance.loginCredentials = (user, password)
            peer_instance.peerServerPort = peerServerPort
            # creates the server thread for this peer, and runs it
            peer_instance.peerServer = PeerServer(peer_instance.loginCredentials[0], peer_instance.peerServerPort)
            peer_instance.peerServer.start()
            # hello message is sent to registry
            peer_instance.sendHelloMessage()
            peer_instance.logged_in = True
            peer_instance.account_created = False

            # Close the socket
            # s.close()
    except Exception as e:
        print(f"Error in client_thread for user {user}: {e}")

# Generate a large number of users and passwords
num_users = 100
users = [f'user{i}' for i in range(1, num_users + 1)]
passwords = [f'Password-{i}' for i in range(1, num_users + 1)]


# Create and start a new thread for each user
threads = []
for i, (user, password) in enumerate(zip(users, passwords),start =1024):
    peer_server_port = i
    thread = threading.Thread(target=client_thread, args=(user, password,peer_server_port))
    threads.append(thread)
    thread.start()
    time.sleep(2)  # Introduce a 10-second delay between threads


# Wait for all threads to finish
for thread in threads:
    thread.join()