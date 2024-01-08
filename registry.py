from socket import *
import threading
import select
import logging
import db
import bcrypt
import re
from colorama import Fore

def is_password_valid(password):
    errors = []
    # Check if the password is at least 9 characters long.
    if len(password) < 9:
        errors.append("Password is not long enough!\n") 
    # Check if the password contains at least one digit.
    if not re.search(r'\d',password):
            errors.append("Password must contain a number!\n")
    # Check if the password contains at least one uppercase letter.
    if not re.search(r'[A-Z]',password):
            errors.append("Password must contain a capital letter!\n")
    # Check if the password contains at least one special character.
    if not re.search(r'\W',password):
        errors.append("Password must contain a special character!\n")
    # Check if the password contains at least one lowercase letter.
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain a lowercase letter!\n")
    # If the password meets all the criteria, return True and a success message.
    if not errors:
        return True, "Password is valid."
    else:
        return False, "".join(errors)
        
def hash_password(password):    
# Generate a salt using bcrypt's gensalt() function. This salt will be used to hash the password.
    salt = bcrypt.gensalt()

    # Hash the password using bcrypt's hashpw() function. The password is first encoded to bytes, 
    # as hashpw() requires a byte string. The salt is also passed to this function.
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    # The hashed password is a byte string, so we decode it back into a regular string. 
    # This decoded string is the final hashed password.
    #return hashed_password.decode()
    return hashed_password.decode()

# The function takes a hashed password and a user's password as input.
# It checks if the user's password, when hashed, matches the hashed password.
def check_password(hashed_password, user_password): 
    # print(user_password.encode())
    # print(hashed_password.encode())
    # print(bcrypt.checkpw(user_password.encode(),hashed_password.encode()))
    return bcrypt.checkpw(user_password.encode(),hashed_password.encode())



# This class is used to process the peer messages sent to registry
# for each peer connected to registry, a new client thread is created
class ClientThread(threading.Thread):
    # initializations for client thread
    def __init__(self, ip, port, tcpClientSocket):
        threading.Thread.__init__(self)
        # ip of the connected peer
        self.ip = ip
        # port number of the connected peer
        self.port = port
        # socket of the peer
        self.tcpClientSocket = tcpClientSocket
        # username, online status and udp server initializations
        self.username = None
        self.isOnline = True
        self.udpServer = None
        print(Fore.GREEN+"New thread started for " + ip + ":" + str(port))

    # main of the thread
    def run(self):
        # locks for thread which will be used for thread synchronization
        self.lock = threading.Lock()
        print(Fore.GREEN+"Connection from: " + self.ip + ":" + str(port))
        print(Fore.GREEN+"IP Connected: " + self.ip)
        
        while True:
            try:
                # if not self.tcpClientSocket.recv(1024):
                #     break  # Exit the loop if the client has disconnected
                # waits for incoming messages from peers
                message = self.tcpClientSocket.recv(1024).decode().split()
                logging.info("Received from " + self.ip + ":" + str(self.port) + " -> " + " ".join(message))            
                #   JOIN    #
                if message:
                    if message[0] == "JOIN":
                        # join-exist is sent to peer,
                        # if an account with this username already exists
                        if db.is_account_exist(message[1]):
                            response = "join-exist"
                            print("From-> " + self.ip + ":" + str(self.port) + " " + response)
                            logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)  
                            self.tcpClientSocket.send(response.encode())
                        # join-success is sent to peer,
                        # if an account with this username is not exist, and the account is created
                        else:

                            hashed_password = hash_password(message[2])
                            db.register(message[1], hashed_password)
                            response = "join-success"   
                            logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response) 
                            self.tcpClientSocket.send(response.encode())
                    #   LOGIN    #
                    elif message[0] == "LOGIN":
                        # login-account-not-exist is sent to peer,
                        # if an account with the username does not exist
                        if not db.is_account_exist(message[1]):
                            response = "login-account-not-exist"
                            logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response) 
                            self.tcpClientSocket.send(response.encode())
                        # login-online is sent to peer,
                        # if an account with the username already online
                        elif db.is_account_online(message[1]):
                            response = "login-online"
                            logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response) 
                            self.tcpClientSocket.send(response.encode())
                        # login-success is sent to peer,
                        # if an account with the username exists and not online
                        else:
                            # retrieves the account's password, and checks if the one entered by the user is correct
                            hashed_password = db.get_password(message[1])
                            # if password is correct, then peer's thread is added to threads list
                            # peer is added to db with its username, port number, and ip address
                            if check_password(hashed_password,message[2]):
                                self.username = message[1]
                                self.lock.acquire()
                                try:
                                    tcpThreads[self.username] = self
                                finally:
                                    self.lock.release()
                                db.user_login(message[1], self.ip, message[3])
                                # login-success is sent to peer,
                                # and a udp server thread is created for this peer, and thread is started
                                # timer thread of the udp server is started
                                response = "login-success"
                                logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response) 
                                self.tcpClientSocket.send(response.encode())
                                self.udpServer = UDPServer(self.username, self.tcpClientSocket)
                                self.udpServer.start()
                                self.udpServer.timer.start()
                            # if password not matches and then login-wrong-password response is sent
                            else:
                                response = "login-wrong-password"
                                logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response) 
                                self.tcpClientSocket.send(response.encode())
                    #   LOGOUT  #
                    elif message[0] == "LOGOUT":
                    # if user is online,
                        # removes the user from onlinePeers list
                        # and removes the thread for this user from tcpThreads
                        # socket is closed and timer thread of the udp for this
                        # user is cancelled
                        if len(message) > 1 and message[1] is not None and db.is_account_online(message[1]):
                            db.user_logout(message[1])
                            self.lock.acquire()
                            try:
                                if message[1] in tcpThreads:
                                    del tcpThreads[message[1]]
                            finally:
                                self.lock.release()
                            print(self.ip + ":" + str(self.port) + " is logged out")
                            self.tcpClientSocket.close()
                            self.udpServer.timer.cancel()
                            break
                        else:
                            self.tcpClientSocket.close()
                            break
                    elif message[0] == "Exit":
                        if len(message) > 1 and message[1] is not None and db.is_account_online(message[1]):
                            db.user_logout(message[1])
                            self.lock.acquire()
                            try:
                                if message[1] in tcpThreads:
                                    del tcpThreads[message[1]]
                            finally:
                                self.lock.release()
                            print(self.ip + ":" + str(self.port) + " is logged out")
                            self.tcpClientSocket.close()
                            self.udpServer.timer.cancel()
                            self.udpServer.waitHelloMessage()
                            break
                        else:
                            self.tcpClientSocket.close()
                            self.udpServer.waitHelloMessage()
                            break
                    #   SEARCH  #
                    elif message[0] == "SEARCH":
                        # checks if an account with the username exists
                        if db.is_account_exist(message[1]):
                            # checks if the account is online
                            # and sends the related response to peer
                            if db.is_account_online(message[1]):
                                peer_info = db.get_peer_ip_port(message[1])
                                response = "search-success " + peer_info[0] + ":" + peer_info[1]
                                logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response) 
                                self.tcpClientSocket.send(response.encode())
                            else:
                                response = "search-user-not-online"
                                logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response) 
                                self.tcpClientSocket.send(response.encode())
                        # enters if username does not exist 
                        else:
                            response = "search-user-not-found"
                            logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response) 
                            self.tcpClientSocket.send(response.encode())
                    elif message[0] == "GET_ONLINE_USERS":
                            # Get the list of online users from MongoDB
                            online_users = db.get_online_peers()
                            if self.username in online_users:
                                online_users.remove(self.username)
                            # Send the list of online users back to the peer
                            if online_users:
                                response = f"ONLINE_USERS {' '.join(online_users)}"
                                self.tcpClientSocket.send(response.encode())
                            else:
                                self.tcpClientSocket.send("NO_ONLINE_USERS_Available".encode())
                    elif message[0] == "CREATE_ROOM":
                            # CREATE-exist is sent to peer,
                            # if a room with this username already exists
                            if db.is_room_exist(message[1],message[2]):
                                response = "chat-room-exists"
                                print("From-> " + self.ip + ":" + str(self.port) + " " + response)
                                logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " +
                                response)
                                self.tcpClientSocket.send(response.encode())
                            else:
                                hashed_password = hash_password(message[3])
                                db.create_room(message[1],message[2],hashed_password,self.username)
                                response = "create-chat-room-success"
                                logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " +
                                response)
                                self.tcpClientSocket.send(response.encode())
                    elif message[0] == "DELETE_ROOM":
                            # CREATE-exist is sent to peer,
                            # if a room with this username already exists
                            if not db.is_room_exist(message[1],message[2]):
                                response = "chat-room-not-exist"
                                logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                                self.tcpClientSocket.send(response.encode())
                            else:
                                roomdetails = db.get_room(message[1],message[2]) 
                                if check_password(roomdetails["password"],message[3]):
                                    if roomdetails["Admin"] == self.username:
                                        db.delete_room(message[1],message[2],self.username)
                                        print("Room deleted:")
                                        print("IP address: " + self.ip)
                                        print("Port number: " + str(self.port))
                                        print("\nListening for incoming connections...\n")
                                        response = "chat-room-deleted-success"
                                    else:
                                        response = "chat-room-not-admin"
                                else:
                                    response = "chat-room-wrong-password"
                                logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                                self.tcpClientSocket.send(response.encode())
                    elif message[0] == "JOIN-ROOM":
                                if db.is_room_exist(message[1],message[2]):
                                    isMember =  db.is_user_in_room(message[1],message[2],self.username)
                                    if not isMember:
                                        room = db.get_room(message[1],message[2])
                                        peers = room["peers"]
                                        peers.append({"username": self.username, "online": False})
                                        peers = [dict(t) for t in set(tuple(d.items()) for d in peers)]
                                        # updates the room in the database
                                        db.update_room(message[1], message[2], peers)
                                        # db.join_room(message[1],message[2],self.username)
                                        response = "join-room-success" 
                                        logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " +
                                        response)
                                        self.tcpClientSocket.send(response.encode())
                                    else:
                                        response = "room-already-joined" 
                                        logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " +
                                        response)
                                        self.tcpClientSocket.send(response.encode())
                                else:
                                    response = "join-room-fail"
                                    logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " +
                                    response)
                                    self.tcpClientSocket.send(response.encode())
                    
                    elif message[0] == "ENTER_ROOM":
                        if not db.is_room_exist(message[1],message[2]):
                            response = "chat-room-not-exist"
                            logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                            self.tcpClientSocket.send(response.encode())
                        else:
                            isMember =  db.is_user_in_room(message[1],message[2],self.username)
                            if isMember:
                                room = db.enter_room(message[1],message[2],self.username)
                                response = "chat-room-valid" 
                                logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " +
                                response)
                                self.tcpClientSocket.send(response.encode())
                            else:
                                response = "chat-room-invalid" 
                                logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " +
                                response)
                                self.tcpClientSocket.send(response.encode())
                            

                    elif message[0] == "ROOM_MEMBERS":
                                roomMembers = db.get_users_in_room(message[1],message[2],self.username)
                                if roomMembers:
                                    response = str(roomMembers)
                                    logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                                    self.tcpClientSocket.send(response.encode())
                                else:
                                    response = "chat-room-empty"
                                    logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                                    self.tcpClientSocket.send(response.encode())

                    
                    elif message[0] == "ROOM_MEMBERS_ONLINE":
                                roomMembers = db.get_users_entered_room(message[1],message[2],self.username)
                                if roomMembers:
                                    response = str(roomMembers)
                                    logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                                    self.tcpClientSocket.send(response.encode())
                                else:
                                    response = "chat-room-empty"
                                    logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                                    self.tcpClientSocket.send(response.encode())
                    
                    elif message[0] == "SHOW_JOINED_ROOMS":
                                myRooms =  db.show_rooms(self.username)
                                if myRooms:
                                    response = str(myRooms)
                                    logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                                    self.tcpClientSocket.send(response.encode())
                                else:
                                    response = "no-rooms-joined"
                                    logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                                    self.tcpClientSocket.send(response.encode())

                    elif message[0] == "EXIT_ROOM":
                        db.exit_room(message[1],message[2],self.username)

                    elif message[0] == "LEAVE_ROOM":
                        if not db.is_room_exist(message[1], message[2]):
                            response = "leave-room-fail"
                            logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                            self.tcpClientSocket.send(response.encode())
                        else:
                            isMember =  db.is_user_in_room(message[1],message[2],self.username)
                            if isMember:
                                db.leave_room(message[1], message[2], self.username)
                                response = "leave-room-success"
                                logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                                self.tcpClientSocket.send(response.encode())
                            else:
                                response = "leave-room-invalid" 
                                logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " +
                                response)
                                self.tcpClientSocket.send(response.encode())
                    elif message[0] == "GET_ROOMS_LIST":
                            chat_rooms = db.get_available_rooms()
                            # for room in chat_rooms:
                            #         print(type(room['roomName']), type(room['roomId']))
                            if chat_rooms:
                                response = "CHAT_ROOMS " + ' '.join([f"{room['roomName']}-{room['roomId']}" for room in chat_rooms])
                                self.tcpClientSocket.send(response.encode())
                                logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                            else: 
                                response = "NO_CHAT_ROOMS_Available"
                                self.tcpClientSocket.send(response.encode())
                                logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
 
            except OSError as oErr:
                logging.error("OSError: {0}".format(oErr)) 


    # function for resettin the timeout for the udp timer thread
    def resetTimeout(self):
        self.udpServer.resetTimer()

                            
# implementation of the udp server thread for clients
class UDPServer(threading.Thread):


    # udp server thread initializations
    def __init__(self, username, clientSocket):
        threading.Thread.__init__(self)
        self.username = username
        # timer thread for the udp server is initialized
        self.timer = threading.Timer(3, self.waitHelloMessage)
        self.tcpClientSocket = clientSocket
    

    # if hello message is not received before timeout
    # then peer is disconnected
    def waitHelloMessage(self):
        if self.username is not None:
            db.user_logout(self.username)
            if self.username in tcpThreads:
                del tcpThreads[self.username]
        self.tcpClientSocket.close()
        print(Fore.RED+"Removed " + self.username + " from online peers")

    # resets the timer for udp server
    def resetTimer(self):
        self.timer.cancel()
        self.timer = threading.Timer(3, self.waitHelloMessage)
        self.timer.start()


# tcp and udp server port initializations
print(Fore.GREEN+"Registy started...")
port = 15600
portUDP = 15500

# db initialization
db = db.DB()

# gets the ip address of this peer
# first checks to get it for windows devices
# if the device that runs this application is not windows
# it checks to get it for macos devices
hostname=gethostname()
try:
    host=gethostbyname(hostname)
except gaierror:
    import netifaces as ni
    host = ni.ifaddresses('en0')[ni.AF_INET][0]['addr']


print(Fore.MAGENTA+"Registry IP address: " + host)
print(Fore.MAGENTA+"Registry port number: " + str(port))

# onlinePeers list for online account
onlinePeers = {}
# accounts list for accounts
accounts = {}
# tcpThreads list for online client's thread
tcpThreads = {}

#tcp and udp socket initializations
tcpSocket = socket(AF_INET, SOCK_STREAM)
udpSocket = socket(AF_INET, SOCK_DGRAM)
tcpSocket.bind((host,port))
udpSocket.bind((host,portUDP))
tcpSocket.listen(5)

# input sockets that are listened
inputs = [tcpSocket, udpSocket]

# log file initialization
logging.basicConfig(filename="registry.log", level=logging.INFO)

# as long as at least a socket exists to listen registry runs
while inputs:

    print(Fore.MAGENTA+"Listening for incoming connections...")
    # monitors for the incoming connections
    readable, writable, exceptional = select.select(inputs, [], [])
    for s in readable:
        # if the message received comes to the tcp socket
        # the connection is accepted and a thread is created for it, and that thread is started
        if s is tcpSocket:
            tcpClientSocket, addr = tcpSocket.accept()
            newThread = ClientThread(addr[0], addr[1], tcpClientSocket)
            newThread.start()
        # if the message received comes to the udp socket
        elif s is udpSocket:
            # received the incoming udp message and parses it
            message, clientAddress = s.recvfrom(1024)
            message = message.decode().split()
            # checks if it is a hello message
            if message[0] == "HELLO":
                # checks if the account that this hello message 
                # is sent from is online
                if message[1] in tcpThreads:
                    # resets the timeout for that peer since the hello message is received
                    tcpThreads[message[1]].resetTimeout()
                    print(Fore.GREEN+"Hello is received from " + message[1])
                    logging.info("Received from " + clientAddress[0] + ":" + str(clientAddress[1]) + " -> " + " ".join(message))
                    
# registry tcp socket is closed
tcpSocket.close()

