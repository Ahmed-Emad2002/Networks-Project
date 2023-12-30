from socket import *
import threading
import time
import select
import logging
from colorama import Fore
import pwinput
import re
import os
import datetime
import ast
os.system("set LESS='-R'")

# Server side of peer
class PeerServer(threading.Thread):

    # Peer server initialization
    def __init__(self, username, peerServerPort):
        threading.Thread.__init__(self)
        # keeps the username of the peer
        self.username = username
        # tcp socket for peer server
        self.tcpServerSocket = socket(AF_INET, SOCK_STREAM)
        # port number of the peer server
        self.peerServerPort = peerServerPort
        # if 1, then user is already chatting with someone
        # if 0, then user is not chatting with anyone
        self.isChatRequested = 0
        self.isRoomRequested = 0
        # keeps the socket for the peer that is connected to this peer
        self.connectedPeerSocket = None
        # keeps the ip of the peer that is connected to this peer's server
        self.connectedPeerIP = None
        # keeps the port number of the peer that is connected to this peer's server
        self.connectedPeerPort = None
        # online status of the peer
        self.isOnline = True
        # keeps the username of the peer that this peer is chatting with
        self.chattingClientName = None

    # main method of the peer server thread
    def run(self):

        print("Peer server started...")

        # gets the ip address of this peer
        # first checks to get it for Windows devices
        # if the device that runs this application is not windows
        # it checks to get it for macOS devices
        hostname = gethostname()
        try:
            self.peerServerHostname = gethostbyname(hostname)
        except gaierror:
            import netifaces as ni
            self.peerServerHostname = ni.ifaddresses('en0')[ni.AF_INET][0]['addr']
        print(self.peerServerHostname)
        print(self.peerServerPort)
        # ip address of this peer
        # self.peerServerHostname = 'localhost'
        # socket initializations for the server of the peer
        self.tcpServerSocket.bind((self.peerServerHostname, self.peerServerPort))
        self.tcpServerSocket.listen(4)
        # inputs sockets that should be listened
        inputs = [self.tcpServerSocket]
        # server listens as long as there is a socket to listen in the inputs list and the user is online
        while inputs and self.isOnline:
            # monitors for the incoming connections
            try:
                readable, writable, exceptional = select.select(inputs, [], [])
                # If a server waits to be connected enters here
                for s in readable:
                    # if the socket that is receiving the connection is 
                    # the tcp socket of the peer's server, enters here
                    if s is self.tcpServerSocket:
                        # accepts the connection, and adds its connection socket to the inputs list
                        # so that we can monitor that socket as well
                        connected, addr = s.accept()
                        connected.setblocking(0)
                        inputs.append(connected)
                        # if the user is not chatting, then the ip and the socket of
                        # this peer is assigned to server variables
                        if self.isChatRequested == 0:
                            print(self.username + " is connected from " + str(addr))
                            self.connectedPeerSocket = connected
                            self.connectedPeerIP = addr[0]
                    # if the socket that receives the data is the one that
                    # is used to communicate with a connected peer, then enters here
                    else:
                        # message is received from connected peer
                        messageReceived = s.recv(1024).decode()
                        # logs the received message
                        logging.info("Received from " + str(self.connectedPeerIP) + " -> " + str(messageReceived))
                        # if message is a request message it means that this is the receiver side peer server
                        # so evaluate the chat request
                        if self.isRoomRequested:
                            message = messageReceived.split()
                            self.chattingClientName = message[0]
                            messageReceived = " ".join(message[1:])
                            if messageReceived == ":q":
                                print(Fore.LIGHTRED_EX+self.chattingClientName + " left the chat")
                            else:
                                print(self.chattingClientName + ": " + messageReceived)
                            inputs.clear()
                            inputs.append(self.tcpServerSocket)
                        
                        elif len(messageReceived) > 11 and messageReceived[:12] == "CHAT-REQUEST":
                            # text for proper input choices is printed however OK or REJECT is taken as input in main
                            # process of the peer if the socket that we received the data belongs to the peer that we
                            # are chatting with, enters here
                            if s is self.connectedPeerSocket:
                                # parses the message
                                messageReceived = messageReceived.split()
                                # gets the port of the peer that sends the chat request message
                                self.connectedPeerPort = int(messageReceived[1])
                                # gets the username of the peer sends the chat request message
                                self.chattingClientName = messageReceived[2]
                                # prints prompt for the incoming chat request
                                print("Incoming chat request from " + self.chattingClientName + " >> ")
                                print("Enter OK to accept or REJECT to reject:  ")
                                # makes isChatRequested = 1 which means that peer is chatting with someone
                                self.isChatRequested = 1
                            # if the socket that we received the data does not belong to the peer that we are
                            # chatting with and if the user is already chatting with someone else(isChatRequested =
                            # 1), then enters here
                            elif s is not self.connectedPeerSocket and self.isChatRequested == 1:
                                # sends a busy message to the peer that sends a chat request when this peer is 
                                # already chatting with someone else
                                message = "BUSY"
                                s.send(message.encode())
                                # remove the peer from the inputs list so that it will not monitor this socket
                                inputs.remove(s)
                        # if an OK message is received then ischatrequested is made 1 and then next messages will be
                        # shown to the peer of this server
                        elif messageReceived == "OK":
                            self.isChatRequested = 1
                        # if an REJECT message is received then ischatrequested is made 0 so that it can receive any
                        # other chat requests
                        elif messageReceived == "REJECT":
                            self.isChatRequested = 0
                            inputs.remove(s)
                        # if a message is received, and if this is not a quit message ':q' and 
                        # if it is not an empty message, show this message to the user
                        elif messageReceived[:2] != ":q" and len(messageReceived) != 0:
                            print(self.chattingClientName + ": " + messageReceived)
                        # if the message received is a quit message ':q',
                        # makes ischatrequested 1 to receive new incoming request messages
                        # removes the socket of the connected peer from the inputs list
                        elif messageReceived[:2] == ":q":
                            self.isChatRequested = 0
                            inputs.clear()
                            inputs.append(self.tcpServerSocket)
                            # connected peer ended the chat
                            if len(messageReceived) == 2:
                                print("User you're chatting with ended the chat")
                                print("Press enter to quit the chat: ")
                        # if the message is an empty one, then it means that the
                        # connected user suddenly ended the chat(an error occurred)
                        elif len(messageReceived) == 0:
                            self.isChatRequested = 0
                            inputs.clear()
                            inputs.append(self.tcpServerSocket)
                            print("User you're chatting with suddenly ended the chat")
                            print("Press enter to quit the chat: ")


            # handles the exceptions, and logs them
            except OSError as oErr:
                logging.error("OSError: {0}".format(oErr))
            except ValueError as vErr:
                logging.error("ValueError: {0}".format(vErr))


# Client side of peer
class PeerClient(threading.Thread):
    # variable initializations for the client side of the peer
    def __init__(self, ipToConnect, portToConnect, username, peerServer, responseReceived):
        threading.Thread.__init__(self)
        # keeps the ip address of the peer that this will connect
        self.ipToConnect = ipToConnect
        # keeps the username of the peer
        self.username = username
        # keeps the port number that this client should connect
        self.portToConnect = portToConnect
        # client side tcp socket initialization
        self.tcpClientSocket = socket(AF_INET, SOCK_STREAM)
        # keeps the server of this client
        self.peerServer = peerServer
        # keeps the phrase that is used when creating the client
        # if the client is created with a phrase, it means this one received the request
        # this phrase should be none if this is the client of the requester peer
        self.responseReceived = responseReceived
        # keeps if this client is ending the chat or not
        self.isEndingChat = False

    # main method of the peer client thread

    def run(self):
        print(Fore.LIGHTGREEN_EX + "Peer client started...")
        # connects to the server of other peer
        self.tcpClientSocket.connect((self.ipToConnect, self.portToConnect))
        # if the server of this peer is not connected by someone else and if this is the requester side peer client
        # then enters here
        if self.peerServer.isChatRequested == 0 and self.responseReceived is None:
            # composes a request message and this is sent to server and then this waits a response message from the
            # server this client connects
            requestMessage = "CHAT-REQUEST " + str(self.peerServer.peerServerPort) + " " + self.username
            # logs the chat request sent to other peer
            logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + requestMessage)
            # sends the chat request
            self.tcpClientSocket.send(requestMessage.encode())
            print("Request message " + requestMessage + " is sent...")
            # received a response from the peer which the request message is sent to
            self.responseReceived = self.tcpClientSocket.recv(1024).decode()
            # logs the received message
            logging.info(
                "Received from " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + self.responseReceived)
            print("Response is " + self.responseReceived)
            # parses the response for the chat request
            self.responseReceived = self.responseReceived.split()
            # if response is ok then incoming messages will be evaluated as client messages and will be sent to the
            # connected server
            if self.responseReceived[0] == "OK":
                # changes the status of this client's server to chatting
                self.peerServer.isChatRequested = 1
                # sets the server variable with the username of the peer that this one is chatting
                self.peerServer.chattingClientName = self.responseReceived[1]
                # as long as the server status is chatting, this client can send messages
                while self.peerServer.isChatRequested == 1:
                    # message input prompt
                    messageSent = input(self.username + ": ")
                    # sends the message to the connected peer, and logs it
                    self.tcpClientSocket.send(messageSent.encode())
                    logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + messageSent)
                    # if the quit message is sent, then the server status is changed to not chatting
                    # and this is the side that is ending the chat
                    if messageSent == ":q":
                        self.peerServer.isChatRequested = 0
                        self.isEndingChat = True
                        break
                # if peer is not chatting, checks if this is not the ending side
                if self.peerServer.isChatRequested == 0:
                    if not self.isEndingChat:
                        # tries to send a quit message to the connected peer
                        # logs the message and handles the exception
                        try:
                            self.tcpClientSocket.send(":q ending-side".encode())
                            logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> :q")
                        except BrokenPipeError as bpErr:
                            logging.error("BrokenPipeError: {0}".format(bpErr))
                    # closes the socket
                    self.responseReceived = None
                    self.tcpClientSocket.close()
            # if the request is rejected, then changes the server status, sends a reject message to the connected
            # peer's server logs the message and then the socket is closed
            elif self.responseReceived[0] == "REJECT":
                self.peerServer.isChatRequested = 0
                print("client of requester is closing...")
                self.tcpClientSocket.send("REJECT".encode())
                logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> REJECT")
                self.tcpClientSocket.close()
            # if a busy response is received, closes the socket
            elif self.responseReceived[0] == "BUSY":
                print("Receiver peer is busy")
                self.tcpClientSocket.close()
        # if the client is created with OK message it means that this is the client of receiver side peer, so it sends
        # an OK message to the requesting side peer server that it connects and then waits for the user inputs.
        elif self.responseReceived == "OK":
            # server status is changed
            self.peerServer.isChatRequested = 1
            # ok response is sent to the requester side
            okMessage = "OK"
            self.tcpClientSocket.send(okMessage.encode())
            logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + okMessage)
            print("Client with OK message is created... and sending messages")
            # client can send messages as long as the server status is chatting
            while self.peerServer.isChatRequested == 1:
                # input prompt for user to enter message
                messageSent = input(self.username + ": ")
                self.tcpClientSocket.send(messageSent.encode())
                logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + messageSent)
                # if a quit message is sent, server status is changed
                if messageSent == ":q":
                    self.peerServer.isChatRequested = 0
                    self.isEndingChat = True
                    break
            # if server is not chatting, and if this is not the ending side
            # sends a quitting message to the server of the other peer
            # then closes the socket
            if self.peerServer.isChatRequested == 0:
                if not self.isEndingChat:
                    self.tcpClientSocket.send(":q ending-side".encode())
                    logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> :q")
                self.responseReceived = None
                self.tcpClientSocket.close()
            

                

# main process of the peer
class peerMain:

    # peer initializations
    def __init__(self):
        while True:
            # ip address of the registry
            # self.registryName = input(Fore.LIGHTYELLOW_EX+"Enter IP address of registry: ")
            self.registryName = gethostbyname(gethostname())
            # port number of the registry
            self.registryPort = 15600
            # tcp socket connection to registry
            self.tcpClientSocket = socket(AF_INET, SOCK_STREAM)
            try:
                self.tcpClientSocket.connect((self.registryName,self.registryPort))
                break
            except Exception as e:
                print(Fore.RED + "Error Connecting to the registry")
        # initializes udp socket which is used to send hello messages

        self.udpClientSocket = socket(AF_INET, SOCK_DGRAM)
        # udp port of the registry
        self.registryUDPPort = 15500
        # login info of the peer
        self.loginCredentials = (None, None)
        #account creation status of the peer
        self.account_created = None
        #login status of the peer
        self.logged_in = None
        # online status of the peer
        self.isOnline = False
        # server port number of this peer
        self.peerServerPort = None
        # server of this peer
        self.peerServer = None
        # client of this peer
        self.peerClient = None
        # timer initialization
        self.timer = None
        
        choice = "0"
        # log file initialization
        logging.basicConfig(filename="peer.log", level=logging.INFO)
        # as long as the user is not logged out, asks to select an option in the menu
                # as long as the user is not logged out, asks to select an option in the menu
        self.logged_in = False
        self.account_created = False
        # logout = False
        while True:
            if (not self.logged_in) and (not self.account_created):
                # menu selection 
                print(Fore.LIGHTBLUE_EX, end='')
                print(f"Welcome to our Chatting Program!\n{Fore.LIGHTBLUE_EX}Choose from the following options, Write the number corresponding to your choice: \n1. Create account\n2. Login\n",end='')
                print(f"Type {Fore.RED}'Exit'{Fore.LIGHTBLUE_EX} to exit from the program.")
                print(Fore.LIGHTBLACK_EX, end='')
                choice = input()
                # if choice is 1, creates an account with the username
                # and password entered by the user
                if choice == "1":
                    self.create_account()
                # if choice is 2 and user is not logged in, asks for the username
                # and the password to login
                elif choice == "2" and self.isOnline:
                    print(Fore.RED + "You are already logged in!")
                elif choice == "2" and not self.isOnline:
                    self.user_login()
                elif choice == "Exit":
                    print(Fore.RESET, end='')
                    break
                else:
                    print(Fore.RED + "You have entered a wrong input!")

            elif self.logged_in:

                print(Fore.LIGHTYELLOW_EX, end='')
                print("Choose: \n1. Logout\n2. Search\n3. Start a chat\n4. Show Online Users\n5. Create a chatting room\n6. List of available rooms.\n7. Join an existing room.\n8. Delete a room\n9. Enter a room\n", end='')
                print(Fore.LIGHTYELLOW_EX, end='')
                choice = input()
                # if choice is 1 and user is logged in, then user is logged out
                # and peer variables are set, and server and client sockets are closed
                if choice == "1" and self.isOnline:
                    self.user_logout()
                    self.isOnline = False
                    self.logged_in = False
                # is peer is not logged in and exits the program
                elif choice == "1":
                    self.logout(2)
                    self.logged_in = False
                    print(Fore.RESET, end='')

                # if choice is 2 and user is online, then user is asked
                # for a username that is wanted to be searched
                elif choice == "2" and self.isOnline:
                    self.user_search()
                elif choice == "2" and not self.isOnline:
                    print(Fore.RED + "You must log in first to search for users!")
                # if choice is 3 and user is online, then user is asked
                # to enter the username of the user that is wanted to be chatted
                elif choice == "3" and self.isOnline:
                    self.start_chat()
                elif choice == "3" and not self.isOnline:
                    print(Fore.RED + "You must log in first to start a chat!")
                # if choice is 4 and user is online, then user views the list of the online users
                elif choice == "4" and self.isOnline:
                    self.Get_online_users()
                elif choice == "4" and not self.isOnline:
                    print(Fore.RED + "You must log in first to get the list of online users!")
                elif choice == "5" and self.isOnline:
                    self.user_createRoom()
                elif choice == "5" and not self.isOnline:
                    print(Fore.RED + "You must log in first to create a chat room!")
                elif choice == "6" and self.isOnline:
                    self.rooms_List()
                elif choice == "6" and not self.isOnline:
                    print(Fore.RED + "You must log in first to get the list of available rooms!")
                elif choice == "7" and self.isOnline:
                    self.user_joinRoom()
                elif choice == "8" and self.isOnline:
                    self.deleteRoom()
                elif choice == "9" and self.isOnline:
                    self.user_enterRoom()
                     
                                
                # if this is the receiver side then it will get the prompt to accept an incoming request during the
                # main loop that's why response is evaluated in main process not the server thread even though the
                # prompt is printed by server if the response is ok then a client is created for this peer with the
                # OK message and that's why it will directly send an OK message to the requesting side peer server
                # and waits for the user input main process waits for the client thread to finish its chat
                elif choice == "OK" and self.isOnline:
                    self.user_ok()
                # if user rejects the chat request then reject message is sent to the requester side
                elif choice == "REJECT" and self.isOnline:
                    self.user_reject()
                # if choice is cancel timer for hello message is cancelled
                elif choice == "CANCEL":
                    self.user_cancel()
                    break
                else:
                    print(Fore.RED + "Wrong input!")

            elif self.account_created:
                self.user_login()

    @staticmethod
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


    def create_account(self):
        print(Fore.LIGHTYELLOW_EX + "username: ", end='')
        print(Fore.LIGHTBLACK_EX, end='')
        username = input('')
        password_is_valid = False
        while not password_is_valid:
            print(Fore.LIGHTYELLOW_EX + "password: ", end='')
            print(Fore.LIGHTBLACK_EX, end='')
            password = pwinput.pwinput(prompt='')
            password_is_valid, message = self.is_password_valid(password)
            if not password_is_valid:
                 print(Fore.RED + message + "Enter your password again please.")
        confirm = False
        while not confirm:
            print(Fore.LIGHTYELLOW_EX + "confirm password: ", end='')
            print(Fore.LIGHTBLACK_EX, end='')
            confirm_password = pwinput.pwinput(prompt='')
            if confirm_password == password:
                confirm = True
            else:
                print(Fore.RED + "passwords doesn't match!\nEnter your password again please.")
        self.createAccount(username, password)
    # account creation function
    def createAccount(self, username, password):
    # join message to create an account is composed and sent to registry
    # if response is success then informs the user for account creation
    # if response is existed then informs the user for account existence
        # hashed_Password = self.hash_password(password)
        message = "JOIN " + username + " " + password
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + response)
        if response == "join-success":
            print(Fore.LIGHTGREEN_EX + "Account created...")
            self.account_created = True
            print(Fore.LIGHTYELLOW_EX + "Login:")
        elif response == "join-exist":
            print(Fore.RED + "This username is taken. Choose another username")

    def user_login(self):
        print(Fore.LIGHTYELLOW_EX + "username: ", end='')
        print(Fore.LIGHTYELLOW_EX, end='')
        username = input('')
        print(Fore.LIGHTYELLOW_EX + "password: ", end='')
        print(Fore.LIGHTYELLOW_EX, end='')
        password = pwinput.pwinput(prompt='')
        print(Fore.LIGHTYELLOW_EX + "Choose port number for Peer Server, Port Range: 1024 - 49151")
        print(Fore.LIGHTYELLOW_EX + "Enter a port number for peer server: ", end='')
        print(Fore.LIGHTYELLOW_EX, end='')
        # asks for the port number for server's tcp socket
        peerServerPort = int(input(""))
        while(peerServerPort< 1024 or peerServerPort > 49151):
            print(Fore.RED+"Please enter a valid Peer server port within the range 1024 - 49151.")
            print(Fore.RED, end='')
            peerServerPort = int(input(""))
        print(peerServerPort)
        status = self.login(username, password, peerServerPort)
        # is user logs in successfully, peer variables are set
        if status == 1:
            self.isOnline = True
            self.loginCredentials = (username, password)
            self.peerServerPort = peerServerPort
            # creates the server thread for this peer, and runs it
            self.peerServer = PeerServer(self.loginCredentials[0], self.peerServerPort)
            self.peerServer.start()
            # hello message is sent to registry
            self.sendHelloMessage()
            self.logged_in = True
            self.account_created = False

    # login function
    def login(self, username, password, peerServerPort):
        # a login message is composed and sent to registry
        # an integer is returned according to each response
        # hashed_Password = self.hash_password(password)
        message = "LOGIN " + username + " " + password + " " + str(peerServerPort)
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + response)
        if response == "login-success":
            print(Fore.LIGHTGREEN_EX + "Logged in successfully...")
            return 1
        elif response == "login-account-not-exist":
            print(Fore.RED + "Account does not exist...")
            return 0
        elif response == "login-online":
            print(Fore.RED + "Account is already online...")
            return 2
        elif response == "login-wrong-password":
            print(Fore.RED + "Wrong password...")
            return 3
    
    # logout function
    def logout(self, option):
        # a logout message is composed and sent to registry
        # timer is stopped
        if option == 1:
            message = "LOGOUT " + self.loginCredentials[0]
            self.timer.cancel()
        else:
            message = "LOGOUT"
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        
    def cancel(self):
        # a logout message is composed and sent to registry
        # timer is stopped
        message = "CANCEL " + self.loginCredentials[0]
        self.timer.cancel()
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())

    def user_search(self):
        print(Fore.LIGHTYELLOW_EX + "Username to be searched: ")
        print(Fore.LIGHTBLACK_EX)
        username = input('')
        if self.loginCredentials[0] == username:
            print(Fore.RED + "You can't search yourself!")
            return
        searchStatus = self.searchUser(username)
        # if user is found its ip address is shown to user
        if searchStatus is not None and searchStatus != 0:
            print(Fore.LIGHTGREEN_EX + username + " is found successfully...")
            print(Fore.LIGHTGREEN_EX + "IP address of " + username + " is " + searchStatus)
        elif searchStatus == 0:
             print(Fore.RED + username + " is not online...", end='')
        elif searchStatus == None:
             print(Fore.RED + username + " is not found", end='')

    # function for searching an online user
    def searchUser(self, username):
        # a search message is composed and sent to registry
        # custom value is returned according to each response
        # to this search message
        message = "SEARCH " + username
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode().split()
        logging.info("Received from " + self.registryName + " -> " + " ".join(response))
        if response[0] == "search-success":
            return response[1]
        elif response[0] == "search-user-not-online":
            return 0
        elif response[0] == "search-user-not-found":
            return None
        
    def start_chat(self):
        print(Fore.LIGHTYELLOW_EX + "Enter the username of user to start chat: ", end='')
        print(Fore.LIGHTBLACK_EX)
        username = input('')
        if self.loginCredentials[0] == username:
            print(Fore.RED + "You can't start a chat with yourself!")
            return
        searchStatus = self.searchUser(username)
        # if searched user is found, then its ip address and port number is retrieved
        # and a client thread is created
        # main process waits for the client thread to finish its chat
        if searchStatus is not None and searchStatus != 0:
            searchStatus = searchStatus.split(":")
            self.peerClient = PeerClient(searchStatus[0], int(searchStatus[1]), self.loginCredentials[0],self.peerServer, None)
            self.peerClient.start()
            self.peerClient.join()
    
    def Get_online_users(self):
        try:
            request_message = "GET_ONLINE_USERS"
            self.tcpClientSocket.send(request_message.encode())
            # Receive the response from the registry
            response = self.tcpClientSocket.recv(1024).decode()
            if response.startswith("ONLINE_USERS"):
                # Extract the online users from the response and display them
                online_users = response.split()[1:]
                print(Fore.LIGHTGREEN_EX + "Online Users:")
                for user in online_users:
                    print(user)
            else:
                print(Fore.RED + "No online users are available.")

        except ConnectionError as e:
            print(f"Connection error: {e}")
        except Exception as ex:
            print(f"An error occurred: {ex}")

    def user_logout(self):
        self.logout(1)
        self.isOnline = False
        self.loginCredentials = (None, None)
        self.peerServer.isOnline = False
        self.peerServer.tcpServerSocket.close()
        if self.peerClient is not None:
            self.peerClient.tcpClientSocket.close()
        print(Fore.LIGHTGREEN_EX + "Logged out successfully")
        print(Fore.RESET, end='')
        peerMain()

    def user_cancel(self):
        self.cancel()
        self.isOnline = False
        self.loginCredentials = (None, None)
        self.peerServer.isOnline = False
        self.peerServer.tcpServerSocket.close()
        if self.peerClient is not None:
            self.peerClient.tcpClientSocket.close()
        print(Fore.LIGHTGREEN_EX + "See you next time!")
        print(Fore.RESET, end='')

    def rooms_List(self):
        message = "GET_ROOMS_LIST "
        logging.info("Send to " + self.registryName + ":" +str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + " ".join(response))
        if response.startswith("CHAT_ROOMS"):
            available_rooms = response.split()[1:]
            print(Fore.LIGHTGREEN_EX + "Available rooms:")
            for room in available_rooms:
                print(room)
        else:
                print(Fore.RED + "No rooms are available.")

    def user_createRoom(self):
        print(Fore.LIGHTYELLOW_EX + "Enter Name of room to be created: ", end='')
        print(Fore.LIGHTBLACK_EX)
        roomName = input('')
        print(Fore.LIGHTYELLOW_EX + "Enter Id of room to be created: ", end='')
        print(Fore.LIGHTBLACK_EX)
        roomID = input('')
        print(Fore.LIGHTYELLOW_EX + "password: ", end='')
        print(Fore.LIGHTYELLOW_EX, end='')
        password = pwinput.pwinput(prompt='')
        self.createRoom(roomID,roomName,password)


    def createRoom(self,roomID,roomName,password):
        message = "CREATE_ROOM " + roomID + " " + roomName + " " + password
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + response)
        if response == "create-chat-room-success":
            print(Fore.LIGHTGREEN_EX+"Chat room created successfully.")
        elif response == "chat-room-exists":
            print(Fore.RED+"Chat room exists with the same name and id")

    def user_deleteRoom(self):
        print(Fore.LIGHTYELLOW_EX + "Enter Name of room to be deleted: ", end='')
        print(Fore.LIGHTBLACK_EX)
        roomName = input('')
        print(Fore.LIGHTYELLOW_EX + "Enter Id of room to be deleted: ", end='')
        print(Fore.LIGHTBLACK_EX)
        roomID = input('')
        print(Fore.LIGHTYELLOW_EX + "password: ", end='')
        print(Fore.LIGHTYELLOW_EX, end='')
        password = pwinput.pwinput(prompt='')
        self.deleteRoom(roomID,roomName,password)

    def deleteRoom (self,roomID,roomName,password):
        message = "DELETE_ROOM " + roomID + " " + roomName + " " +password
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + response)
        if response == "chat-room-deleted-success":
            print(Fore.LIGHTGREEN_EX + "Room Deleted Sucessfully")
        elif response == "chat-room-not-exist":
            print(Fore.RED + "Room doesn't exist")
        elif response == "chat-room-wrong-password":
            print(Fore.RED + "Incorrect Room password")
        elif response == "chat-room-not-admin":
            print(Fore.RED + "You can't delete the room because you aren't the admin")

    def user_joinRoom(self):
        print(Fore.LIGHTYELLOW_EX + "Name of room that you want to join: ", end='')
        print(Fore.LIGHTBLACK_EX)
        roomName = input('')
        print(Fore.LIGHTYELLOW_EX + "Id of room that you want to join: ", end='')
        print(Fore.LIGHTBLACK_EX)
        roomID = input('')
        self.joinRoom(roomName,roomID)

    def joinRoom(self,roomName,roomID):
        message = "JOIN-ROOM " + roomID + " " + roomName 
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + " ".join(response))
        if response == "join-room-success":
            print(Fore.LIGHTGREEN_EX+"Chat Room joined sucessfully")
        elif response == "join-room-fail":
            print(Fore.RED+"Chat Room doesn't exist")
        elif response == "room-already-joined":
            print(Fore.RED+"You have already joined the room")

    def user_enterRoom(self):
        if(self.showJoinedRooms()):
            print(Fore.LIGHTYELLOW_EX + "Name of room that you want to join: ", end='')
            print(Fore.LIGHTBLACK_EX)
            roomName = input('')
            print(Fore.LIGHTYELLOW_EX + "Id of room that you want to join: ", end='')
            print(Fore.LIGHTBLACK_EX)
            roomID = input('')
            self.enterRoom(roomID,roomName)
        else:
            print(Fore.RED+"You haven't joined any room yet.")
        

    def enterRoom(self,roomID,roomName):
        message = "ENTER_ROOM " + roomID + " " + roomName
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + " ".join(response))
        if response == "chat-room-valid":
            members = self.roomMembers(roomName,roomID)
            if members:
                roomMembers = ast.literal_eval(members)
                print("Room Members")
                for member in roomMembers:
                    print(Fore.LIGHTMAGENTA_EX+member)
                print("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ")
                self.sendRoomMessage(roomName,roomID)
        elif response == "chat-room-invalid":
            print(Fore.RED + "You must join the room first")
        elif response == "chat-room-not-exist":
            print(Fore.RED + "Room does not exist...")

    def roomMembers(self,roomName,roomID):
        message = "ROOM_MEMBERS " + roomID + " " + roomName
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        if response == "chat-room-empty":
            print(Fore.RED+"Chat Room has no members")
            return 0
        else:
            return response
        
    def onlineRoomMembers(self,roomName,roomID):
        message = "ROOM_MEMBERS_ONLINE " + roomID + " " + roomName
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + " ".join(response))
        if response == "chat-room-empty":
            print(Fore.RED+"Chat Room has no online members\n", end='')
            return 0
        else:
            return response
        
    def showJoinedRooms(self):
        message = "SHOW_JOINED_ROOMS"
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + " ".join(response))
        if response == "no-rooms-joined":
            print(Fore.RED+"You didn't join any room yet", end='')
            return 0
        else:
            Rooms = ast.literal_eval(response)
            print("Joined Rooms:")
            for index, room in enumerate(Rooms, start=1):
                print(Fore.LIGHTMAGENTA_EX + f"{index}: {room['roomName']} - {room['roomId']}")
            return 1
        

    def sendRoomMessage(self, roomname, roomId):
        print("Chat:\n\n")
        self.peerServer.isRoomRequested = 1
        self.peerServer.isChatRequested = 1
        members = self.onlineRoomMembers(roomname,roomId)
        if members:
            roomMembers = ast.literal_eval(members)
            for member in roomMembers:
                roomMembers = ast.literal_eval(members)
                print("Online Room Members")
                for member in roomMembers:
                    print(Fore.LIGHTMAGENTA_EX+member)
                cred = self.searchUser (member)
                if cred != 0 and cred != None:
                    memberCred = cred.split(':')
                    ip = memberCred[0]
                    port = memberCred[1]
                    msgSocket = socket(AF_INET,SOCK_STREAM)
                    msgSocket.connect((ip, int(port)))
                    username = self.loginCredentials[0].split(':')[0]
                    print(Fore.LIGHTBLUE_EX)
                    message = "      " + username + " " + "Joined the room!"
                    msgSocket.send(message.encode())
                    msgSocket.close()
        while 1:
            print(Fore.LIGHTCYAN_EX)
            msg = input()
            members = self.onlineRoomMembers(roomname,roomId)
            if members:
                roomMembers = ast.literal_eval(members)
                for member in roomMembers:
                    cred = self.searchUser (member)
                    if cred != 0 and cred != None:
                        memberCred = cred.split(':')
                        ip = memberCred[0]
                        port = memberCred[1]
                        msgSocket = socket(AF_INET,SOCK_STREAM)
                        msgSocket.connect((ip, int(port)))
                        message = self.loginCredentials[0] + " " + msg
                        msgSocket.send(message.encode())
                        msgSocket.close()
            
            if msg == ":q":
                self.exitRoom(roomname,roomId)
                self.peerServer.isRoomRequested = 0
                self.peerServer.isChatRequested = 0
                break

    def exitRoom(self,roomname,roomid):
        message = "EXIT_ROOM " + roomid + " " + roomname
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        print(Fore.LIGHTMAGENTA_EX+"You have quit the room.")


    # function for sending hello message
    # a timer thread is used to send hello messages to udp socket of registry
    def sendHelloMessage(self):
        message = "HELLO " + self.loginCredentials[0]
        logging.info("Send to " + self.registryName + ":" + str(self.registryUDPPort) + " -> " + message)
        self.udpClientSocket.sendto(message.encode(), (self.registryName, self.registryUDPPort))
        self.timer = threading.Timer(1, self.sendHelloMessage)
        self.timer.start()

    def user_ok(self):
        okMessage = "OK " + self.loginCredentials[0]
        logging.info("Send to " + self.peerServer.connectedPeerIP + " -> " + okMessage)
        self.peerServer.connectedPeerSocket.send(okMessage.encode())
        self.peerClient = PeerClient(self.peerServer.connectedPeerIP, self.peerServer.connectedPeerPort,
                                        self.loginCredentials[0], self.peerServer, "OK")
        self.peerClient.start()
        self.peerClient.join()

    def user_reject(self):
        self.peerServer.connectedPeerSocket.send("REJECT".encode())
        self.peerServer.isChatRequested = 0
        logging.info("Send to " + self.peerServer.connectedPeerIP + " -> REJECT")

# peer is started
main = peerMain()