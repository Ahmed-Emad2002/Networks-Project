from pymongo import MongoClient

# Includes database operations
class DB:


    # db initializations
    def __init__(self):
        self.client = MongoClient('mongodb://localhost:27017/')
        self.db = self.client['p2p-chat']
      

    # checks if an account with the username exists
    def is_account_exist(self, username):
        return self.db.accounts.find_one({'username': username})

    

    # registers a user
    def register(self, username, password):
        account = {
            "username": username,
            "password": password
        }
        self.db.accounts.insert_one(account)


    # retrieves the password for a given username
    def get_password(self, username):
        user = self.db.accounts.find_one({"username": username})
        if user:
            return user["password"]
        else:
            return None


    # checks if an account with the username online
    def is_account_online(self, username):
        return self.db.online_peers.count_documents({"username": username}) > 0


    
    # logs in the user
    def user_login(self, username, ip, port):
        online_peer = {
            "username": username,
            "ip": ip,
            "port": port
        }
        self.db.online_peers.insert_one(online_peer)
    

    # logs out the user 
    def user_logout(self, username):
        self.db.online_peers.delete_many({"username": username})
    

    # retrieves the ip address and the port number of the username
    def get_peer_ip_port(self, username):
        res = self.db.online_peers.find_one({"username": username})
        return (res["ip"], res["port"])
    
    #retrieves the list of online peers
    def get_online_peers(self):
        online_peers = self.db.online_peers.find()
        return [peer['username'] for peer in online_peers]
    
    def is_room_exist(self, roomId, roomName):
        return bool (self.db.rooms.find_one({"roomId": roomId, "roomName": roomName}))

    def create_room(self, roomId, roomName,password,username):
        # Check if the roomId and roomName already exist in the database
        if self.db.rooms.find_one({"roomId": roomId, "roomName": roomName}):
            raise ValueError(f"Room with id {roomId} and name {roomName} already exists.")
        
        room = {
            "roomId": roomId,
            "roomName": roomName,
            "password": password,
            "Admin": username,
            "peers": [{"username": username, "online": False}]
        }
        
        # Store the room information in the database
        self.db.rooms.insert_one(room)

    def delete_room(self,roomId,roomName,username):
        self.db.rooms.delete_one({"roomId": roomId, "roomName": roomName, "Admin": username})
        self.db.messages.delete_many({"roomId": roomId, "roomName": roomName})

    def get_users_in_room(self, roomId,roomName, current_username):
        room = self.db.rooms.find_one({"roomId": roomId, "roomName": roomName}, {"_id": 0, "peers": 1})
        users_in_room = [user["username"] for user in room["peers"] if user["username"] != current_username]
        return users_in_room if users_in_room else None
    
    def get_users_entered_room(self, roomId, roomName, current_username):
        room = self.db.rooms.find_one({"roomId": roomId, "roomName": roomName}, {"_id": 0, "peers": 1})
        users_in_room = [user["username"] for user in room["peers"] if user["online"] and user["username"] != current_username]
        return users_in_room if users_in_room else None

    
    def is_user_in_room(self,roomId,roomName,username):
        room = self.db.rooms.find_one({"roomId": roomId, "roomName": roomName}, {"_id": 0, "peers": 1})
        return any(peer["username"] == username for peer in room["peers"])
    
    def show_rooms(self, username):
        cursor = self.db.rooms.find({"peers.username": username}, {"_id": 0, "roomId": 1, "roomName": 1})
        rooms = [{"roomId": doc["roomId"], "roomName": doc["roomName"]} for doc in cursor]
        return rooms if rooms else None
    
    def enter_room(self, roomId,roomName, username):
        self.db.rooms.update_one({"roomId": roomId, "roomName": roomName, "peers.username": username}, {"$set": {"peers.$.online": True}})

    def exit_room(self, roomId,roomName, username):
        self.db.rooms.update_one({"roomId": roomId, "roomName": roomName, "peers.username": username}, {"$set": {"peers.$.online": False}})

    def is_user_in_any_room(self, username):
        # Get all rooms
        rooms = self.db.rooms.find()

        for room in rooms:
            # Get all peers in the current room
            peers = room['peers']  # Adjust this line based on your room document structure

            # Check if the user is in the current room
            for peer in peers:
                if peer['username'] == username:
                    return True
        # If the user is not in any room
        return False
    
    def leave_room(self, roomId, roomName, username):        
        # Remove the user from the room
        self.db.rooms.update_one(
            {"roomId": roomId, "roomName": roomName},
            {"$pull": {"peers": {"username": username}}}
        )

    def get_room(self, roomId, roomName):
        return self.db.rooms.find_one({"roomId": roomId ,"roomName": roomName}, {'_id': 0, "password": 1, "Admin": 1, "peers" : 1} )

    def update_room(self, roomId, roomName, peers):
        projection = {"roomId": roomId, "roomName": roomName}
        update_data = {
            "$set": {"peers": peers}
        }
        self.db.rooms.update_one(projection, update_data)


    def get_available_rooms(self):
        projection = {'roomId': 1, 'roomName': 1, '_id': 0}
        rooms = list(self.db.rooms.find({}, projection))
        return [{'roomId': str(room['roomId']), 'roomName': str(room['roomName'])} for room in rooms]
    
    def create_message(self, roomId, roomName, username, message, timestamp):
        # Create a message document
        message_doc = {
            "roomId": roomId,
            "roomName": roomName,
            "username": username,
            "message": message,
            "timestamp": timestamp,  # Add a timestamp
            "readBy": [username]  # Add a list of users who have read the message
        }
        
        # Store the message document in the messages collection and get its ID
        return self.db.messages.insert_one(message_doc).inserted_id
    
    def get_messages_in_room(self, roomId, roomName):
        # Find all messages for the given room
        messages = self.db.messages.find({"roomId": roomId, "roomName": roomName})
        
        # Convert the messages to a list and return it
        return list(messages)


    def get_all_unread_messages(self, username):
        # Get the list of rooms the user is in
        rooms = self.show_rooms(username)
        
        # Find all unread messages for the user in those rooms
        unread_messages = self.db.messages.find(
            {"roomId": {"$in": [room["roomId"] for room in rooms]}, "roomName": {"$in": [room["roomName"] for room in rooms]}, "readBy": {"$ne": username}}
        )
        
        # Convert the messages to a list and return it
        return [message for message in unread_messages]

    def mark_message_as_read(self, messageId, username):
        # Add the user to the readBy field of the message
        self.db.messages.update_one(
            {"_id": messageId},
            {"$addToSet": {"readBy": username}}
        )

    
  