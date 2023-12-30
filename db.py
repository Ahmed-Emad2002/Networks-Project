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

    # def get_room(self, roomId, roomName):
    # # Find the room with the specified roomId and roomName
    #     room = self.db.rooms.find_one({"roomId": roomId, "roomName": roomName})
    #     # If no such room exists, return None
    #     if room is None:
    #         return None
    #     # Otherwise, return the room
    #     return room
    
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
    
    # def leave_room(self, roomId, roomName, peer):
    #     # Find the room with the specified roomId and roomName
    #     room = self.db.rooms.find_one({"roomId": roomId, "roomName": roomName})
        
    #     # If no such room exists, return an error
    #     if room is None:
    #         return "Room not found."
        
    #     # Remove the peer from the room's peers
    #     peers = room["peers"]
    #     if peer in peers:
    #         peers.remove(peer)
        
    #     # Update the room in the database
    #     self.db.rooms.update_one({"roomId": roomId, "roomName": roomName}, {"$set": {"peers": peers}})
        
    #     return "Successfully left the room."



    # def leave_chat_room(self, room_name, username):
    #     # Check if the chat room exists
    #     chat_room = self.db.chat_rooms.find_one({"room_name": room_name})
    #     if chat_room:
    #         # Remove the user from the participants list
    #         self.db.chat_rooms.update_one(
    #             {"room_name": room_name},
    #             {"$pull": {"participants": username}}
    #         )
