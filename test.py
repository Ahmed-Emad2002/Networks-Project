import io
import itertools
import socket
import sys
import pytest
from peer import peerMain  
from peer import PeerClient
import unittest
from unittest.mock import Mock, patch, MagicMock

# def test_password_length():
#     assert peerMain.is_password_valid('12345678')[0] == False

# def test_password_digit():
#     assert peerMain.is_password_valid('abcdefghi')[0] == False

# def test_password_uppercase():
#     assert peerMain.is_password_valid('abcdefghi1')[0] == False

# def test_password_special_char():
#     assert peerMain.is_password_valid('Abcdefghi1')[0] == False

# def test_password_lowercase():
#     assert peerMain.is_password_valid('ABCDEFGHI1!')[0] == False

# def test_password_valid():
#     assert peerMain.is_password_valid('Abcdefghi1!')[0] == True

class TestPeerMain(unittest.TestCase):

    def test_valid_password(self):
        password = "ValidPassword123!"
        is_valid, message = peerMain.is_password_valid(password)
        self.assertTrue(is_valid)
        self.assertEqual(message, "Password is valid.")

    def test_short_password(self):
        password = "Short1!"
        is_valid, message = peerMain.is_password_valid(password)
        self.assertFalse(is_valid)
        self.assertIn("Password is not long enough!", message)

    def test_password_without_digit(self):
        password = "PasswordWithoutDigit!"
        is_valid, message = peerMain.is_password_valid(password)
        self.assertFalse(is_valid)
        self.assertIn("Password must contain a number!", message)

    def test_password_without_uppercase(self):
        password = "passwordwithoutuppercase1!"
        is_valid, message = peerMain.is_password_valid(password)
        self.assertFalse(is_valid)
        self.assertIn("Password must contain a capital letter!", message)

    def test_password_without_special_character(self):
        password = "PasswordWithoutSpecialCharacter1"
        is_valid, message = peerMain.is_password_valid(password)
        self.assertFalse(is_valid)
        self.assertIn("Password must contain a special character!", message)

    def test_password_without_lowercase(self):
        password = "PASSWORDWITHOUTLOWERCASE1!"
        is_valid, message = peerMain.is_password_valid(password)
        self.assertFalse(is_valid)
        self.assertIn("Password must contain a lowercase letter!", message)

    @patch('pwinput.pwinput', side_effect=itertools.repeat('Password-1'))
    @patch('builtins.input', return_value='username1')
    def test_create_account_success(self, mock_input, mock_pwinput):
        # Arrange
        peer = peerMain()
        peer.tcpClientSocket = MagicMock()
        peer.tcpClientSocket.recv.return_value = b'join-success'
        capturedOutput = io.StringIO()          # Create StringIO object
        sys.stdout = capturedOutput             # Redirect stdout.

        # Act
        peer.create_account()

        # Assert
        sys.stdout = sys.__stdout__             # Reset redirect.
        self.assertEqual(mock_input.call_count, 1)
        self.assertEqual(mock_pwinput.call_count, 2)
        self.assertTrue("Account created..." in capturedOutput.getvalue())  # assert the printed output

    @patch('pwinput.pwinput', side_effect=itertools.repeat('Password-1'))
    @patch('builtins.input', return_value='username1')
    def test_create_account_exist(self, mock_input, mock_pwinput):
        # Arrange
        peer = peerMain()
        peer.tcpClientSocket = MagicMock()
        peer.tcpClientSocket.recv.return_value = b'join-exist'
        capturedOutput = io.StringIO()          # Create StringIO object
        sys.stdout = capturedOutput             # Redirect stdout.

        # Act
        peer.create_account()

        # Assert
        sys.stdout = sys.__stdout__             # Reset redirect.
        self.assertEqual(mock_input.call_count, 1)
        self.assertEqual(mock_pwinput.call_count, 2)
        self.assertTrue("This username is taken. Choose another username" in capturedOutput.getvalue())  # assert the printed output

    def setUp(self):
        self.peer = peerMain()
        self.mock_socket = MagicMock()
        self.peer.tcpClientSocket = self.mock_socket
        #self.peer.tcpClientSocket = MagicMock()

    def test_login_success(self):
        # Arrange
        self.peer.tcpClientSocket.recv.return_value = b'login-success'
        capturedOutput = io.StringIO()          # Create StringIO object
        sys.stdout = capturedOutput             # Redirect stdout.

        # Act
        result = self.peer.login('username1', 'Password-1', 12345)

        # Assert
        sys.stdout = sys.__stdout__             # Reset redirect.
        self.assertEqual(result, 1)
        self.assertTrue("Logged in successfully..." in capturedOutput.getvalue())  # assert the printed output

    def test_login_account_not_exist(self):
        # Arrange
        self.peer.tcpClientSocket.recv.return_value = b'login-account-not-exist'
        capturedOutput = io.StringIO()          # Create StringIO object
        sys.stdout = capturedOutput             # Redirect stdout.

        # Act
        result = self.peer.login('username1', 'Password-1', 12345)

        # Assert
        sys.stdout = sys.__stdout__             # Reset redirect.
        self.assertEqual(result, 0)
        self.assertTrue("Account does not exist..." in capturedOutput.getvalue())  # assert the printed output

    def test_logout_option_1(self):
        # Arrange
        self.peer.loginCredentials = ['username1', 'Password-1']
        self.peer.timer = MagicMock()
        new_socket_instance = MagicMock()  # Create a second mock object for the new socket instance
        self.peer.tcpClientSocket.connect.side_effect = [None, new_socket_instance]  # Set the side effect of connect
        # Act
        self.peer.logout(1)

        # Print method calls
        # print(self.mock_socket.mock_calls)

        # Assert
        self.mock_socket.send.assert_called_once_with("LOGOUT username1".encode())
        # self.assertEqual(self.peer.tcpClientSocket.send.call_count, 1)

    def test_logout_option_other(self):
        # Arrange
        self.peer.loginCredentials = ['username1', 'Password-1']
        new_socket_instance = MagicMock()  # Create a second mock object for the new socket instance
        self.peer.tcpClientSocket.connect.side_effect = [None, new_socket_instance]  # Set the side effect of connect

        # Act
        self.peer.logout(0)

        # Assert
        self.mock_socket.send.assert_called_once_with("LOGOUT".encode())

    def test_user_search_self(self):
        with patch('builtins.input', return_value='username1') as mock_input:
            # Arrange
            self.peer.loginCredentials = ['username1', 'Password-1']
            capturedOutput = io.StringIO()          # Create StringIO object
            sys.stdout = capturedOutput             # Redirect stdout.

            # Act
            self.peer.user_search()

            # Assert
            sys.stdout = sys.__stdout__             # Reset redirect.
            self.assertTrue("You can't search yourself!" in capturedOutput.getvalue())

    def test_user_search_not_found(self):
        with patch('builtins.input', return_value='username2') as mock_input:
            # Arrange
            self.peer.loginCredentials = ['username1', 'Password-1']
            self.mock_socket.recv.return_value = b'search-user-not-found'
            capturedOutput = io.StringIO()          # Create StringIO object
            sys.stdout = capturedOutput             # Redirect stdout.

            # Act
            self.peer.user_search()

            # Assert
            sys.stdout = sys.__stdout__             # Reset redirect.
            self.mock_socket.send.assert_called_once_with("SEARCH username2".encode())
            self.assertTrue("username2 is not found" in capturedOutput.getvalue())

    def test_user_search_not_online(self):
        with patch('builtins.input', return_value='username2') as mock_input:
            # Arrange
            self.peer.loginCredentials = ['username1', 'Password-1']
            self.mock_socket.recv.return_value = b'search-user-not-online'
            capturedOutput = io.StringIO()          # Create StringIO object
            sys.stdout = capturedOutput             # Redirect stdout.

            # Act
            self.peer.user_search()

            # Assert
            sys.stdout = sys.__stdout__             # Reset redirect.
            self.mock_socket.send.assert_called_once_with("SEARCH username2".encode())
            self.assertTrue("username2 is not online..." in capturedOutput.getvalue())

    def test_user_search_found(self):
        with patch('builtins.input', return_value='username2') as mock_input:
            # Arrange
            self.peer.loginCredentials = ['username1', 'Password-1']
            self.mock_socket.recv.return_value = b'search-success 192.168.1.1'
            capturedOutput = io.StringIO()          # Create StringIO object
            sys.stdout = capturedOutput             # Redirect stdout.

            # Act
            self.peer.user_search()

            # Assert
            sys.stdout = sys.__stdout__             # Reset redirect.
            self.mock_socket.send.assert_called_once_with("SEARCH username2".encode())
            self.assertTrue("username2 is found successfully..." in capturedOutput.getvalue())
            self.assertTrue("IP address of username2 is 192.168.1.1" in capturedOutput.getvalue())

    def test_start_chat_self(self):
        with patch('builtins.input', return_value='username1') as mock_input:
            # Arrange
            self.peer.loginCredentials = ['username1', 'Password-1']
            capturedOutput = io.StringIO()          # Create StringIO object
            sys.stdout = capturedOutput             # Redirect stdout.

            # Act
            self.peer.start_chat()

            # Assert
            sys.stdout = sys.__stdout__             # Reset redirect.
            self.assertTrue("You can't start a chat with yourself!" in capturedOutput.getvalue())

    def test_start_chat_not_found(self):
        with patch('builtins.input', return_value='username2') as mock_input:
            # Arrange
            self.peer.loginCredentials = ['username1', 'Password-1']
            self.mock_socket.recv.return_value = b'search-user-not-found'
            capturedOutput = io.StringIO()          # Create StringIO object
            sys.stdout = capturedOutput             # Redirect stdout.

            # Act
            self.peer.start_chat()

            # Assert
            sys.stdout = sys.__stdout__             # Reset redirect.
            self.mock_socket.send.assert_called_once_with("SEARCH username2".encode())

    def test_start_chat_found(self):
        with patch('builtins.input', return_value='username2') as mock_input:
            # Arrange
            self.peer.loginCredentials = ['username1', 'Password-1']
            self.mock_socket.recv.return_value = b'search-success 192.168.1.1:12345'
            capturedOutput = io.StringIO()          # Create StringIO object
            sys.stdout = capturedOutput             # Redirect stdout.
            with patch.object(PeerClient, 'start') as mock_start, patch.object(PeerClient, 'join') as mock_join:
                # Act
                self.peer.start_chat()
                # Assert
                self.mock_socket.send.assert_called_once_with("SEARCH username2".encode())
                self.assertTrue(mock_start.called)
                self.assertTrue(mock_join.called)

    
    def test_Get_online_users_found(self):
        # Arrange
        self.mock_socket.recv.return_value = b'ONLINE_USERS username2 username3'
        capturedOutput = io.StringIO()          # Create StringIO object
        sys.stdout = capturedOutput             # Redirect stdout.

        # Act
        self.peer.Get_online_users()

        # Assert
        sys.stdout = sys.__stdout__             # Reset redirect.
        self.mock_socket.send.assert_called_once_with("GET_ONLINE_USERS".encode())
        self.assertTrue("Online Users:" in capturedOutput.getvalue())
        self.assertTrue("username2" in capturedOutput.getvalue())
        self.assertTrue("username3" in capturedOutput.getvalue())

    def test_Get_online_users_not_found(self):
        # Arrange
        self.mock_socket.recv.return_value = b'No online users are available.'
        capturedOutput = io.StringIO()          # Create StringIO object
        sys.stdout = capturedOutput             # Redirect stdout.

        # Act
        self.peer.Get_online_users()

        # Assert
        sys.stdout = sys.__stdout__             # Reset redirect.
        self.mock_socket.send.assert_called_once_with("GET_ONLINE_USERS".encode())
        self.assertTrue("No online users are available." in capturedOutput.getvalue())

    
    def test_rooms_List_found(self):
        # Arrange
        self.mock_socket.recv.return_value = b'CHAT_ROOMS room1 room2'
        capturedOutput = io.StringIO()          # Create StringIO object
        sys.stdout = capturedOutput             # Redirect stdout.

        # Act
        self.peer.rooms_List()

        # Assert
        sys.stdout = sys.__stdout__             # Reset redirect.
        self.mock_socket.send.assert_called_once_with("GET_ROOMS_LIST ".encode())
        self.assertTrue("Available rooms:" in capturedOutput.getvalue())
        self.assertTrue("room1" in capturedOutput.getvalue())
        self.assertTrue("room2" in capturedOutput.getvalue())

    def test_rooms_List_not_found(self):
        # Arrange
        self.mock_socket.recv.return_value = b'No rooms are available.'
        capturedOutput = io.StringIO()          # Create StringIO object
        sys.stdout = capturedOutput             # Redirect stdout.

        # Act
        self.peer.rooms_List()

        # Assert
        sys.stdout = sys.__stdout__             # Reset redirect.
        self.mock_socket.send.assert_called_once_with("GET_ROOMS_LIST ".encode())
        self.assertTrue("No rooms are available." in capturedOutput.getvalue())

    def test_user_createRoom_success(self):
        with patch('pwinput.pwinput', return_value='password'), \
            patch('builtins.input', side_effect=['roomName', 'roomID']), \
            patch.object(self.peer.tcpClientSocket, 'recv', return_value=b'create-chat-room-success'):

            # Arrange
            capturedOutput = io.StringIO()
            sys.stdout = capturedOutput

            # Act
            self.peer.user_createRoom()

            # Assert
            sys.stdout = sys.__stdout__             # Reset redirect.
            assert "Chat room created successfully." in capturedOutput.getvalue()

    def test_user_createRoom_exists(self):
        with patch('pwinput.pwinput', return_value='password'), \
            patch('builtins.input', side_effect=['roomName', 'roomID']), \
            patch.object(self.peer.tcpClientSocket, 'recv', return_value=b'chat-room-exists'):

            # Arrange
            capturedOutput = io.StringIO()
            sys.stdout = capturedOutput

            # Act
            self.peer.user_createRoom()

            # Assert
            sys.stdout = sys.__stdout__             # Reset redirect.
            assert "Chat room exists with the same name and id" in capturedOutput.getvalue()

    def test_user_deleteRoom_success(self):
        with patch('pwinput.pwinput', return_value='password'), \
            patch('builtins.input', side_effect=['roomName', 'roomID']), \
            patch.object(self.peer.tcpClientSocket, 'recv', return_value=b'chat-room-deleted-success'):

            # Arrange
            capturedOutput = io.StringIO()
            sys.stdout = capturedOutput

            # Act
            self.peer.user_deleteRoom()

            # Assert
            sys.stdout = sys.__stdout__             # Reset redirect.
            assert "Room Deleted Successfully" in capturedOutput.getvalue()

    def test_user_deleteRoom_not_exist(self):
        with patch('pwinput.pwinput', return_value='password'), \
            patch('builtins.input', side_effect=['roomName', 'roomID']), \
            patch.object(self.peer.tcpClientSocket, 'recv', return_value=b'chat-room-not-exist'):

            # Arrange
            capturedOutput = io.StringIO()
            sys.stdout = capturedOutput

            # Act
            self.peer.user_deleteRoom()

            # Assert
            sys.stdout = sys.__stdout__             # Reset redirect.            
            assert "Room doesn't exist" in capturedOutput.getvalue()

    def test_user_deleteRoom_wrong_password(self):
        with patch('pwinput.pwinput', return_value='password'), \
            patch('builtins.input', side_effect=['roomName', 'roomID']), \
            patch.object(self.peer.tcpClientSocket, 'recv', return_value=b'chat-room-wrong-password'):

            # Arrange
            capturedOutput = io.StringIO()
            sys.stdout = capturedOutput

            # Act
            self.peer.user_deleteRoom()

            # Assert
            sys.stdout = sys.__stdout__             # Reset redirect.
            assert "Incorrect Room password" in capturedOutput.getvalue()

    def test_user_deleteRoom_not_admin(self):
        with patch('pwinput.pwinput', return_value='password'), \
            patch('builtins.input', side_effect=['roomName', 'roomID']), \
            patch.object(self.peer.tcpClientSocket, 'recv', return_value=b'chat-room-not-admin'):

            # Arrange
            capturedOutput = io.StringIO()
            sys.stdout = capturedOutput

            # Act
            self.peer.user_deleteRoom()
            # Assert
            sys.stdout = sys.__stdout__             # Reset redirect.
            assert "You can't delete the room because you aren't the admin" in capturedOutput.getvalue()

    def test_user_joinRoom_success(self):
        with patch('builtins.input', side_effect=['roomName', 'roomID']), \
            patch.object(self.peer.tcpClientSocket, 'recv', return_value=b'join-room-success'):
            capturedOutput = io.StringIO()
            sys.stdout = capturedOutput
            self.peer.user_joinRoom()
            sys.stdout = sys.__stdout__
            assert "Chat Room joined successfully" in capturedOutput.getvalue()

    def test_user_joinRoom_not_exist(self):
        with patch('builtins.input', side_effect=['roomName', 'roomID']), \
            patch.object(self.peer.tcpClientSocket, 'recv', return_value=b'join-room-fail'):
            capturedOutput = io.StringIO()
            sys.stdout = capturedOutput
            self.peer.user_joinRoom()
            sys.stdout = sys.__stdout__
            assert "Chat Room doesn't exist" in capturedOutput.getvalue()

    def test_user_joinRoom_already_joined(self):
        with patch('builtins.input', side_effect=['roomName', 'roomID']), \
            patch.object(self.peer.tcpClientSocket, 'recv', return_value=b'room-already-joined'):
            capturedOutput = io.StringIO()
            sys.stdout = capturedOutput
            self.peer.user_joinRoom()
            sys.stdout = sys.__stdout__
            assert "You have already joined the room" in capturedOutput.getvalue()

    def test_user_enterRoom(self):
        with patch.object(peerMain, 'showJoinedRooms', return_value=True), \
            patch.object(self.peer, 'enterRoom') as mock_enterRoom, \
            patch('builtins.input', side_effect=['TestRoom', '12345']):
            # Arrange
            self.peer.enterRoom = mock_enterRoom
            capturedOutput = io.StringIO()
            sys.stdout = capturedOutput

            # Act
            self.peer.user_enterRoom()

            # Assert
            mock_enterRoom.assert_called_once()

    def test_enterRoom_valid(self):
        # Arrange
        roomID = '12345'
        roomName = 'TestRoom'
        self.peer.tcpClientSocket.recv.return_value = b'chat-room-valid'
        self.peer.roomMembers = MagicMock(return_value='["member1", "member2"]')
        self.peer.onlineRoomMembers = MagicMock(return_value='["member1"]')
        self.peer.sendRoomMessage = MagicMock()

        # Act
        self.peer.enterRoom(roomID, roomName)

        # Assert
        self.mock_socket.send.assert_called_once_with('ENTER_ROOM 12345 TestRoom'.encode())
        self.peer.sendRoomMessage.assert_called_once_with(roomName, roomID)

    def test_enterRoom_invalid(self):
        # Arrange
        roomID = '12345'
        roomName = 'TestRoom'
        self.peer.tcpClientSocket.recv.return_value = b'chat-room-invalid'

        # Act
        capturedOutput = io.StringIO()
        sys.stdout = capturedOutput
        self.peer.enterRoom(roomID, roomName)

        # Assert
        self.mock_socket.send.assert_called_once_with('ENTER_ROOM 12345 TestRoom'.encode())

    def test_enterRoom_not_exist(self):
        # Arrange
        roomID = '12345'
        roomName = 'TestRoom'
        self.peer.tcpClientSocket.recv.return_value = b'chat-room-not-exist'

        # Act
        self.peer.enterRoom(roomID, roomName)
        capturedOutput = io.StringIO()
        sys.stdout = capturedOutput

        # Assert
        self.mock_socket.send.assert_called_once_with('ENTER_ROOM 12345 TestRoom'.encode())


    def test_roomMembers_empty(self):
        with patch.object(self.peer.tcpClientSocket, 'recv', return_value=b'chat-room-empty'):
            capturedOutput = io.StringIO()
            sys.stdout = capturedOutput
            result = self.peer.roomMembers('roomName', 'roomID')
            sys.stdout = sys.__stdout__
            assert "Chat Room has no members" in capturedOutput.getvalue()
            assert result == 0

    def test_roomMembers_not_empty(self):
        with patch.object(self.peer.tcpClientSocket, 'recv', return_value=b'user1 user2 user3'):
            result = self.peer.roomMembers('roomName', 'roomID')
            assert result == 'user1 user2 user3'


    def test_onlineRoomMembers_empty(self):
        with patch.object(self.peer.tcpClientSocket, 'recv', return_value=b'chat-room-empty'):
            result = self.peer.onlineRoomMembers('roomName', 'roomID')
            assert result == 0

    def test_onlineRoomMembers_not_empty(self):
        with patch.object(self.peer.tcpClientSocket, 'recv', return_value=b'user1 user2'):
            result = self.peer.onlineRoomMembers('roomName', 'roomID')
            assert result == 'user1 user2'

    def test_showJoinedRooms_no_rooms_joined(self):
        with patch.object(self.peer.tcpClientSocket, 'recv', return_value=b'no-rooms-joined'):
            capturedOutput = io.StringIO()
            sys.stdout = capturedOutput
            result = self.peer.showJoinedRooms()
            sys.stdout = sys.__stdout__
            assert "You didn't join any room yet" in capturedOutput.getvalue()
            assert result == 0
    
    def test_showJoinedRooms_rooms_joined(self):
        with patch.object(self.peer.tcpClientSocket, 'recv', return_value=b"[{'roomName': 'room1', 'roomId': 'id1'}, {'roomName': 'room2', 'roomId': 'id2'}]"):
            capturedOutput = io.StringIO()
            sys.stdout = capturedOutput
            result = self.peer.showJoinedRooms()
            sys.stdout = sys.__stdout__
            assert "1: room1 - id1" in capturedOutput.getvalue()
            assert "2: room2 - id2" in capturedOutput.getvalue()
            assert result == 1

    def test_exitRoom(self):
        with patch.object(self.peer.tcpClientSocket, 'send') as mock_send:
            capturedOutput = io.StringIO()
            sys.stdout = capturedOutput
            self.peer.exitRoom('roomName', 'roomID')
            sys.stdout = sys.__stdout__
            mock_send.assert_called_once_with("EXIT_ROOM roomID roomName".encode())
            assert "You have quit the room." in capturedOutput.getvalue()

    #with patch.object(peerMain, 'onlineRoomMembers', return_value='["member1", "member2"]'), \
    # def test_sendRoomMessage(self):
    #     with patch.object(peerMain, 'onlineRoomMembers', return_value=None), \
    #         patch.object(peerMain, 'searchUser', return_value='192.168.1.1:12345'), \
    #         patch.object(peerMain, 'exitRoom') as mock_exitRoom, \
    #         patch('builtins.input', return_value=':q'), \
    #         patch('socket.socket', side_effect=lambda *args, **kwargs: MagicMock()):  # Return a new MagicMock for each socket
    #         # Arrange
    #         roomID = '12345'
    #         roomName = 'TestRoom'
    #         self.peer.loginCredentials = ['username1', 'Password-1']
    #         self.peer.peerServer = MagicMock()  # Mock the peerServer attribute

    #         # Mock the socket's connect method
    #         self.mock_socket.connect = MagicMock()

    #         # Act
    #         capturedOutput = io.StringIO()
    #         sys.stdout = capturedOutput
    #         self.peer.sendRoomMessage(roomName, roomID)

    #         # Assert
    #         mock_exitRoom.assert_called_once()
    #         # self.mock_socket.connect.assert_called()
    #         # self.mock_socket.send.assert_called()
            
    def test_sendHelloMessage(self):
        # Arrange
        self.peer.loginCredentials = ['username1', 'Password-1']
        mock_socket = MagicMock()
        self.peer.udpClientSocket = mock_socket

        # Act
        self.peer.sendHelloMessage()

        # Let the sendHelloMessage run for some time
        # time.sleep(2)
        # Stop the timer
        self.peer.timer.cancel()

        # Assert
        mock_socket.sendto.assert_called_with("HELLO username1".encode(), (self.peer.registryName, self.peer.registryUDPPort))

    def test_user_ok(self):
        # Arrange
        self.peer.loginCredentials = ['username1', 'Password-1']
        self.peer.peerServer = MagicMock()  # Initialize peerServer
        self.peer.peerServer.connectedPeerSocket = MagicMock()
        self.peer.peerClient = MagicMock()

        # Mock the PeerClient constructor and its start and join methods
        with patch('peer.PeerClient', return_value=self.peer.peerClient):
            # Mock the send method of connectedPeerSocket
            with patch.object(self.peer.peerClient, 'start') as mock_start, patch.object(self.peer.peerClient, 'join') as mock_join:
                with patch.object(self.peer.peerServer.connectedPeerSocket, 'send') as mock_send:
                    # Act
                    self.peer.user_ok()
                    # Assert
                    mock_send.assert_called_once_with("OK username1".encode())
                    self.assertTrue(mock_start.called)
                    self.assertTrue(mock_join.called)

    def test_user_reject(self):
        # Arrange
        self.peer.peerServer = MagicMock()  # Initialize peerServer
        self.peer.peerServer.connectedPeerSocket = MagicMock()

        # Act
        self.peer.user_reject()

        # Assert
        self.peer.peerServer.connectedPeerSocket.send.assert_called_once_with("REJECT".encode())
        self.assertEqual(self.peer.peerServer.isChatRequested, 0)

    
    def test_bold_text(self):
        message = "*Hello, World!*"
        expected_output = '\033[1mHello, World!\033[0m'
        self.assertEqual(peerMain.format_message(message), expected_output)

    def test_italic_text(self):
        message = "_Hello, World!_"
        expected_output = '\033[3mHello, World!\033[0m'
        self.assertEqual(peerMain.format_message(message), expected_output)

    def test_bold_and_italic_text(self):
        message = "*Hello*, _World!_"
        expected_output = '\033[1mHello\033[0m, \033[3mWorld!\033[0m'
        self.assertEqual(peerMain.format_message(message), expected_output)

    def test_unmatched_asterisks(self):
        message = "*Hello, World!"
        expected_output = "*Hello, World!"  # Unmatched asterisks, text should not be bold
        self.assertEqual(peerMain.format_message(message), expected_output)

    def test_unmatched_underscores(self):
        message = "_Hello, World!"
        expected_output = "_Hello, World!"  # Unmatched underscores, text should not be italic
        self.assertEqual(peerMain.format_message(message), expected_output)

    def test_special_characters(self):
        message = "*Hello, World!* # This is a comment"
        expected_output = '\033[1mHello, World!\033[0m # This is a comment'
        self.assertEqual(peerMain.format_message(message), expected_output)

    def test_escape_sequences(self):
        message = "*Hello, \\*World!*"
        expected_output = '\033[1mHello, \\*World!\033[0m'  # Bold formatting should be applied
        self.assertEqual(peerMain.format_message(message), expected_output)






if __name__ == '__main__':
    unittest.main()
