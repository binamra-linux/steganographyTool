import argparse
import os
import binascii
import numpy as np
from PIL import Image
import mysql.connector
from getpass import getpass
import hashlib
import sys
from datetime import datetime

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',  # XAMPP default empty password
    'database': 'steganography_db'
}

class UserAuth:
    def __init__(self):
        self.db = None
        self.cursor = None
        self.setup_database()

    def setup_database(self):
        try:
            # First connect without database to create it if it doesn't exist
            temp_db = mysql.connector.connect(
                host=DB_CONFIG['host'],
                user=DB_CONFIG['user'],
                password=DB_CONFIG['password']
            )
            temp_cursor = temp_db.cursor()
            
            # Create database if it doesn't exist
            temp_cursor.execute("CREATE DATABASE IF NOT EXISTS steganography_db")
            temp_cursor.close()
            temp_db.close()

            # Connect to the database
            self.db = mysql.connector.connect(**DB_CONFIG)
            self.cursor = self.db.cursor()

            # Create users table if it doesn't exist
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password VARCHAR(256) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create message_history table if it doesn't exist
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS message_history (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    image_path VARCHAR(255) NOT NULL,
                    decoded_message TEXT NOT NULL,
                    decode_method VARCHAR(10) NOT NULL,
                    decoded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            
            self.db.commit()
        except mysql.connector.Error as err:
            print(f"Database Error: {err}")
            sys.exit(1)

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def register(self, username, password):
        try:
            hashed_password = self.hash_password(password)
            self.cursor.execute(
                "INSERT INTO users (username, password) VALUES (%s, %s)",
                (username, hashed_password)
            )
            self.db.commit()
            return True
        except mysql.connector.IntegrityError:
            print("Username already exists!")
            return False
        except mysql.connector.Error as err:
            print(f"Registration error: {err}")
            return False

    def login(self, username, password):
        try:
            hashed_password = self.hash_password(password)
            self.cursor.execute(
                "SELECT id, username FROM users WHERE username = %s AND password = %s",
                (username, hashed_password)
            )
            user = self.cursor.fetchone()
            return user
        except mysql.connector.Error as err:
            print(f"Login error: {err}")
            return None

    def log_decoded_message(self, user_id, image_path, decoded_message, decode_method):
        try:
            self.cursor.execute("""
                INSERT INTO message_history 
                (user_id, image_path, decoded_message, decode_method)
                VALUES (%s, %s, %s, %s)
            """, (user_id, image_path, decoded_message, decode_method))
            self.db.commit()
        except mysql.connector.Error as err:
            print(f"Error logging message: {err}")

    def get_user_history(self, username):
        try:
            self.cursor.execute("""
                SELECT m.image_path, m.decoded_message, m.decode_method, m.decoded_at
                FROM message_history m
                JOIN users u ON m.user_id = u.id
                WHERE u.username = %s
                ORDER BY m.decoded_at DESC
            """, (username,))
            return self.cursor.fetchall()
        except mysql.connector.Error as err:
            print(f"Error fetching history: {err}")
            return []

    def close(self):
        if self.cursor:
            self.cursor.close()
        if self.db:
            self.db.close()

class Steganography:
    def __init__(self):
        self.hex_delimiter = "##END##"
        self.start_marker = "##START##"

    def encode_image(self, input_image_path, secret_message, output_image_path, method="lsb"):
        if method.lower() == "lsb":
            self._encode_lsb(input_image_path, secret_message, output_image_path)
        elif method.lower() == "hex":
            self._encode_hex(input_image_path, secret_message, output_image_path)
        else:
            raise ValueError("Invalid method! Use 'lsb' or 'hex'")

    def _encode_lsb(self, input_image_path, secret_message, output_image_path):
        img = Image.open(input_image_path).convert('RGB')
        img_array = np.array(img)
        
        binary_message = ''.join(format(ord(char), '08b') for char in secret_message) + '1111111111111110'
        
        if len(binary_message) > img_array.size:
            raise ValueError("Message is too long for this image")
        
        data_index = 0
        modified_array = img_array.copy()
        
        for i in range(img_array.shape[0]):
            for j in range(img_array.shape[1]):
                for channel in range(3):
                    if data_index < len(binary_message):
                        modified_array[i, j, channel] = (img_array[i, j, channel] & 254) | int(binary_message[data_index])
                        data_index += 1
                    else:
                        break
                if data_index >= len(binary_message):
                    break
            if data_index >= len(binary_message):
                break
        
        encoded_img = Image.fromarray(modified_array)
        encoded_img.save(output_image_path, "PNG")

    def _encode_hex(self, input_image_path, secret_message, output_image_path):
        with open(input_image_path, 'rb') as f:
            content = f.read()
        
        hex_message = (self.start_marker + secret_message + self.hex_delimiter).encode('utf-8').hex()
        
        with open(output_image_path, 'wb') as f:
            f.write(content)
            f.write(bytes.fromhex(hex_message))

    def decode_image(self, encoded_image_path, method="lsb"):
        if method.lower() == "lsb":
            return self._decode_lsb(encoded_image_path)
        elif method.lower() == "hex":
            return self._decode_hex(encoded_image_path)
        else:
            raise ValueError("Invalid method! Use 'lsb' or 'hex'")

    def _decode_lsb(self, encoded_image_path):
        img = Image.open(encoded_image_path).convert('RGB')
        img_array = np.array(img)
        binary_message = ""

        for i in range(img_array.shape[0]):
            for j in range(img_array.shape[1]):
                for channel in range(3):
                    binary_message += str(img_array[i, j, channel] & 1)
                    if len(binary_message) >= 16 and binary_message[-16:] == '1111111111111110':
                        message_bits = binary_message[:-16]
                        return ''.join(chr(int(message_bits[i:i+8], 2)) for i in range(0, len(message_bits), 8))
        return "No hidden message found."

    def _decode_hex(self, encoded_image_path):
        with open(encoded_image_path, 'rb') as f:
            content = f.read()
        
        hex_content = content.hex()
        start_marker_hex = self.start_marker.encode('utf-8').hex()
        start_index = hex_content.find(start_marker_hex)
        if start_index == -1:
            return "No hidden message found."
        
        end_marker_hex = self.hex_delimiter.encode('utf-8').hex()
        end_index = hex_content.find(end_marker_hex, start_index)
        if end_index == -1:
            return "No hidden message found."
        
        hex_message = hex_content[start_index:end_index + len(end_marker_hex)]
        message = bytes.fromhex(hex_message).decode('utf-8')
        return message.replace(self.start_marker, "").replace(self.hex_delimiter, "")

def main():
    parser = argparse.ArgumentParser(description="Steganography CLI Tool with User Authentication")
    subparsers = parser.add_subparsers(dest="command")
    
    # Register parser
    register_parser = subparsers.add_parser("register", help="Register a new user")
    register_parser.add_argument("-u", "--username", required=True, help="Username")
    
    # Login parser
    login_parser = subparsers.add_parser("login", help="Login to use the tool")
    login_parser.add_argument("-u", "--username", required=True, help="Username")
    
    # History parser
    history_parser = subparsers.add_parser("history", help="View your message decode history")
    history_parser.add_argument("-u", "--username", required=True, help="Username")
    
    # Encode parser
    encode_parser = subparsers.add_parser("encode", help="Encode a message into an image")
    encode_parser.add_argument("-i", "--input", required=True, help="Input image file path")
    encode_parser.add_argument("-o", "--output", required=True, help="Output image file path")
    encode_parser.add_argument("-m", "--message", required=True, help="Message to encode")
    encode_parser.add_argument("-t", "--method", choices=["lsb", "hex"], default="lsb", help="Encoding method")
    encode_parser.add_argument("-u", "--username", required=True, help="Username")
    
    # Decode parser
    decode_parser = subparsers.add_parser("decode", help="Decode a message from an image")
    decode_parser.add_argument("-i", "--input", required=True, help="Encoded image file path")
    decode_parser.add_argument("-t", "--method", choices=["lsb", "hex"], default="lsb", help="Decoding method")
    decode_parser.add_argument("-u", "--username", required=True, help="Username")
    
    args = parser.parse_args()
    auth = UserAuth()
    
    try:
        if args.command == "register":
            password = getpass("Enter password: ")
            confirm_password = getpass("Confirm password: ")
            
            if password != confirm_password:
                print("Passwords do not match!")
                return
                
            if auth.register(args.username, password):
                print("Registration successful!")

        elif args.command == "history":
            password = getpass("Enter password: ")
            user = auth.login(args.username, password)
            if user:
                history = auth.get_user_history(args.username)
                if history:
                    print("\nYour decode history:")
                    print("-" * 80)
                    for entry in history:
                        image_path, message, method, timestamp = entry
                        print(f"Time: {timestamp}")
                        print(f"Image: {image_path}")
                        print(f"Method: {method}")
                        print(f"Message: {message}")
                        print("-" * 80)
                else:
                    print("No decode history found.")
            else:
                print("Invalid credentials!")
            
        elif args.command == "login":
            password = getpass("Enter password: ")
            if auth.login(args.username, password):
                print("Login successful!")
            else:
                print("Invalid credentials!")
                
        elif args.command in ["encode", "decode"]:
            password = getpass("Enter password: ")
            user = auth.login(args.username, password)
            if not user:
                print("Authentication failed!")
                return
                
            stego = Steganography()
            
            if args.command == "encode":
                try:
                    stego.encode_image(args.input, args.message, args.output, args.method)
                    print("Message successfully encoded!")
                except Exception as e:
                    print(f"Error: {e}")
                    
            elif args.command == "decode":
                try:
                    message = stego.decode_image(args.input, args.method)
                    print("Decoded Message:", message)
                    # Log the decoded message
                    if message != "No hidden message found.":
                        auth.log_decoded_message(
                            user[0],  # user_id
                            os.path.abspath(args.input),  # full path to image
                            message,
                            args.method
                        )
                except Exception as e:
                    print(f"Error: {e}")
        else:
            parser.print_help()
            
    finally:
        auth.close()

if __name__ == "__main__":
    main()