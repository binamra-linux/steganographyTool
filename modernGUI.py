import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import mysql.connector
import hashlib
import os
import numpy as np
from PIL import Image, ImageTk
from datetime import datetime
import sys

class ModernTheme:
    # Color scheme
    PRIMARY_COLOR = "#2196F3"  # Blue
    SECONDARY_COLOR = "#FFF"   # White
    BACKGROUND_COLOR = "#F5F5F5"  # Light Gray
    TEXT_COLOR = "#212121"     # Dark Gray
    ERROR_COLOR = "#F44336"    # Red
    SUCCESS_COLOR = "#4CAF50"  # Green

    # Styles
    BUTTON_STYLE = {
        "font": ("Helvetica", 10),
        "borderwidth": 0,
        "padx": 15,
        "pady": 8,
        "background": PRIMARY_COLOR,
        "foreground": SECONDARY_COLOR,
    }

    LABEL_STYLE = {
        "font": ("Helvetica", 10),
        "background": BACKGROUND_COLOR,
        "foreground": TEXT_COLOR,
    }

    ENTRY_STYLE = {
        "font": ("Helvetica", 10),
        "borderwidth": 1,
        "relief": "solid",
    }

class SteganographyGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Steganography Tool")
        self.root.geometry("800x600")
        self.root.configure(bg=ModernTheme.BACKGROUND_COLOR)
        
        # Initialize backend classes
        self.auth = UserAuth()
        self.stego = Steganography()
        self.current_user = None
        
        # Create style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TNotebook', background=ModernTheme.BACKGROUND_COLOR)
        self.style.configure('TFrame', background=ModernTheme.BACKGROUND_COLOR)
        
        # Create main container
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Initialize the authentication frame
        self.show_auth_frame()

    def show_auth_frame(self):
        self.clear_main_container()
        
        # Create authentication frame
        auth_frame = ttk.Frame(self.main_container)
        auth_frame.pack(expand=True)
        
        # Title
        title = tk.Label(auth_frame, text="Steganography Tool", 
                        font=("Helvetica", 24, "bold"),
                        bg=ModernTheme.BACKGROUND_COLOR,
                        fg=ModernTheme.PRIMARY_COLOR)
        title.pack(pady=20)
        
        # Login/Register fields
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        
        # Username
        username_frame = ttk.Frame(auth_frame)
        username_frame.pack(pady=10)
        ttk.Label(username_frame, text="Username:").pack(side=tk.LEFT, padx=5)
        ttk.Entry(username_frame, textvariable=self.username_var).pack(side=tk.LEFT)
        
        # Password
        password_frame = ttk.Frame(auth_frame)
        password_frame.pack(pady=10)
        ttk.Label(password_frame, text="Password:").pack(side=tk.LEFT, padx=5)
        ttk.Entry(password_frame, textvariable=self.password_var, show="*").pack(side=tk.LEFT)
        
        # Buttons
        button_frame = ttk.Frame(auth_frame)
        button_frame.pack(pady=20)
        
        login_btn = tk.Button(button_frame, text="Login",
                            command=self.login,
                            **ModernTheme.BUTTON_STYLE)
        login_btn.pack(side=tk.LEFT, padx=5)
        
        register_btn = tk.Button(button_frame, text="Register",
                               command=self.register,
                               **ModernTheme.BUTTON_STYLE)
        register_btn.pack(side=tk.LEFT, padx=5)

    def show_main_app(self):
        self.clear_main_container()
        
        # Create notebook for tabs
        notebook = ttk.Notebook(self.main_container)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        encode_frame = ttk.Frame(notebook)
        decode_frame = ttk.Frame(notebook)
        history_frame = ttk.Frame(notebook)
        
        notebook.add(encode_frame, text="Encode")
        notebook.add(decode_frame, text="Decode")
        notebook.add(history_frame, text="History")
        
        # Setup encode tab
        self.setup_encode_tab(encode_frame)
        self.setup_decode_tab(decode_frame)
        self.setup_history_tab(history_frame)
        
        # Add logout button
        logout_btn = tk.Button(self.main_container, text="Logout",
                             command=self.logout,
                             **ModernTheme.BUTTON_STYLE)
        logout_btn.pack(pady=10)

    def setup_encode_tab(self, parent):
        # Input image selection
        input_frame = ttk.Frame(parent)
        input_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(input_frame, text="Input Image:").pack(side=tk.LEFT, padx=5)
        self.input_path_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.input_path_var).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        ttk.Button(input_frame, text="Browse", command=lambda: self.browse_file(self.input_path_var)).pack(side=tk.LEFT)
        
        # Output image selection
        output_frame = ttk.Frame(parent)
        output_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(output_frame, text="Output Image:").pack(side=tk.LEFT, padx=5)
        self.output_path_var = tk.StringVar()
        ttk.Entry(output_frame, textvariable=self.output_path_var).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        ttk.Button(output_frame, text="Browse", command=lambda: self.browse_file(self.output_path_var, save=True)).pack(side=tk.LEFT)
        
        # Message input
        message_frame = ttk.Frame(parent)
        message_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        ttk.Label(message_frame, text="Message:").pack(anchor=tk.W)
        self.message_text = tk.Text(message_frame, height=5)
        self.message_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Method selection
        method_frame = ttk.Frame(parent)
        method_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(method_frame, text="Method:").pack(side=tk.LEFT, padx=5)
        self.encode_method_var = tk.StringVar(value="lsb")
        ttk.Radiobutton(method_frame, text="LSB", variable=self.encode_method_var, value="lsb").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(method_frame, text="HEX", variable=self.encode_method_var, value="hex").pack(side=tk.LEFT, padx=5)
        
        # Encode button
        encode_btn = tk.Button(parent, text="Encode Message",
                             command=self.encode_message,
                             **ModernTheme.BUTTON_STYLE)
        encode_btn.pack(pady=20)

    def setup_decode_tab(self, parent):
        # Image selection
        input_frame = ttk.Frame(parent)
        input_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(input_frame, text="Image to Decode:").pack(side=tk.LEFT, padx=5)
        self.decode_path_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.decode_path_var).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        ttk.Button(input_frame, text="Browse", command=lambda: self.browse_file(self.decode_path_var)).pack(side=tk.LEFT)
        
        # Method selection
        method_frame = ttk.Frame(parent)
        method_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(method_frame, text="Method:").pack(side=tk.LEFT, padx=5)
        self.decode_method_var = tk.StringVar(value="lsb")
        ttk.Radiobutton(method_frame, text="LSB", variable=self.decode_method_var, value="lsb").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(method_frame, text="HEX", variable=self.decode_method_var, value="hex").pack(side=tk.LEFT, padx=5)
        
        # Decoded message display
        message_frame = ttk.Frame(parent)
        message_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        ttk.Label(message_frame, text="Decoded Message:").pack(anchor=tk.W)
        self.decoded_text = tk.Text(message_frame, height=5, state='disabled')
        self.decoded_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Decode button
        decode_btn = tk.Button(parent, text="Decode Message",
                             command=self.decode_message,
                             **ModernTheme.BUTTON_STYLE)
        decode_btn.pack(pady=20)

    def setup_history_tab(self, parent):
        # Create treeview
        columns = ("Time", "Image", "Method", "Message")
        self.history_tree = ttk.Treeview(parent, columns=columns, show='headings')
        
        # Set column headings
        for col in columns:
            self.history_tree.heading(col, text=col)
            self.history_tree.column(col, width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack widgets
        self.history_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=20, pady=10)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        
        # Refresh button
        refresh_btn = tk.Button(parent, text="Refresh History",
                              command=self.refresh_history,
                              **ModernTheme.BUTTON_STYLE)
        refresh_btn.pack(pady=10)

    def browse_file(self, string_var, save=False):
        if save:
            filename = filedialog.asksaveasfilename(defaultextension=".png",
                                                  filetypes=[("PNG files", "*.png")])
        else:
            filename = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp")])
        if filename:
            string_var.set(filename)

    def encode_message(self):
        try:
            input_path = self.input_path_var.get()
            output_path = self.output_path_var.get()
            message = self.message_text.get("1.0", tk.END).strip()
            method = self.encode_method_var.get()
            
            if not all([input_path, output_path, message]):
                messagebox.showerror("Error", "Please fill in all fields")
                return
                
            self.stego.encode_image(input_path, message, output_path, method)
            messagebox.showinfo("Success", "Message encoded successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decode_message(self):
        try:
            input_path = self.decode_path_var.get()
            method = self.decode_method_var.get()
            
            if not input_path:
                messagebox.showerror("Error", "Please select an image to decode")
                return
                
            message = self.stego.decode_image(input_path, method)
            
            # Update text widget
            self.decoded_text.config(state='normal')
            self.decoded_text.delete("1.0", tk.END)
            self.decoded_text.insert("1.0", message)
            self.decoded_text.config(state='disabled')
            
            # Log the decoded message
            if message != "No hidden message found." and self.current_user:
                self.auth.log_decoded_message(
                    self.current_user[0],
                    os.path.abspath(input_path),
                    message,
                    method
                )
                self.refresh_history()
                
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def refresh_history(self):
        if not self.current_user:
            return
            
        # Clear existing items
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
            
        # Fetch and display history
        history = self.auth.get_user_history(self.current_user[1])
        for entry in history:
            image_path, message, method, timestamp = entry
            self.history_tree.insert("", tk.END, values=(timestamp, image_path, method, message))

    def login(self):
        username = self.username_var.get()
        password = self.password_var.get()
        
        user = self.auth.login(username, password)
        if user:
            self.current_user = user
            messagebox.showinfo("Success", "Login successful!")
            self.show_main_app()
        else:
            messagebox.showerror("Error", "Invalid credentials!")

    def register(self):
        username = self.username_var.get()
        password = self.password_var.get()
        
        if self.auth.register(username, password):
            messagebox.showinfo("Success", "Registration successful!")
        else:
            messagebox.showerror("Error", "Registration failed!")

    def logout(self):
        self.current_user = None
        self.show_auth_frame()

    def clear_main_container(self):
        for widget in self.main_container.winfo_children():
            widget.destroy()

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            if self.auth:
                self.auth.close()
            self.root.destroy()

def main():
    root = tk.Tk()
    app = SteganographyGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

# Reuse the UserAuth and Steganography classes from the original code
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
            return False
        except mysql.connector.Error:
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
        except mysql.connector.Error:
            return None

    def log_decoded_message(self, user_id, image_path, decoded_message, decode_method):
        try:
            self.cursor.execute("""
                INSERT INTO message_history 
                (user_id, image_path, decoded_message, decode_method)
                VALUES (%s, %s, %s, %s)
            """, (user_id, image_path, decoded_message, decode_method))
            self.db.commit()
        except mysql.connector.Error:
            pass

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
        except mysql.connector.Error:
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

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',  # XAMPP default empty password
    'database': 'steganography_db'
}

if __name__ == "__main__":
    main()