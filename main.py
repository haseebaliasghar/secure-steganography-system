import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from PIL import Image
import base64
import hashlib
import os
import secrets

# Constants for salt length
SALT_LENGTH = 16  # 16 bytes for salt

# Key Derivation Function
def generate_key(password, salt):
    """Generate a key from the password and salt using PBKDF2-HMAC-SHA256."""
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.urlsafe_b64encode(key[:32])

# Steganography Functions
def encode_image(image_path, encrypted_message, output_path, salt_aes):
    """Encode the encrypted message and salt into the image using LSB steganography."""
    try:
        img = Image.open(image_path).convert("RGB")  # Ensure RGB format
    except Exception as e:
        raise ValueError(f"Invalid image file: {e}")

    binary_message = ''.join(format(byte, '08b') for byte in encrypted_message)
    binary_salt_aes = ''.join(format(byte, '08b') for byte in salt_aes)
    binary_message += binary_salt_aes + '00000000'  # Append salt and null terminator
    message_length = len(binary_message)
    width, height = img.size

    # Check if the image is large enough to embed the message
    if width * height * 3 < message_length:
        raise ValueError("Image is too small to embed the message.")

    index = 0
    for x in range(width):
        for y in range(height):
            pixel = list(img.getpixel((x, y)))
            for i in range(3):  # Modify RGB channels
                if index < message_length:
                    pixel[i] = pixel[i] & ~1 | int(binary_message[index])
                    index += 1
            img.putpixel((x, y), tuple(pixel))
            if index >= message_length:
                img.save(output_path, format="PNG")  # Save as PNG
                return

def decode_image(image_path):
    """Decode the encrypted message and salt from the image using LSB steganography."""
    try:
        img = Image.open(image_path).convert("RGB")  # Ensure RGB format
    except Exception as e:
        raise ValueError(f"Invalid image file: {e}")

    width, height = img.size
    binary_message = ''
    for x in range(width):
        for y in range(height):
            pixel = img.getpixel((x, y))
            for i in range(3):  # Extract from RGB channels
                binary_message += str(pixel[i] & 1)
                if len(binary_message) % 8 == 0 and len(binary_message) >= 8:
                    byte = binary_message[-8:]
                    if byte == '00000000':  # Stop at null terminator
                        # Extract the encrypted message and salt
                        total_bits = len(binary_message) - 8  # Exclude null terminator
                        salt_bits = SALT_LENGTH * 8  # One salt
                        message_bits = total_bits - salt_bits
                        encrypted_message = bytes(int(binary_message[i:i+8], 2) for i in range(0, message_bits, 8))
                        salt_aes = bytes(int(binary_message[i:i+8], 2) for i in range(message_bits, total_bits, 8))
                        return encrypted_message, salt_aes
    raise ValueError("Failed to extract message or salt from the image.")

def calculate_max_message_size(image_path):
    """Calculate the maximum message size (in bytes) that can be embedded in the image."""
    img = Image.open(image_path)
    width, height = img.size
    return (width * height * 3) // 8  # 3 bits per pixel (RGB), 8 bits per byte

# Main Application
class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Semester Project")
        self.root.geometry("300x200")
        self.root.configure(bg="#2E3440")

        # Main Frame
        self.main_frame = tk.Frame(root, bg="#2E3440")
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Title
        self.title_label = tk.Label(self.main_frame, text="Semester Project", bg="#2E3440", fg="white", font=("Arial", 16, "bold"))
        self.title_label.pack(pady=10)

        # Buttons
        self.encrypt_button = tk.Button(self.main_frame, text="Encrypt and Embed", command=self.open_encrypt_window, font=("Arial", 12), bg="#5E81AC", fg="white")
        self.encrypt_button.pack(pady=10)

        self.decrypt_button = tk.Button(self.main_frame, text="Extract and Decrypt", command=self.open_decrypt_window, font=("Arial", 12), bg="#BF616A", fg="white")
        self.decrypt_button.pack(pady=10)

    def open_encrypt_window(self):
        """Open the encryption window."""
        self.encrypt_window = tk.Toplevel(self.root)
        self.encrypt_window.title("Encrypt and Embed")
        self.encrypt_window.geometry("400x400")
        self.encrypt_window.configure(bg="#2E3440")

        # Fields
        self.message_label = tk.Label(self.encrypt_window, text="Secret Message:", bg="#2E3440", fg="white", font=("Arial", 12))
        self.message_label.pack(pady=10)
        self.message_entry = tk.Entry(self.encrypt_window, width=40, font=("Arial", 12), bg="#4C566A", fg="white", insertbackground="white")
        self.message_entry.pack(pady=10)

        self.password_label = tk.Label(self.encrypt_window, text="Password:", bg="#2E3440", fg="white", font=("Arial", 12))
        self.password_label.pack(pady=10)
        self.password_entry = tk.Entry(self.encrypt_window, width=40, show="*", font=("Arial", 12), bg="#4C566A", fg="white", insertbackground="white")
        self.password_entry.pack(pady=10)

        self.image_label = tk.Label(self.encrypt_window, text="Image File:", bg="#2E3440", fg="white", font=("Arial", 12))
        self.image_label.pack(pady=10)
        self.image_entry = tk.Entry(self.encrypt_window, width=40, font=("Arial", 12), bg="#4C566A", fg="white", insertbackground="white")
        self.image_entry.pack(pady=10)
        self.browse_button = tk.Button(self.encrypt_window, text="Browse", command=lambda: self.browse_image(self.image_entry), font=("Arial", 12), bg="#5E81AC", fg="white")
        self.browse_button.pack(pady=10)

        # Encrypt Button
        self.encrypt_button = tk.Button(self.encrypt_window, text="Encrypt and Embed", command=self.encode, font=("Arial", 12), bg="#88C0D0", fg="white")
        self.encrypt_button.pack(pady=20)

    def open_decrypt_window(self):
        """Open the decryption window."""
        self.decrypt_window = tk.Toplevel(self.root)
        self.decrypt_window.title("Extract and Decrypt")
        self.decrypt_window.geometry("400x300")
        self.decrypt_window.configure(bg="#2E3440")

        # Fields
        self.password_label = tk.Label(self.decrypt_window, text="Password:", bg="#2E3440", fg="white", font=("Arial", 12))
        self.password_label.pack(pady=10)
        self.password_entry = tk.Entry(self.decrypt_window, width=40, show="*", font=("Arial", 12), bg="#4C566A", fg="white", insertbackground="white")
        self.password_entry.pack(pady=10)

        self.image_label = tk.Label(self.decrypt_window, text="Image File:", bg="#2E3440", fg="white", font=("Arial", 12))
        self.image_label.pack(pady=10)
        self.image_entry = tk.Entry(self.decrypt_window, width=40, font=("Arial", 12), bg="#4C566A", fg="white", insertbackground="white")
        self.image_entry.pack(pady=10)
        self.browse_button = tk.Button(self.decrypt_window, text="Browse", command=lambda: self.browse_image(self.image_entry), font=("Arial", 12), bg="#5E81AC", fg="white")
        self.browse_button.pack(pady=10)

        # Decrypt Button
        self.decrypt_button = tk.Button(self.decrypt_window, text="Extract and Decrypt", command=self.decode, font=("Arial", 12), bg="#BF616A", fg="white")
        self.decrypt_button.pack(pady=20)

    def browse_image(self, entry_widget):
        """Open a file dialog to select an image."""
        file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")])
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, file_path)

    def encode(self):
        """Encrypt the message and embed it into the image."""
        message = self.message_entry.get()
        password = self.password_entry.get()
        image_path = self.image_entry.get()

        if not message or not password or not image_path:
            messagebox.showerror("Error", "Please fill all fields.")
            return

        try:
            # Calculate maximum embeddable message size
            max_message_size = calculate_max_message_size(image_path)
            encrypted_message_size = len(message) + 32  # Approximate size after encryption and salt
            if encrypted_message_size > max_message_size:
                messagebox.showerror("Error", f"The image is too small to embed the message. Maximum embeddable size: {max_message_size} bytes.")
                return

            # Generate salt
            salt_aes = secrets.token_bytes(SALT_LENGTH)

            # Derive key
            key_aes = generate_key(password, salt_aes)

            # Encrypt the message
            fernet = Fernet(key_aes)
            encrypted_message = fernet.encrypt(message.encode())

            # Encode the message and salt into the image
            output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Files", "*.png")])
            if output_path:
                encode_image(image_path, encrypted_message, output_path, salt_aes)
                messagebox.showinfo("Success", "Message encrypted and embedded successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def decode(self):
        """Extract and decrypt the message from the image."""
        password = self.password_entry.get()
        image_path = self.image_entry.get()

        if not password or not image_path:
            messagebox.showerror("Error", "Please fill all fields.")
            return

        try:
            # Decode the message and salt from the image
            encrypted_message, salt_aes = decode_image(image_path)

            # Derive key
            key_aes = generate_key(password, salt_aes)

            # Decrypt the message
            fernet = Fernet(key_aes)
            decrypted_message = fernet.decrypt(encrypted_message).decode()
            messagebox.showinfo("Decrypted Message", f"Decrypted Message: {decrypted_message}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
