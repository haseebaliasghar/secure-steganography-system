# Secure Information System using Encryption and Steganography

This project implements a secure system for hiding confidential messages in images using **AES encryption** and **LSB steganography**. The system ensures data confidentiality and provides a user-friendly interface for encrypting, embedding, extracting, and decrypting messages.

---

## Features
- **AES Encryption:** Securely encrypts messages using the Advanced Encryption Standard (AES) algorithm.
- **LSB Steganography:** Embeds encrypted messages into the least significant bits (LSBs) of image pixels.
- **User-Friendly GUI:** Built using Tkinter for easy interaction.
- **Secure Key Derivation:** Uses PBKDF2-HMAC-SHA256 with a salt for robust key generation.
- **PNG Compatibility:** Ensures data integrity by standardizing image processing to the PNG format.
- **Standalone Executable:** Packaged as a standalone application for easy distribution.

---

## How It Works
1. **Encryption and Embedding:**
   - The user provides a secret message, a password, and a cover image.
   - The message is encrypted using AES and embedded into the image using LSB steganography.
   - The resulting stego-image is saved and can be securely transmitted.

2. **Extraction and Decryption:**
   - The recipient provides the stego-image and the password.
   - The system extracts the encrypted message and decrypts it using the provided password.
   - The original secret message is revealed.
