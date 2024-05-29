import tkinter as tk
from tkinter import ttk
from AES import AES
from RSA import RSA
from Bifid import Bifid

class EncryptionApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.bifid = Bifid()
        self.rsa = RSA()
        self.aesKEY = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x97\x95\x8d\x6e\x61\x7d'
        self.aes = AES(self.aesKEY)

        self.title("Encryption and Decryption GUI")
        self.geometry("600x400")

        self.create_widgets()

    def create_widgets(self):
        # Read File Section
        self.file_path_label = ttk.Label(self, text="File path:")
        self.file_path_label.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)

        self.file_path_entry = ttk.Entry(self, width=50)
        self.file_path_entry.grid(row=0, column=1, padx=10, pady=5)

        self.read_file_button = ttk.Button(self, text="Read File", command=self.read_file)
        self.read_file_button.grid(row=0, column=2, padx=10, pady=5)

        # Input field for message to encrypt
        self.message_encrypt_label = ttk.Label(self, text="Message to encrypt:")
        self.message_encrypt_label.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)

        self.message_encrypt_entry = ttk.Entry(self, width=70)
        self.message_encrypt_entry.grid(row=1, column=1, padx=10, pady=5, columnspan=3)

        # Input field for message to decrypt
        self.message_decrypt_label = ttk.Label(self, text="Message to decrypt:")
        self.message_decrypt_label.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)

        self.message_decrypt_entry = ttk.Entry(self, width=70)
        self.message_decrypt_entry.grid(row=2, column=1, padx=10, pady=5, columnspan=3)

        # Hill Cipher Section
        self.hill_label = ttk.Label(self, text="Bifid")
        self.hill_label.grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)

        self.hill_encrypt_button = ttk.Button(self, text="Encrypt", command=self.hill_encrypt)
        self.hill_encrypt_button.grid(row=4, column=0, padx=10, pady=5)

        self.hill_encrypt_output = ttk.Entry(self, width=70)
        self.hill_encrypt_output.grid(row=4, column=1, padx=10, pady=5, columnspan=3)

        self.hill_decrypt_button = ttk.Button(self, text="Decrypt", command=self.hill_decrypt)
        self.hill_decrypt_button.grid(row=5, column=0, padx=10, pady=5)

        self.hill_decrypt_output = ttk.Entry(self, width=70)
        self.hill_decrypt_output.grid(row=5, column=1, padx=10, pady=5, columnspan=3)

        # RSA Section
        self.rsa_label = ttk.Label(self, text="RSA")
        self.rsa_label.grid(row=6, column=0, padx=10, pady=5, sticky=tk.W)

        self.rsa_encrypt_button = ttk.Button(self, text="Encrypt", command=self.rsa_encrypt)
        self.rsa_encrypt_button.grid(row=7, column=0, padx=10, pady=5)

        self.rsa_encrypt_output = ttk.Entry(self, width=70)
        self.rsa_encrypt_output.grid(row=7, column=1, padx=10, pady=5, columnspan=3)

        self.rsa_decrypt_button = ttk.Button(self, text="Decrypt", command=self.rsa_decrypt)
        self.rsa_decrypt_button.grid(row=8, column=0, padx=10, pady=5)

        self.rsa_decrypt_output = ttk.Entry(self, width=70)
        self.rsa_decrypt_output.grid(row=8, column=1, padx=10, pady=5, columnspan=3)

        # AES Section
        self.aes_label = ttk.Label(self, text="AES")
        self.aes_label.grid(row=9, column=0, padx=10, pady=5, sticky=tk.W)

        self.aes_encrypt_button = ttk.Button(self, text="Encrypt", command=self.aes_encrypt)
        self.aes_encrypt_button.grid(row=10, column=0, padx=10, pady=5)

        self.aes_encrypt_output = ttk.Entry(self, width=70)
        self.aes_encrypt_output.grid(row=10, column=1, padx=10, pady=5, columnspan=3)

        self.aes_decrypt_button = ttk.Button(self, text="Decrypt", command=self.aes_decrypt)
        self.aes_decrypt_button.grid(row=11, column=0, padx=10, pady=5)

        self.aes_decrypt_output = ttk.Entry(self, width=70)
        self.aes_decrypt_output.grid(row=11, column=1, padx=10, pady=5, columnspan=3)

    def hill_encrypt(self):
        message = self.message_encrypt_entry.get().upper()
        encrypted_message = self.bifid.encrypt(message)
        self.hill_encrypt_output.delete(0, tk.END)
        self.hill_encrypt_output.insert(0, encrypted_message)

    def hill_decrypt(self):
        message = self.message_decrypt_entry.get().upper()
        decrypted_message = self.bifid.decrypt(message)
        self.hill_decrypt_output.delete(0, tk.END)
        self.hill_decrypt_output.insert(0, decrypted_message)

    def rsa_encrypt(self):
        message = self.message_encrypt_entry.get()
        encrypted_message = self.rsa.encode_message(message)
        self.rsa_encrypt_output.delete(0, tk.END)
        self.rsa_encrypt_output.insert(0, encrypted_message)

    def rsa_decrypt(self):
        message = self.message_decrypt_entry.get()

        # Converting the encoded message into an array of ints
        # since we receive it in a form of strings separated by spaces
        message_lst = [int(x) for x in message.split(" ")]

        decrypted_message = self.rsa.decode_message(message_lst)

        self.rsa_decrypt_output.delete(0, tk.END)
        self.rsa_decrypt_output.insert(0, decrypted_message)

    def aes_encrypt(self):
        message = self.message_encrypt_entry.get()

        # Encoding the string message to a utf-8 byte sequence
        message_utf8 = message.encode("utf-8")

        encrypted_message = self.aes.encrypt(self.aesKEY, message_utf8)

        # Converting the returned byte array to a hexadecimal escaped string
        # since the output cannot display anything but strings
        escaped_message = self.to_hex_escaped_string(encrypted_message)

        self.aes_encrypt_output.delete(0, tk.END)
        self.aes_encrypt_output.insert(0, escaped_message)

    def aes_decrypt(self):
        encoded = self.message_decrypt_entry.get()
        encoded_bytes = bytes.fromhex(encoded.replace('\\x', ''))
        decrypted_message = self.aes.decrypt(self.aesKEY, encoded_bytes)
        self.aes_decrypt_output.delete(0, tk.END)
        self.aes_decrypt_output.insert(0, decrypted_message)

    def to_hex_escaped_string(self, byte_data):
        return ''.join(f'\\x{b:02x}' for b in byte_data)

    def read_file(self):
        file_path = self.file_path_entry.get()
        try:
            with open(file_path, 'r') as file:
                file_content = file.read()
                self.message_encrypt_entry.delete(0, tk.END)
                self.message_encrypt_entry.insert(0, file_content)
        except Exception as e:
            self.message_encrypt_entry.delete(0, tk.END)
            self.message_encrypt_entry.insert(0, f"Error reading file: {e}")

if __name__ == "__main__":
    app = EncryptionApp()
    app.mainloop()
