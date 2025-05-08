import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

class ImageEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Encryption Tool")
        self.root.geometry("600x600")
        self.root.configure(bg="#f7f7f7")

        self.key = None
        self.iv = None
        self.original_image_path = None
        self.encrypted_file_path = None

        # Title
        tk.Label(root, text="Secure Image Encryption", font=("Helvetica", 16, "bold"),
                 bg="#f7f7f7", fg="#2c3e50").pack(pady=10)

        # Buttons
        tk.Button(root, text="Upload Image", command=self.upload_image,
                  bg="#3498db", fg="white", width=25).pack(pady=10)

        tk.Button(root, text="Encrypt Image", command=self.encrypt_image,
                  bg="#e67e22", fg="white", width=25).pack(pady=5)

        tk.Button(root, text="Upload Encrypted File", command=self.upload_encrypted_file,
                  bg="#9b59b6", fg="white", width=25).pack(pady=5)

        tk.Button(root, text="Decrypt & Show Image", command=self.decrypt_image,
                  bg="#2ecc71", fg="white", width=25).pack(pady=5)

        # Image Display
        self.image_label = tk.Label(root, bg="#f7f7f7")
        self.image_label.pack(pady=20)

    def upload_image(self):
        path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
        if path:
            self.original_image_path = path
            self.display_image(path)
            messagebox.showinfo("Image Loaded", "Image loaded successfully.")

    def upload_encrypted_file(self):
        path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.bin")])
        if path:
            self.encrypted_file_path = path
            messagebox.showinfo("File Loaded", "Encrypted file loaded successfully.")

    def display_image(self, path):
        img = Image.open(path)
        img = img.resize((300, 300))
        photo = ImageTk.PhotoImage(img)
        self.image_label.configure(image=photo)
        self.image_label.image = photo

    def encrypt_image(self):
        if not self.original_image_path:
            messagebox.showerror("Error", "Please upload an image first.")
            return

        try:
            with open(self.original_image_path, "rb") as f:
                img_bytes = f.read()

            self.key = get_random_bytes(16)
            self.iv = get_random_bytes(16)

            cipher = AES.new(self.key, AES.MODE_CFB, iv=self.iv)
            encrypted_data = cipher.encrypt(img_bytes)

            with open("encrypted_image.bin", "wb") as f:
                f.write(self.key + self.iv + encrypted_data)

            messagebox.showinfo("Encryption Complete", "Encrypted and saved as 'encrypted_image.bin'.")
            self.image_label.configure(image="", text="Encrypted. Upload to decrypt.", font=("Arial", 12), fg="gray")
        except Exception as e:
            messagebox.showerror("Encryption Failed", str(e))

    def decrypt_image(self):
        if not self.encrypted_file_path:
            messagebox.showerror("Error", "Please upload an encrypted file.")
            return

        try:
            with open(self.encrypted_file_path, "rb") as f:
                content = f.read()

            key = content[:16]
            iv = content[16:32]
            encrypted_data = content[32:]

            cipher = AES.new(key, AES.MODE_CFB, iv=iv)
            decrypted_data = cipher.decrypt(encrypted_data)

            with open("decrypted_image.jpg", "wb") as f:
                f.write(decrypted_data)

            self.display_image("decrypted_image.jpg")
            messagebox.showinfo("Decryption Complete", "Image decrypted and displayed.")
        except Exception as e:
            messagebox.showerror("Decryption Failed", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = ImageEncryptorApp(root)
    root.mainloop()
