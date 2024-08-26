import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

class SecureMessaging:
    def __init__(self, root):
        # Initialize the main window
        self.root = root
        self.root.title("Secure Messaging")
        self.root.geometry("800x400")
        self.root.resizable(False, False)

        # String variables for user input
        self.email = tk.StringVar()
        self.password = tk.StringVar()
        self.receiver = tk.StringVar()
        self.subject = tk.StringVar()

        # Create and place labels and entry fields
        self.email_label = tk.Label(self.root, text="Email:")
        self.email_label.place(x=50, y=50)
        self.email_entry = tk.Entry(self.root, textvariable=self.email, width=50)
        self.email_entry.place(x=150, y=50)

        self.password_label = tk.Label(self.root, text="Password:")
        self.password_label.place(x=50, y=100)
        self.password_entry = tk.Entry(self.root, textvariable=self.password, width=50, show="*")
        self.password_entry.place(x=150, y=100)

        self.receiver_label = tk.Label(self.root, text="Receiver:")
        self.receiver_label.place(x=50, y=150)
        self.receiver_entry = tk.Entry(self.root, textvariable=self.receiver, width=50)
        self.receiver_entry.place(x=150, y=150)

        self.subject_label = tk.Label(self.root, text="Subject:")
        self.subject_label.place(x=50, y=200)
        self.subject_entry = tk.Entry(self.root, textvariable=self.subject, width=50)
        self.subject_entry.place(x=150, y=200)

        self.message_label = tk.Label(self.root, text="Message:")
        self.message_label.place(x=50, y=250)
        self.message_entry = tk.Text(self.root, width=50, height=5)
        self.message_entry.place(x=150, y=250)

        # Create and place buttons for various functionalities
        self.send_button = tk.Button(self.root, text="Send", command=self.send_email)
        self.send_button.place(x=50, y=350)
        self.attach_button = tk.Button(self.root, text="Attach File", command=self.attach_file)
        self.attach_button.place(x=150, y=350)
        self.save_button = tk.Button(self.root, text="Save", command=self.save_message)
        self.save_button.place(x=250, y=350)
        self.clear_button = tk.Button(self.root, text="Clear", command=self.clear_fields)
        self.clear_button.place(x=300, y=350)
        self.quit_button = tk.Button(self.root, text="Quit", command=self.root.destroy)
        self.quit_button.place(x=350, y=350)
        self.encrypt_button = tk.Button(self.root, text="Encrypt", command=self.encrypt_message)
        self.encrypt_button.place(x=400, y=350)
        self.decrypt_button = tk.Button(self.root, text="Decrypt", command=self.decrypt_message)
        self.decrypt_button.place(x=500, y=350)

        # Initialize variables to store file paths and messages
        self.file_path = ""
        self.message_text = ""
        self.encrypted_message = ""
        self.decrypted_message = ""
        self.save_path = ""
        self.save_file_name = ""
        self.attachment = ""
        self.save_attachment = ""
        self.attachment_path = ""
        self.attachment_name = ""

    def send_email(self):
        """
        Sends an email with the content and attachment specified by the user.
        """
        try:
            # Retrieve email information from the GUI fields
            email = self.email.get()
            password = self.password.get()
            receiver = self.receiver.get()
            subject = self.subject.get()
            message = self.message_entry.get("1.0", tk.END)
            attachment = self.attachment_path

            # Create the email message
            msg = MIMEMultipart()
            msg['From'] = email
            msg['To'] = receiver
            msg['Subject'] = subject
            msg.attach(MIMEText(message, 'plain'))

            # If an attachment is specified, add it to the email
            if attachment:
                with open(attachment, "rb") as attachment_file:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment_file.read())
                    encoders.encode_base64(part)
                    part.add_header('Content-Disposition', f"attachment; filename= {os.path.basename(attachment)}")
                    msg.attach(part)

            # Send the email using SMTP
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(email, password)
            text = msg.as_string()
            server.sendmail(email, receiver, text)
            server.quit()

            # Show a success message
            messagebox.showinfo("Email Sent", "Email has been sent successfully!")

        except Exception as e:
            # Show an error message if something goes wrong
            messagebox.showerror("Error", f"Failed to send email. Error: {str(e)}")

    def attach_file(self):
        """
        Opens a file dialog to select a file to attach to the email.
        """
        self.attachment_path = filedialog.askopenfilename()
        self.attachment_name = os.path.basename(self.attachment_path)
        messagebox.showinfo("Attachment", f"Attachment: {self.attachment_name}")

    def save_message(self):
        """
        Saves the message text to a .txt file.
        """
        message_text = self.message_entry.get("1.0", tk.END)
        save_path = filedialog.asksaveasfilename(defaultextension=".txt")
        with open(save_path, "w") as file:
            file.write(message_text)
        messagebox.showinfo("Message Saved", "Message has been saved successfully!")

    def clear_fields(self):
        """
        Clears all the input fields in the GUI.
        """
        self.email_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.receiver_entry.delete(0, tk.END)
        self.subject_entry.delete(0, tk.END)
        self.message_entry.delete("1.0", tk.END)
        self.attachment_path = ""
        self.attachment_name = ""
        messagebox.showinfo("Fields Cleared", "Fields have been cleared successfully!")

    def encrypt_message(self):
        """
        Encrypts the message text using AES encryption and saves the encryption key to a file.
        """
        try:
            # Get the message text from the input field
            message_text = self.message_entry.get("1.0", tk.END).strip()

            # Generate a random AES key and create a cipher object
            key = get_random_bytes(32) # 16 bytes for AES-128, 24 bytes for AES-192, 32 bytes for AES-256
            cipher = AES.new(key, AES.MODE_CBC)

            # Encrypt the message text and encode it
            ct_bytes = cipher.encrypt(pad(message_text.encode('utf-8'), AES.block_size))
            iv = base64.b64encode(cipher.iv).decode('utf-8')
            ct = base64.b64encode(ct_bytes).decode('utf-8')
            encrypted_message = f"{iv}:{ct}"

            # Replace the input field content with the encrypted message
            self.message_entry.delete("1.0", tk.END)
            self.message_entry.insert("1.0", encrypted_message)
            messagebox.showinfo("Message Encrypted", "Message has been encrypted successfully!\nSave the key for decryption.")

            # Save the encryption key to a file
            key_path = filedialog.asksaveasfilename(defaultextension=".key", title="Save Encryption Key")
            with open(key_path, "wb") as key_file:
                key_file.write(key)

        except Exception as e:
            # Show an error message if something goes wrong
            messagebox.showerror("Error", f"Encryption failed. Error: {str(e)}")

    def decrypt_message(self):
        """
        Decrypts the encrypted message text using AES decryption and a provided key.
        """
        try:
            # Get the encrypted message from the input field
            encrypted_message = self.message_entry.get("1.0", tk.END).strip()

            # Open a file dialog to select the key file
            key_path = filedialog.askopenfilename(title="Select Encryption Key")
            with open(key_path, "rb") as key_file:
                key = key_file.read()

            # Extract the initialisation vector (IV) and ciphertext from the encrypted message
            iv, ct = encrypted_message.split(":")
            iv = base64.b64decode(iv)
            ct = base64.b64decode(ct)

            # Create a cipher object and decrypt the message
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')

            # Replace the input field content with the decrypted message
            self.message_entry.delete("1.0", tk.END)
            self.message_entry.insert("1.0", pt)
            messagebox.showinfo("Message Decrypted", "Message has been decrypted successfully!")

        except ValueError:
            messagebox.showerror("Error", "Invalid encryption key. Please try again.")
        except Exception as e:
            # Show an error message if something goes wrong
            messagebox.showerror("Error", f"Decryption failed")
            print(e)
            return
        
        # Save the decrypted message to a file
        save_path = filedialog.asksaveasfilename(defaultextension=".txt", title="Save Decrypted Message")
        with open(save_path, "w") as file:
            file.write(pt)
        messagebox.showinfo("Decrypted Message Saved", "Decrypted message has been saved successfully!")
        def encrypt_message(self):
            """
            Encrypts the message text using AES encryption and saves the encryption key to a file.
            """
            try:
                # Get the message text from the input field
                message_text = self.message_entry.get("1.0", tk.END).strip()

                # Generate a random AES key and create a cipher object
                key = get_random_bytes(16)
                cipher = AES.new(key, AES.MODE_CBC)

                # Encrypt the message text and encode it
                ct_bytes = cipher.encrypt(pad(message_text.encode('utf-8'), AES.block_size))
                iv = base64.b64encode(cipher.iv).decode('utf-8')
                ct = base64.b64encode(ct_bytes).decode('utf-8')
                encrypted_message = f"{iv}:{ct}"

                # Replace the input field content with the encrypted message
                self.message_entry.delete("1.0", tk.END)
                self.message_entry.insert("1.0", encrypted_message)
                messagebox.showinfo("Message Encrypted", "Message has been encrypted successfully!\nSave the key for decryption.")

                # Save the encryption key to a file
                key_path = filedialog.asksaveasfilename(defaultextension=".key", title="Save Encryption Key")
                with open(key_path, "wb") as key_file:
                    key_file.write(key)

            except Exception as e:
                # Show an error message if something goes wrong
                messagebox.showerror("Error", f"Encryption failed. Error: {str(e)}")
                return

#runs the application
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureMessaging(root)
    root.mainloop()
