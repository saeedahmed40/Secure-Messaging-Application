# Secure Messaging Application

## Overview

This is a Python-based secure messaging application with a graphical user interface (GUI) built using Tkinter. The application allows users to send encrypted emails, attach files, and save messages securely.

## Features

- Send encrypted emails
- Attach files to emails
- Encrypt and decrypt messages using AES encryption
- Save messages to files
- User-friendly GUI

## Dependencies

- Python 3.x
- Tkinter
- pycryptodome

## Installation

1. Clone this repository:
git clone https://github.com/yourusername/secure-messaging-app.git

2. Install the required dependencies:
pip install pycryptodome

## Usage

Run the application:
python secure_messaging.py
## Functionality

### Sending Emails

1. Enter your email address and password
2. Specify the receiver's email address
3. Enter the subject and message
4. Click "Send" to send the email

### Attaching Files

1. Click "Attach File"
2. Select the file you want to attach

### Encrypting Messages

1. Enter your message
2. Click "Encrypt"
3. Save the encryption key when prompted

### Decrypting Messages

1. Enter the encrypted message
2. Click "Decrypt"
3. Select the corresponding encryption key file when prompted

### Saving Messages

1. Enter your message
2. Click "Save"
3. Choose a location to save the message

## Security Considerations

- This application uses AES encryption for message security
- Encryption keys are saved separately and should be kept secure
- The application currently uses Gmail's SMTP server, which may require enabling "Less secure app access" or using an app password

## Limitations and Future Improvements

- Currently only supports Gmail for sending emails
- Error handling could be improved
- User authentication and key management could be enhanced

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
[Saeed Ahmed](https://www.linkedin.com/in/saeedahmed40/)

## License

This project is open source and available under the [MIT License](LICENSE).
