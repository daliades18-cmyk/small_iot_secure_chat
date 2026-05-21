# Secure Chat Application

A secure real-time chat application built using Python that demonstrates modern secure communication techniques such as hybrid encryption, digital signatures, secure socket communication, and encrypted file transfer.

This project was developed as a cybersecurity and networking learning project to understand how secure messaging applications like WhatsApp work internally.

---

# Project Objective

The main objective of this project is to learn and implement:

- Secure client-server communication
- Hybrid encryption (RSA + AES)
- Digital signatures
- Socket programming
- Secure file transfer
- GUI-based chat systems
- Real-time encrypted messaging

Instead of only using existing messaging platforms, this project focuses on understanding the internal working of secure communication systems.

---

# Features

- Secure encrypted messaging
- RSA + AES hybrid encryption
- Digital signatures
- File sharing support
- Typing indicators
- Read receipts (✓ and ✓✓)
- Real-time communication
- Tkinter GUI interface
- Secure socket communication

---

# Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core programming |
| Socket Programming | Communication |
| Tkinter | GUI |
| Cryptography Library | Encryption |
| Threading | Background message handling |
| JSON/Base64 | Packet serialization |

---

# Security Concepts Implemented

## RSA Encryption
Used for:
- Public/private key generation
- Secure AES key exchange
- Digital signatures

## AES-GCM Encryption
Used for:
- Fast symmetric encryption
- Message confidentiality
- Integrity verification

## Hybrid Encryption
Workflow:
1. Generate AES key
2. Encrypt message using AES
3. Encrypt AES key using RSA
4. Send encrypted packet

## Digital Signatures
- Verifies sender authenticity
- Detects message tampering

---

# Project Structure

```text
secure-chat-app/
│
├── client.py
├── server.py
├── crypto_utils.py
├── requirements.txt
├── README.md
├── .gitignore
└── screenshots/
```

---

# How to Run in VS Code

## Step 1: Install Python

Download Python:

https://www.python.org/downloads/

During installation:
- Enable "Add Python to PATH"

Check installation:

```bash
python --version
```

---

## Step 2: Install VS Code

Download Visual Studio Code:

https://code.visualstudio.com/

Install normally.

---

## Step 3: Install Python Extension

Open VS Code.

Go to:
- Extensions
- Search for `Python`
- Install the Python extension by Microsoft

---

## Step 4: Clone or Download Project

### Clone Using Git

```bash
git clone https://github.com/yourusername/secure-chat-app.git
```

### OR Download ZIP
- Click Code
- Click Download ZIP
- Extract folder

---

## Step 5: Open Project in VS Code

- Open VS Code
- Click File → Open Folder
- Select project folder

---

## Step 6: Create Virtual Environment

Open terminal in VS Code:

```bash
python -m venv venv
```

Activate environment.

### Windows

```bash
venv\Scripts\activate
```

### Linux/Mac

```bash
source venv/bin/activate
```

---

## Step 7: Install Requirements

```bash
pip install -r requirements.txt
```

---

## Step 8: Run Server

Open terminal:

```bash
python server.py
```

Server window opens and waits for connection.

---

## Step 9: Run Client

Open another terminal:

```bash
python client.py
```

Client connects securely to server.

---

## Step 10: Start Chatting

You can now:
- Send encrypted messages
- Share files
- View typing indicators
- See read receipts

---

# How It Works

## Server
- Waits for client connection
- Exchanges RSA public keys
- Receives encrypted packets
- Decrypts and verifies messages

## Client
- Connects to server
- Encrypts messages before sending
- Verifies received signatures
- Displays secure chat GUI

---

# Message Flow

```text
Sender
   ↓
AES Encrypt Message
   ↓
RSA Encrypt AES Key
   ↓
Digitally Sign Message
   ↓
Send Packet
   ↓
Receiver Verifies + Decrypts
```

---

# Installation

## Install Requirements

```bash
pip install -r requirements.txt
```

---

# Run Application

## Run Server

```bash
python server.py
```

## Run Client

```bash
python client.py
```

---

# Learning Outcomes

Through this project, I learned:

- Socket programming
- Secure communication systems
- Cryptography fundamentals
- RSA and AES encryption
- Digital signatures
- Multithreading
- GUI development
- Secure file transfer
- Packet serialization/deserialization

---

# Future Improvements

Possible future upgrades:

- Multi-client support
- Group chat
- Database message storage
- User authentication/login
- Cloud deployment
- Voice/video communication
- End-to-end key verification
- Optimized file transfer

---

# Educational Purpose

This project is mainly designed for:
- Cybersecurity learning
- Networking practice
- Understanding encrypted communication
- Academic mini/final-year projects

It is a simplified educational implementation inspired by real-world secure chat systems.

---

# Author

Developed as a cybersecurity and networking learning project using Python.
