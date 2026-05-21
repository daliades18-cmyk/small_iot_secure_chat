# ================================
# FILE: server.py
# ================================

import socket
import threading
import tkinter as tk
from datetime import datetime
from crypto_utils import *
from tkinter import filedialog
import os

HOST = '127.0.0.1'
PORT = 5555
DOWNLOAD_FOLDER = "downloads"
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

# Tracks sent messages so we can find their labels later and update to double ticks
# Format: { "message_text": tk.Label_Object }
sent_messages_registry = {}

# ==========================================
# GUI SETUP
# ==========================================
window = tk.Tk()
window.title("WhatsApp Secure Server")
window.geometry("500x700")
window.configure(bg="#0b141a")

top_frame = tk.Frame(window, bg="#202c33", height=60)
top_frame.pack(fill=tk.X)

title = tk.Label(top_frame, text="Secure Chat Server", bg="#202c33", fg="white", font=("Arial", 14, "bold"))
title.pack(side=tk.LEFT, padx=15, pady=15)

status_label = tk.Label(top_frame, text="Online", bg="#202c33", fg="#00ff88", font=("Arial", 10))
status_label.pack(side=tk.LEFT, pady=20)

typing_label = tk.Label(top_frame, text="", bg="#202c33", fg="white", font=("Arial", 9))
typing_label.pack(side=tk.RIGHT, padx=15)

chat_canvas = tk.Canvas(window, bg="#0b141a", highlightthickness=0)
chat_canvas.pack(fill=tk.BOTH, expand=True)

scrollbar = tk.Scrollbar(window, command=chat_canvas.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
chat_canvas.configure(yscrollcommand=scrollbar.set)

messages_frame = tk.Frame(chat_canvas, bg="#0b141a")
canvas_frame_window = chat_canvas.create_window((0, 0), window=messages_frame, anchor="nw")

def send_typing_status():
    try:
        typing_message = "TYPING"
        encrypted = hybrid_encrypt(typing_message, client_public_key)
        signature = sign_message(typing_message.encode(), private_key)
        packet = serialize_message(*encrypted, signature)
        conn.sendall(packet)
    except:
        pass

def configure_scroll(event):
    # Update the scrollable area bounding box
    chat_canvas.configure(scrollregion=chat_canvas.bbox("all"))
    
    # FORCE the inner frame to expand horizontally to match the canvas width
    chat_canvas.itemconfig(canvas_frame_window, width=chat_canvas.winfo_width())

messages_frame.bind("<Configure>", configure_scroll)

# ALSO bind the canvas resize event so it updates immediately when maximizing
chat_canvas.bind("<Configure>", lambda e: chat_canvas.itemconfig(canvas_frame_window, width=chat_canvas.winfo_width()))

def mouse_scroll(event):
    chat_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

chat_canvas.bind_all("<MouseWheel>", mouse_scroll)

def open_file(filepath):
    try:
        os.startfile(filepath)
    except Exception as e:
        add_message(f"Cannot open file: {e}", "System")

# ==========================================
# MESSAGE BUBBLE
# ==========================================
def add_message(message, sender="You"):
    outer = tk.Frame(messages_frame, bg="#0b141a")
    outer.pack(fill=tk.X, pady=5, padx=10)

    is_you = sender == "You"
    bubble_color = "#005c4b" if is_you else "#202c33"
    
    bubble = tk.Frame(outer, bg=bubble_color, padx=10, pady=7)
    bubble.pack(side=tk.RIGHT if is_you else tk.LEFT, anchor="e" if is_you else "w")

    msg_label = tk.Label(
        bubble,
        text=message,
        bg=bubble_color,
        fg="white",
        font=("Arial", 11),
        wraplength=300,
        justify="left"
    )
    msg_label.pack(anchor="w")

    time_label = tk.Label(
        bubble,
        text=datetime.now().strftime("%H:%M"),
        bg=bubble_color,
        fg="#cccccc",
        font=("Arial", 7)
    )
    time_label.pack(anchor="e")

    chat_canvas.update_idletasks()
    window.update_idletasks()
    chat_canvas.configure(scrollregion=chat_canvas.bbox("all"))
    chat_canvas.yview_moveto(1.0)
    
    return msg_label  # Return the reference so we can update ticks later

# Helper to acknowledge a seen status back to the sender
def send_seen_receipt(original_msg):
    try:
        seen_payload = f"SEEN::{original_msg}"
        encrypted = hybrid_encrypt(seen_payload, client_public_key)
        signature = sign_message(seen_payload.encode(), private_key)
        packet = serialize_message(*encrypted, signature)
        conn.sendall(packet)
    except:
        pass

# ==========================================
# RECEIVE MESSAGES & CONTROL PACKETS
# ==========================================
def receive_messages():
    while True:
        try:
            data = deserialize_message(conn)
            if not data:
                break

            enc_key, nonce, ciphertext, signature = data
            decrypted = hybrid_decrypt(enc_key, nonce, ciphertext, private_key)
            valid = verify_signature(decrypted.encode(), signature, client_public_key)

            def handle_message(decrypted_text=decrypted, is_valid=valid):
                # 1. TYPING HANDLING
                if decrypted_text == "TYPING":
                    typing_label.config(text="Typing...")
                    window.after(1000, lambda: typing_label.config(text=""))
                    return

                # 2. SEEN RECEIPT HANDLING (Update Single Tick to Double Tick)
                if decrypted_text.startswith("SEEN::"):
                    original_content = decrypted_text.split("::", 1)[1]
                    # Find our logged message label and change tick
                    if original_content in sent_messages_registry:
                        lbl = sent_messages_registry[original_content]
                        lbl.config(text=f"{original_content} ✓✓")
                    return

                if not is_valid:
                    add_message("⚠ Security Warning: Message failed verification!", "System")

                # 3. FILE RECEIVE
                if decrypted_text.startswith("FILE::"):
                    parts = decrypted_text.split("::", 2)
                    filename = parts[1]
                    file_content = parts[2]

                    save_path = os.path.join(DOWNLOAD_FOLDER, filename)
                    with open(save_path, "wb") as f:
                        f.write(file_content.encode('latin1'))

                    add_message(f"📁 {filename}", "Client")

                    open_btn = tk.Button(
                        messages_frame, text=f"Open {filename}", bg="#202c33", fg="white",
                        relief=tk.FLAT, command=lambda p=save_path: open_file(p)
                    )
                    open_btn.pack(anchor="w", padx=20, pady=2)
                    
                    # Fire back read receipt for the file structure token
                    send_seen_receipt(f"📁 Sent File: {filename}")

                # 4. NORMAL TEXT RECEIVE
                else:
                    add_message(decrypted_text, "Client")
                    # Fire back read receipt for standard text
                    send_seen_receipt(decrypted_text)

            window.after(0, handle_message)

        except Exception as e:
            window.after(0, lambda ex=e: add_message(f"Error: {ex}", "System"))
            break

# ==========================================
# SEND MESSAGES & FILES
# ==========================================
def send_message(event=None):
    message = message_entry.get().strip()
    if not message:
        return

    try:
        encrypted = hybrid_encrypt(message, client_public_key)
        signature = sign_message(message.encode(), private_key)
        packet = serialize_message(*encrypted, signature)
        
        conn.sendall(packet)

        # Initial clean render with single tick
        msg_label_ref = add_message(message + " ✓", "You")
        
        # Save structural reference so background receipt can find it later
        sent_messages_registry[message] = msg_label_ref
        
        typing_label.config(text="")
        message_entry.delete(0, tk.END)

    except Exception as e:
        add_message(f"Send Error: {e}", "System")

def send_file():
    filepath = filedialog.askopenfilename()
    if not filepath:
        return

    try:
        filename = os.path.basename(filepath)
        with open(filepath, "rb") as f:
            file_data = f.read()

        file_message = "FILE::" + filename + "::" + file_data.decode('latin1')
        encrypted_data = hybrid_encrypt(file_message, client_public_key)
        signature = sign_message(file_message.encode(), private_key)

        conn.sendall(serialize_message(*encrypted_data, signature))

        display_text = f"📁 Sent File: {filename}"
        msg_label_ref = add_message(display_text + " ✓", "You")
        
        # Register file descriptor string for read tracking
        sent_messages_registry[display_text] = msg_label_ref

    except Exception as e:
        add_message(f"File Error: {e}", "System")

bottom_frame = tk.Frame(window, bg="#202c33", height=70)
bottom_frame.pack(fill=tk.X, side=tk.BOTTOM)

message_entry = tk.Entry(bottom_frame, font=("Arial", 12), bg="#2a3942", fg="white", insertbackground="white", relief=tk.FLAT)
message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10, pady=10, ipady=10)
message_entry.bind("<KeyPress>", lambda e: send_typing_status())

send_button = tk.Button(bottom_frame, text="Send", bg="#00a884", fg="white", font=("Arial", 11, "bold"), relief=tk.FLAT, padx=20, command=send_message)
send_button.pack(side=tk.RIGHT, padx=10)

file_button = tk.Button(bottom_frame, text="📎", bg="#202c33", fg="white", font=("Arial", 14), relief=tk.FLAT, command=send_file)
file_button.pack(side=tk.RIGHT, padx=5)
message_entry.bind("<Return>", send_message)

# NETWORK KEY EXCHANGE
private_key, public_key = generate_keys()
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)

add_message("Waiting for client...", "System")
conn, addr = server.accept()
add_message(f"Connected: {addr}", "System")

conn.sendall(public_key)
client_public_key = conn.recv(8192)
add_message("Secure Connection Established", "System")

threading.Thread(target=receive_messages, daemon=True).start()
window.mainloop()