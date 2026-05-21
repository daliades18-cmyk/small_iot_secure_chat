# ================================
# FILE: client.py
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

sent_messages_registry = {}
unacknowledged_received_messages = []

# ==========================================
# GUI INITIALIZATION
# ==========================================
window = tk.Tk()
window.title("WhatsApp Secure Client")
window.geometry("500x700")
window.configure(bg="#0b141a")

# Top Status Bar Layout
top_frame = tk.Frame(window, bg="#202c33", height=60)
top_frame.pack(fill=tk.X)

title = tk.Label(top_frame, text="Secure Chat Client", bg="#202c33", fg="white", font=("Arial", 14, "bold"))
title.pack(side=tk.LEFT, padx=15, pady=15)

status_label = tk.Label(top_frame, text="Online", bg="#202c33", fg="#00ff88", font=("Arial", 10))
status_label.pack(side=tk.LEFT, pady=20)

typing_label = tk.Label(top_frame, text="", bg="#202c33", fg="white", font=("Arial", 9))
typing_label.pack(side=tk.RIGHT, padx=15)

# Chat Canvas & Scroll Engine Layout
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
        encrypted = hybrid_encrypt(typing_message, server_public_key)
        signature = sign_message(typing_message.encode(), private_key)
        packet = serialize_message(*encrypted, signature)
        client.sendall(packet)
    except:
        pass

def configure_scroll(event):
    chat_canvas.configure(scrollregion=chat_canvas.bbox("all"))
    # Fix layout break: Force inner frame to stretch up to full canvas width
    chat_canvas.itemconfig(canvas_frame_window, width=chat_canvas.winfo_width())

messages_frame.bind("<Configure>", configure_scroll)

# Redraw and re-stretch instantly when user maximizes window
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
# MESSAGE RENDERING BUBBLE
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
    
    return msg_label

# ==========================================
# FOCUS & READ RECEIPT MANAGER
# ==========================================
def send_seen_receipt(original_msg):
    try:
        seen_payload = f"SEEN::{original_msg}"
        encrypted = hybrid_encrypt(seen_payload, server_public_key)
        signature = sign_message(seen_payload.encode(), private_key)
        packet = serialize_message(*encrypted, signature)
        client.sendall(packet)
    except:
        pass

def on_window_focused(event):
    global unacknowledged_received_messages
    if unacknowledged_received_messages:
        for msg in unacknowledged_received_messages:
            send_seen_receipt(msg)
        unacknowledged_received_messages.clear()

window.bind("<FocusIn>", on_window_focused)

# ==========================================
# BACKGROUND RECEIVE NETWORK THREAD
# ==========================================
def receive_messages():
    while True:
        try:
            data = deserialize_message(client)
            if not data:
                break

            enc_key, nonce, ciphertext, signature = data
            decrypted = hybrid_decrypt(enc_key, nonce, ciphertext, private_key)
            valid = verify_signature(decrypted.encode(), signature, server_public_key)

            def handle_message(decrypted_text=decrypted, is_valid=valid):
                # Typing updates
                if decrypted_text == "TYPING":
                    typing_label.config(text="Typing...")
                    window.after(1000, lambda: typing_label.config(text=""))
                    return

                # Read Receipt processing
                if decrypted_text.startswith("SEEN::"):
                    original_content = decrypted_text.split("::", 1)[1]
                    if original_content in sent_messages_registry:
                        lbl = sent_messages_registry[original_content]
                        lbl.config(text=f"{original_content} ✓✓")
                    return

                if not is_valid:
                    add_message("⚠ Security Warning: Message signature invalid!", "System")

                tracking_payload = ""

                # File Receiver Logic
                if decrypted_text.startswith("FILE::"):
                    parts = decrypted_text.split("::", 2)
                    filename = parts[1]
                    file_content = parts[2]

                    save_path = os.path.join(DOWNLOAD_FOLDER, filename)
                    with open(save_path, "wb") as f:
                        f.write(file_content.encode('latin1'))

                    add_message(f"📁 {filename}", "Server")

                    open_btn = tk.Button(
                        messages_frame, text=f"Open {filename}", bg="#202c33", fg="white",
                        relief=tk.FLAT, command=lambda p=save_path: open_file(p)
                    )
                    open_btn.pack(anchor="w", padx=20, pady=2)
                    
                    tracking_payload = f"📁 Sent File: {filename}"
                
                # Text Receiver Logic
                else:
                    add_message(decrypted_text, "Server")
                    tracking_payload = decrypted_text

                # Check if app is open and viewed before updating double ticks
                if window.focus_displayof() is not None:
                    send_seen_receipt(tracking_payload)
                else:
                    unacknowledged_received_messages.append(tracking_payload)

            window.after(0, handle_message)

        except Exception as e:
            window.after(0, lambda ex=e: add_message(f"Error: {ex}", "System"))
            break

# ==========================================
# OUTBOUND SEND PIPELINES
# ==========================================
def send_message(event=None):
    message = message_entry.get().strip()
    if not message:
        return

    try:
        encrypted = hybrid_encrypt(message, server_public_key)
        signature = sign_message(message.encode(), private_key)
        packet = serialize_message(*encrypted, signature)
        
        client.sendall(packet)

        # Draw local echo with single tick
        msg_label_ref = add_message(message + " ✓", "You")
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
            file_bytes = f.read()

        file_data = file_bytes.decode('latin1')
        message = "FILE::" + filename + "::" + file_data

        encrypted_data = hybrid_encrypt(message, server_public_key)
        signature = sign_message(message.encode(), private_key)

        client.sendall(serialize_message(*encrypted_data, signature))

        display_text = f"📁 Sent File: {filename}"
        msg_label_ref = add_message(display_text + " ✓", "You")
        sent_messages_registry[display_text] = msg_label_ref

    except Exception as e:
        add_message(f"File Send Error: {e}", "System")

# ==========================================
# BOTTOM CONTROLS LAYOUT
# ==========================================
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

# ==========================================
# SOCKET & ENCRYPTION HANDSHAKE KEYS
# ==========================================
private_key, public_key = generate_keys()
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

server_public_key = client.recv(8192)
client.sendall(public_key)
add_message("Secure Connection Established", "System")

threading.Thread(target=receive_messages, daemon=True).start()
window.mainloop()