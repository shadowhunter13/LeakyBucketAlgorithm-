import tkinter as tk
from tkinter import messagebox, ttk
import socket
import threading
import time

class LeakyBucket:
    def __init__(self, capacity, leak_rate):
        self.capacity = capacity
        self.leak_rate = leak_rate
        self.current_water = 0
        self.last_leak_time = time.time()

    def add_packet(self, packets):
        self.leak()
        if self.current_water + packets <= self.capacity:
            self.current_water += packets
            return True
        return False

    def leak(self):
        current_time = time.time()
        elapsed = current_time - self.last_leak_time
        leaked_amount = elapsed * self.leak_rate
        self.current_water = max(0, self.current_water - leaked_amount)
        self.last_leak_time = current_time

class LeakyBucketApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Leaky Bucket Simulator")
        self.root.geometry("450x400")
        self.root.configure(bg="#2d2d2d")

        self.bucket = LeakyBucket(capacity=10, leak_rate=2)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", font=("Helvetica", 10), padding=5, background="#4a4a4a", foreground="white")
        style.map("TButton", background=[("active", "#6a6a6a")])
        style.configure("TLabel", background="#2d2d2d", foreground="#ffffff", font=("Helvetica", 12))

        self.status_frame = tk.Frame(root, bg="#2d2d2d")
        self.status_frame.pack(pady=20)
        self.status_label = ttk.Label(self.status_frame, text=f"Bucket: {self.bucket.current_water}/{self.bucket.capacity}")
        self.status_label.pack()

        self.entry_frame = tk.Frame(root, bg="#2d2d2d")
        self.entry_frame.pack(pady=10)
        
        self.packet_entry = ttk.Entry(self.entry_frame, width=20, font=("Helvetica", 10))
        self.packet_entry.pack()
        
        self.leak_dropdown = ttk.Combobox(self.entry_frame, values=[str(i) for i in range(1, 11)], state="readonly")
        self.leak_dropdown.current(0)
        self.leak_dropdown.pack_forget()

        self.action_button = ttk.Button(root, text="Action", command=self.perform_action)
        self.action_button.pack(pady=10)
        self.action_button.config(state="disabled")

        self.mode_frame = tk.Frame(root, bg="#2d2d2d")
        self.mode_frame.pack(pady=20)
        
        self.sender_button = ttk.Button(self.mode_frame, text="Run as Sender", command=self.start_sender)
        self.sender_button.grid(row=0, column=0, padx=10)
        
        self.receiver_button = ttk.Button(self.mode_frame, text="Run as Receiver", command=self.start_receiver)
        self.receiver_button.grid(row=0, column=1, padx=10)

        self.socket = None
        self.is_sender = False
        self.connection = None
        self.running = True

    def start_sender(self):
        self.is_sender = True
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(('localhost', 5555))
        self.socket.listen(1)
        self.status_label.config(text=f"Bucket: {self.bucket.current_water}/{self.bucket.capacity} - Waiting for Receiver...")
        self.sender_button.config(state="disabled")
        self.receiver_button.config(state="disabled")
        self.packet_entry.config(state="normal")
        self.leak_dropdown.pack_forget()
        self.action_button.config(text="Add Packet", state="normal")

        threading.Thread(target=self.accept_receiver, daemon=True).start()

    def accept_receiver(self):
        self.connection, addr = self.socket.accept()
        self.status_label.config(text=f"Bucket: {self.bucket.current_water}/{self.bucket.capacity} - Receiver connected")
        self.connection.send(str(self.bucket.current_water).encode('utf-8'))
        threading.Thread(target=self.receive_updates, daemon=True).start()

    def start_receiver(self):
        self.is_sender = False
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect(('localhost', 5555))
        self.status_label.config(text=f"Bucket: {self.bucket.current_water}/{self.bucket.capacity} - Connected to Sender")
        self.sender_button.config(state="disabled")
        self.receiver_button.config(state="disabled")
        self.packet_entry.pack_forget()
        self.leak_dropdown.pack()
        self.action_button.config(text="Leak Packets", state="normal")

        threading.Thread(target=self.receive_updates, daemon=True).start()

    def perform_action(self):
        if self.is_sender:
            self.add_packet()
        else:
            self.leak_packets()

    def add_packet(self):
        try:
            packets = int(self.packet_entry.get())
            if packets <= 0:
                messagebox.showwarning("Warning", "Enter a positive number!")
                return
            if self.bucket.add_packet(packets):
                self.update_status()
                if self.connection:
                    self.connection.send(str(self.bucket.current_water).encode('utf-8'))
            else:
                messagebox.showerror("Error", "Bucket Overflow!")
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number!")
        self.packet_entry.delete(0, tk.END)

    def leak_packets(self):
        leak_amount = int(self.leak_dropdown.get())
        self.bucket.leak()
        self.update_status()
        if self.socket:
            self.socket.send(str(self.bucket.current_water).encode('utf-8'))

    def receive_updates(self):
        while self.running:
            try:
                if self.is_sender and self.connection:
                    data = self.connection.recv(1024).decode('utf-8')
                elif not self.is_sender:
                    data = self.socket.recv(1024).decode('utf-8')
                if data:
                    self.bucket.current_water = int(data)
                    self.update_status()
            except:
                if self.running:
                    self.status_label.config(text="Connection lost.")
                break

    def update_status(self):
        self.status_label.config(text=f"Bucket: {self.bucket.current_water}/{self.bucket.capacity}")

    def on_closing(self):
        self.running = False
        if self.connection:
            self.connection.close()
        if self.socket:
            self.socket.close()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = LeakyBucketApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)

    root.mainloop()
