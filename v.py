# Multi-user Password Vault with Individual Encryption
# Affan's Vault System - Each user has their own login, encrypted key and password storage

import os
import json
import bcrypt
from tkinter import *
from tkinter import messagebox
from cryptography.fernet import Fernet

USERS_FILE = "users.json"

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

def generate_key(username):
    key = Fernet.generate_key()
    with open(f"key_{username}.key", 'wb') as f:
        f.write(key)

def load_key(username):
    return open(f"key_{username}.key", 'rb').read()

def save_data(username, data, fernet):
    encrypted = fernet.encrypt(json.dumps(data).encode())
    with open(f"vault_{username}.json", 'wb') as f:
        f.write(encrypted)

def load_data(username, fernet):
    if not os.path.exists(f"vault_{username}.json"):
        return {}
    with open(f"vault_{username}.json", 'rb') as f:
        encrypted = f.read()
    try:
        decrypted = fernet.decrypt(encrypted)
        return json.loads(decrypted.decode())
    except:
        messagebox.showerror("Error", "Vault corrupted or wrong key.")
        return {}

def show_vault_ui(username, fernet, vault_data):
    root = Tk()
    root.title(f"🔐 {username}'s Vault")
    root.geometry("500x600")
    root.config(bg="#f0f4f7")

    Label(root, text=f"Welcome, {username}", font=("Helvetica", 16, "bold"), bg="#f0f4f7").pack(pady=10)

    frame = Frame(root, bg="#f0f4f7")
    frame.pack(pady=5)

    Label(frame, text="Website", bg="#f0f4f7").grid(row=0, column=0, sticky=W, padx=5, pady=5)
    site_entry = Entry(frame, width=30)
    site_entry.grid(row=0, column=1, pady=5)

    Label(frame, text="Username", bg="#f0f4f7").grid(row=1, column=0, sticky=W, padx=5)
    user_entry = Entry(frame, width=30)
    user_entry.grid(row=1, column=1, pady=5)

    Label(frame, text="Password", bg="#f0f4f7").grid(row=2, column=0, sticky=W, padx=5)
    pass_entry = Entry(frame, show="*", width=30)
    pass_entry.grid(row=2, column=1, pady=5)

    def toggle_password():
        if pass_entry.cget('show') == '':
            pass_entry.config(show='*')
            toggle_btn.config(text="Show Password")
        else:
            pass_entry.config(show='')
            toggle_btn.config(text="Hide Password")

    toggle_btn = Button(frame, text="Show Password", command=toggle_password, bg="#9e9e9e", fg="white")
    toggle_btn.grid(row=2, column=2, padx=5)

    listbox_frame = Frame(root, bg="#f0f4f7")
    scrollbar = Scrollbar(listbox_frame)
    scrollbar.pack(side=RIGHT, fill=Y)

    listbox = Listbox(listbox_frame, width=60, height=10, yscrollcommand=scrollbar.set)
    listbox.pack()
    scrollbar.config(command=listbox.yview)

    def update_listbox():
        listbox.delete(0, END)
        if not vault_data:
            listbox.insert(END, "No entries found.")
        else:
            for site in vault_data:
                creds = vault_data[site]
                listbox.insert(END, f"{site} → {creds['username']} | {creds['password']}")
        listbox_frame.pack(pady=10)

    def add_entry():
        site = site_entry.get()
        username_ = user_entry.get()
        password = pass_entry.get()
        if site and username_ and password:
            vault_data[site] = {"username": username_, "password": password}
            save_data(username, vault_data, fernet)
            update_listbox()
            site_entry.delete(0, END)
            user_entry.delete(0, END)
            pass_entry.delete(0, END)
            messagebox.showinfo("Saved", "Entry saved successfully!")
        else:
            messagebox.showwarning("Input Error", "All fields required!")

    def delete_entry():
        selected = listbox.curselection()
        if selected:
            selected_text = listbox.get(selected[0])
            website = selected_text.split(" →")[0].strip()
            if website in vault_data:
                confirm = messagebox.askyesno("Delete", f"Delete entry for {website}?")
                if confirm:
                    del vault_data[website]
                    save_data(username, vault_data, fernet)
                    update_listbox()
        else:
            messagebox.showwarning("No Selection", "Please select an entry to delete.")

    def modify_entry():
        selected = listbox.curselection()
        if selected:
            selected_text = listbox.get(selected[0])
            website = selected_text.split(" →")[0].strip()
            new_user = user_entry.get()
            new_pass = pass_entry.get()
            if new_user and new_pass:
                vault_data[website] = {"username": new_user, "password": new_pass}
                save_data(username, vault_data, fernet)
                update_listbox()
                messagebox.showinfo("Updated", f"{website} updated!")
            else:
                messagebox.showwarning("Input Error", "Username and password required!")

    Button(root, text="Add Entry", command=add_entry, bg="#4CAF50", fg="white").pack(pady=5)
    Button(root, text="View Entries", command=update_listbox, bg="#2196F3", fg="white").pack(pady=5)
    Button(root, text="Modify Selected", command=modify_entry, bg="#ff9800", fg="white").pack(pady=5)
    Button(root, text="Delete Selected", command=delete_entry, bg="#f44336", fg="white").pack(pady=5)

    root.mainloop()

def show_login_window():
    win = Tk()
    win.title("Login or Register")
    win.geometry("300x250")
    win.config(bg="#f7f9fc")

    Label(win, text="Username:", bg="#f7f9fc").pack(pady=5)
    user_entry = Entry(win)
    user_entry.pack()

    Label(win, text="Master Password:", bg="#f7f9fc").pack(pady=5)
    pass_entry = Entry(win, show="*")
    pass_entry.pack()

    def handle_register():
        username = user_entry.get()
        password = pass_entry.get()
        users = load_users()
        if username in users:
            messagebox.showerror("Error", "Username already exists!")
        else:
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            users[username] = hashed.decode()
            save_users(users)
            generate_key(username)
            messagebox.showinfo("Success", "User registered. Now login.")

    def handle_login():
        username = user_entry.get()
        password = pass_entry.get()
        users = load_users()
        if username in users and bcrypt.checkpw(password.encode(), users[username].encode()):
            win.destroy()
            key = load_key(username)
            fernet = Fernet(key)
            data = load_data(username, fernet)
            show_vault_ui(username, fernet, data)
        else:
            messagebox.showerror("Error", "Invalid credentials!")

    Button(win, text="Login", command=handle_login, bg="#4CAF50", fg="white").pack(pady=10)
    Button(win, text="Register", command=handle_register, bg="#2196F3", fg="white").pack(pady=5)
    win.mainloop()

show_login_window()
