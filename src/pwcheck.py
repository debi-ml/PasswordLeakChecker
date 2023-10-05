import requests
import hashlib
import sys
import os
import tkinter as tk
from tkinter import messagebox

# Takes first 5 characters of SHA1 hash of the password and sends a request to api, returns response
def request_api_data(input_char):
    url = "https://api.pwnedpasswords.com/range/" + input_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error code {res.status_code}, check the api and try again.")
    return res

# Takes password and returns  the number of times pw was pwned
def get_api_password_hashes(password):
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_api_password_leaks_count(response, tail)

# Takes hashes from api, and the tail of sha1 of password, outputs the number of times pw was pwned
def get_api_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

# Gets passwords from password.txt 
def get_text_passwords():
    password_text_path = os.path.join(os.getcwd(), "password.txt")
    if not os.path.exists(password_text_path):
        open(password_text_path, 'w').close()
        os.startfile(password_text_path)
        sys.exit(0)

    with open(password_text_path, 'r') as file:
        password_texts = file.readlines()

    return password_texts

# Takes argv and text file for passwords, and
def main():
    argv = sys.argv[1:]
    texts = get_text_passwords()

    if argv:
        for item in argv:
            print(get_api_password_hashes(item))
        sys.exit(0)
    
    if texts:
        for text in texts:
            print(get_api_password_hashes(text.strip()))

def check_password():
    password = password_entry.get()
    if password:
        result = get_api_password_hashes(password)
        result_text.set(f"Your password was found {result} times in pwned passwords database.")
    else:
        messagebox.showerror("Error", "Please enter a password.")

def check_file_passwords():
    texts = get_text_passwords()
    if texts:
        results = []
        for text in texts:
            result = get_api_password_hashes(text.strip())
            results.append(f"Password: {text.strip()}, was found {result} times")
        result_text.set('\n'.join(results))
        
root = tk.Tk()

password_text = tk.StringVar()
password_entry = tk.Entry(root, textvariable=password_text)
password_entry.pack()

check_button = tk.Button(root, text="Check Password", command=check_password)
check_button.pack()

check_file_button = tk.Button(root, text="Check Passwords from text file", command=check_file_passwords)
check_file_button.pack()

result_text = tk.StringVar()
result_label = tk.Label(root, textvariable=result_text)
result_label.pack()

root.mainloop()

if __name__ == "__main__":
    main()