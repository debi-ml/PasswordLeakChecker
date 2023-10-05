import requests
import hashlib
import sys
import os

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


# Gets password from password.txt 
def get_text_password():

    password_text_path = os.path.join(os.getcwd(), "password.txt")

    with open(password_text_path, 'r') as file:
        password_text = file.read()

    return password_text


# Takes argv and text file for passwords, and
def main():
    #
    argv = sys.argv[1:]
    text = get_text_password()

    if argv:
        for item in argv:
            print(get_api_password_hashes(item))
    if text:
        print(get_api_password_hashes(text))
    
#main()

import tkinter as tk
from tkinter import messagebox

def check_password():
    password = password_entry.get()
    if password:
        result = get_api_password_hashes(password)
        result_text.set(f"Your password was found {result} times in pwned passwords database.")
    else:
        messagebox.showerror("Error", "Please enter a password.")

root = tk.Tk()

password_text = tk.StringVar()
password_entry = tk.Entry(root, textvariable=password_text)
password_entry.pack()

check_button = tk.Button(root, text="Check Password", command=check_password)
check_button.pack()

result_text = tk.StringVar()
result_label = tk.Label(root, textvariable=result_text)
result_label.pack()

root.mainloop()