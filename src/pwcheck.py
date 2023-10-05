import requests
import hashlib
import sys
import os
import tkinter as tk
from tkinter import messagebox

def request_api_data(input_char):
    """Send a request to the API with the first 5 characters of the SHA1 hash of the password."""
    url = "https://api.pwnedpasswords.com/range/" + input_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error fetching data: {res.status_code}")
    return res

def get_api_password_hashes(password):
    """Return the number of times a password was found in pwned passwords database."""
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_api_password_leaks_count(response, tail)

def get_api_password_leaks_count(hashes, hash_to_check):
    """Check if our password tail is in the response and if so, return the count."""
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def get_text_passwords():
    """Read passwords from a text file. If file doesn't exist, create it and open it."""
    password_text_path = os.path.join(os.getcwd(), "password.txt")
    if not os.path.exists(password_text_path):
        open(password_text_path, 'w').close()
        os.startfile(password_text_path)
        result_text.set("password.txt created, type one password per line.")
        return []

    with open(password_text_path, 'r') as file:
        password_texts = file.readlines()

    return password_texts

def main():
    """Main function to handle command line arguments or read from text file."""
    argv = sys.argv[1:]
    texts = get_text_passwords()

    if len(argv) > 0:
        for item in argv:
            print(f"your password {item} has been pwned {get_api_password_hashes(item)} times")
        sys.exit(0)
    
    if texts:
        for text in texts:
            print(get_api_password_hashes(text.strip()))

def check_password(event=None):
    """Check a single password from GUI input."""
    password = password_entry.get()
    if password:
        result = get_api_password_hashes(password)
        result_text.set(f"Your password was found {result} times in pwned passwords database.")
    else:
        messagebox.showerror("Error", "Please enter a password.")

def check_file_passwords():
    """Check multiple passwords from text file."""
    texts = get_text_passwords()
    if texts:
        results = []
        for text in texts:
            result = get_api_password_hashes(text.strip())
            results.append(f"Password: {text.strip()}, was found {result} times")
        result_text.set('\n'.join(results))
        


if __name__ == "__main__":
    main()
    root = tk.Tk()
    root.geometry("500x300")

    password_text = tk.StringVar()
    password_entry = tk.Entry(root, textvariable=password_text)
    password_entry.pack()
    password_entry.bind('<Return>', check_password)  # Bind the Return key

    check_button = tk.Button(root, text="Check Password", command=check_password)
    check_button.pack()

    check_file_button = tk.Button(root, text="Check Passwords from text file", command=check_file_passwords)
    check_file_button.pack()

    result_text = tk.StringVar()
    result_label = tk.Label(root, textvariable=result_text)
    result_label.pack()

    root.mainloop()