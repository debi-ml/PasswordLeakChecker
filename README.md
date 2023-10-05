# Password Leak Checker

This small utility is designed to check if your password has been compromised in previous data breaches by querying the "Have I Been Pwned" API. It provides a secure way to verify if your password has appeared in known data leaks without sharing sensitive information. Instead, it uses a portion of your password's hash to perform the check.

## Motivation

The primary motivations for this project are:

1. **Education**: This project serves as a learning exercise for those interested in API integration and GUI development with Python, using the `requests` library for API calls and `tkinter` for the GUI.

2. **Security**: By not sharing your actual password with external services, you can ensure a higher level of security. This utility only shares a portion of your password's hash, allowing you to verify its integrity locally.

## How it Works

The utility works by sending a partial SHA1 hash of your password to the "Have I Been Pwned" API. The API responds with a list of password hashes that match the partial hash. The utility then checks if your full password hash is present in the response, indicating a compromised password.

## Getting Started

1. **Prerequisites**: Ensure you have Python installed on your machine.

2. **Clone the Repository**: Clone this repository to your local machine.

   ```shell
   git clone https://github.com/your-username/password-leak-checker.git
   ```

3. **Install Dependencies**: Install the required dependencies using pip.
    ```shell
   pip install -r requirements.txt
   ```

## Usage

You can use this utility in three ways:

**Option 1: GUI**

1. Launch the GUI by running the script.

2. Enter your password in the input field.

3. Click the "Check Password" button to see if your password has been found in the "Have I Been Pwned" database.

**Option 2: Command Line**

You can also check passwords from the command line by providing them as arguments when running the script. For example:

```shell
 python pwcheck.py mypassword123 anotherpassword
```

In this mode, the utility will check the provided passwords for leaks and display the results in the terminal.

**Option 3: password.txt File**

You can store multiple passwords in a password.txt file, with each password on a separate line. If the file doesn't exist, the utility will create it for you. To use this mode:

Create or edit the password.txt file in the same directory as the script. Type one password per line in the file.



