import json
import hashlib
import os
import getpass # For securely getting password input without showing it
import time
import random
import threading

# Define the file to store user data
USERS_FILE = 'users.json'

def hash_password(password, salt):
    """
    Hashes a password with a given salt using PBKDF2.
    PBKDF2 is recommended for password hashing as it's slow,
    making brute-force attacks more difficult.
    """
    # 'pbkdf2_hmac' is the algorithm
    # 'sha256' is the hash function
    # password.encode('utf-8') converts the string to bytes
    # salt is the random data to add to the hash
    # 100000 is the number of iterations (the more, the slower and more secure)
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    # Return the hash as bytes
    return hashed_password

def load_users():
    """
    Loads the user database from the JSON file.
    If the file doesn't exist, it returns an empty dictionary.
    """
    try:
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        # Handle case where file is empty or corrupted
        return {}

def save_users(users):
    """Saves the user database to the JSON file."""
    with open(USERS_FILE, 'w') as f:
        # indent=4 makes the JSON file human-readable
        json.dump(users, f, indent=4)

def register_user():
    """Registers a new user."""
    print("\n--- Register New User ---")
    users = load_users()
    
    username = input("Enter a new username: ").strip()

    # Check if username already exists
    if username in users:
        print("Error: This username is already taken. Please try another.")
        return

    # Use getpass to hide password input
    password = getpass.getpass("Enter a new password: ")
    password_confirm = getpass.getpass("Confirm your password: ")

    if password != password_confirm:
        print("Error: Passwords do not match.")
        return

    if not password:
        print("Error: Password cannot be empty.")
        return

    # Generate a random salt
    # os.urandom(16) generates 16 random bytes
    salt = os.urandom(16)
    
    # Hash the password
    hashed_password = hash_password(password, salt)

    # Store the user, salt (as hex), and hash (as hex)
    # We must convert bytes (salt, hashed_password) to hex strings
    # to store them in a JSON file.
    users[username] = {
        'salt': salt.hex(),
        'hash': hashed_password.hex()
    }
    
    save_users(users)
    print(f"Successfully registered user: {username}")

def login_user():
    """Logs in an existing user."""
    print("\n--- User Login ---")
    users = load_users()
    
    username = input("Enter your username: ").strip()
    
    # Check if user exists
    if username not in users:
        print("Error: Invalid username or password.")
        return False

    password = getpass.getpass("Enter your password: ")

    # Get the user's stored data
    stored_data = users[username]
    
    try:
        # Convert the hex-encoded salt back into bytes
        salt = bytes.fromhex(stored_data['salt'])
        
        # Convert the hex-encoded hash back into bytes
        stored_hash = bytes.fromhex(stored_data['hash'])
    except (ValueError, TypeError):
        print("Error: User data is corrupted. Please re-register.")
        return False

    # Hash the password the user just entered using the *stored* salt
    provided_hash = hash_password(password, salt)

    # Compare the two hashes
    # We use 'hashlib.timing_safe_compare' to prevent "timing attacks",
    # where an attacker could measure the time it takes to compare
    # passwords to guess the hash.
    if hashlib.timing_safe_compare(stored_hash, provided_hash):
        print(f"\nLogin successful! Welcome, {username}.")
        return True
    else:
        print("Error: Invalid username or password.")
        return False

def remove_user():
    """Removes an existing user from the users file."""
    print("\n--- Remove User ---")
    users = load_users()

    username = input("Enter the username to remove: ").strip()

    if username not in users:
        print("Error: Username not found.")
        return

    confirm = input(f"Are you sure you want to permanently delete '{username}'? (yes/NO): ").strip().lower()
    if confirm != 'yes':
        print("Aborted. No changes made.")
        return

    # Remove the user and save
    try:
        del users[username]
        save_users(users)
        print(f"Successfully removed user: {username}")
    except Exception as e:
        print(f"Error removing user: {e}")

def list_users():
    """Lists all current usernames stored in the users file."""
    print("\n--- Current Users ---")
    users = load_users()

    if not users:
        print("No users found.")
        return

    # Print usernames, one per line
    for uname in sorted(users.keys()):
        print(f"- {uname}")


def main():
    """Main application loop."""
    print("Welcome to the Python Authenticator")
    
    while True:
        print("\nWhat would you like to do?")
        print("1. Register a new user")
        print("2. Login")
        print("3. Exit")
        print("4. Generate 6-digit codes every 30 seconds")
        print("5. Remove an existing user")
        print("6. List all current users")
        
        choice = input("Enter your choice (1, 2, 3, 4, 5, or 6): ").strip()
        
        if choice == '1':
            register_user()
        elif choice == '2':
            login_user() # You could do something after successful login
        elif choice == '3':
            print("Exiting program. Goodbye!")
            break
        elif choice == '4':
            # Start the 6-digit code generator in a thread and stop on Enter
            stop_event = threading.Event()

            def generate_codes(stop_event):
                print("\nStarting 6-digit code generator. Press Enter to stop.\n")
                try:
                    while not stop_event.is_set():
                        code = str(random.randint(0, 999999)).zfill(6)
                        print(f"Code: {code} (valid for 30s)")
                        # wait up to 30 seconds, but return early if stopped
                        stop_event.wait(30)
                except Exception:
                    pass
                finally:
                    print("\nCode generator stopped.")

            thread = threading.Thread(target=generate_codes, args=(stop_event,), daemon=True)
            thread.start()
            # Wait for user to press Enter to stop the generator
            try:
                input()
            except KeyboardInterrupt:
                # Allow Ctrl+C to stop as well
                pass
            stop_event.set()
            thread.join()
        elif choice == '5':
            remove_user()
        elif choice == '6':
            list_users()
        else:
            print("Invalid choice. Please enter 1, 2, 3, 4, 5, or 6.")

# This ensures the main() function runs only when the script is executed directly
if __name__ == "__main__":
    main()