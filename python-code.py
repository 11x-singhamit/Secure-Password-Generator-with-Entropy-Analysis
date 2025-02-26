import random
import string
import re
import math
import bcrypt

def generate_password(length):
    """
    Generates a random password with a mix of characters, numbers, and symbols.
    
    :param length: Length of the password
    :return: Generated password string
    """
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def enforce_password_policy(password):
    """
    Enforces a basic password policy.
    
    :param password: The password to check
    :return: Tuple (bool, str) indicating if the password is valid and why/why not
    """
    policy_details = (
        "Password Policy:\n"
        "- Minimum length of 8 characters\n"
        "- At least one uppercase letter\n"
        "- At least one lowercase letter\n"
        "- At least one digit\n"
        "- At least one special character from !@#$%^&*(),.?\":{}|<>"
    )

    if len(password) < 8:
        return False, f"{policy_details}\n\nPassword must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, f"{policy_details}\n\nPassword must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, f"{policy_details}\n\nPassword must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, f"{policy_details}\n\nPassword must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, f"{policy_details}\n\nPassword must contain at least one special character."
    return True, f"{policy_details}\n\nPassword meets policy requirements."

def salt_password(password):
    """
    Adds a salt to the password for demonstration purposes.
    
    :param password: The original password
    :return: Tuple (str, str) of salted password and salt
    """
    salt = bcrypt.gensalt()
    salted_password = bcrypt.hashpw(password.encode(), salt)
    return salted_password, salt

def calculate_entropy(password):
    """
    Calculates the entropy of the password for security awareness.
    
    :param password: The password to analyze
    :return: Entropy in bits
    """
    charset = len(string.ascii_letters + string.digits + string.punctuation)
    return math.log2(charset) * len(password)

# Main execution
if __name__ == "__main__":
    while True:
        try:
            length = int(input("\nEnter the desired length of the password (12-20 characters recommended): "))
            if length <= 0:
                print("\nPlease enter a positive number for length.")
            else:
                break
        except ValueError:
            print("\nPlease enter a valid number.")

    new_password = generate_password(length)
    
    print(f"\nGenerated Password: \n{new_password}")
    
    # Check password against policy
    is_valid, reason = enforce_password_policy(new_password)
    print(f"\n{reason}")
    
    # Add salt and hash the password
    salted_password, salt = salt_password(new_password)
    print(f"\nSalted and Hashed Password: \n{salted_password.decode()}")
    print(f"\nSalt used: \n{salt.decode()}")
    
    # Entropy calculation
    entropy = calculate_entropy(new_password)
    print(f"\nPassword Entropy: \n{entropy:.2f} bits")

    # Educational advice
    print("\nEducational Tips:")
    print("- Use a password manager to generate and store unique, strong passwords.")
    print("- Enable two-factor authentication wherever possible.")
    print("- Never reuse passwords across different services to prevent cross-site vulnerabilities.")
