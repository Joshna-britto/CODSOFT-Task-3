import string
import random

def generate_password(length, use_uppercase=True, use_digits=True, use_symbols=True):
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase if use_uppercase else ''
    digits = string.digits if use_digits else ''
    symbols = string.punctuation if use_symbols else ''

    all_chars = lower + upper + digits + symbols

    if not all_chars:
        raise ValueError("At least one character set must be enabled.")

    # Ensure password includes at least one of each selected category
    password = []
    if use_uppercase:
        password.append(random.choice(upper))
    if use_digits:
        password.append(random.choice(digits))
    if use_symbols:
        password.append(random.choice(symbols))

    # Fill the rest of the password
    password += random.choices(all_chars, k=length - len(password))

    # Shuffle the result to mix up categories
    random.shuffle(password)
    return ''.join(password)

def main():
    print(" Password Generator")
    try:
        length = int(input("Enter desired password length (e.g., 12): "))
        if length < 4:
            print("Password length should be at least 4 for good security.")
            return

        use_uppercase = input("Include uppercase letters? (y/n): ").lower() == 'y'
        use_digits = input("Include digits? (y/n): ").lower() == 'y'
        use_symbols = input("Include special characters? (y/n): ").lower() == 'y'

        password = generate_password(length, use_uppercase, use_digits, use_symbols)
        print(f"\n Your generated password is:\n{password}")

    except ValueError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()