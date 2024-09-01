import secrets
import string
import argparse

def generate_password(length, use_uppercase=True, use_lowercase=True, use_digits=True, use_special=True):
    if length < 4:
        raise ValueError("Password length should be at least 4 to include all character types.")

    character_sets = []
    if use_uppercase:
        character_sets.append(string.ascii_uppercase)
    if use_lowercase:
        character_sets.append(string.ascii_lowercase)
    if use_digits:
        character_sets.append(string.digits)
    if use_special:
        character_sets.append(string.punctuation)

    if not character_sets:
        raise ValueError("At least one character type must be selected.")

    password = [secrets.choice(char_set) for char_set in character_sets]
    all_characters = ''.join(character_sets)
    password += [secrets.choice(all_characters) for _ in range(length - len(password))]
    secrets.SystemRandom().shuffle(password)

    return ''.join(password)

def password_strength(password):
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)

    strength = 0
    if length >= 8:
        strength += 1
    if has_upper:
        strength += 1
    if has_lower:
        strength += 1
    if has_digit:
        strength += 1
    if has_special:
        strength += 1

    return strength

def main():
    parser = argparse.ArgumentParser(description="Generate a secure password.")
    parser.add_argument("length", type=int, help="Length of the password")
    parser.add_argument("--no-uppercase", action="store_false", dest="use_uppercase", help="Exclude uppercase letters")
    parser.add_argument("--no-lowercase", action="store_false", dest="use_lowercase", help="Exclude lowercase letters")
    parser.add_argument("--no-digits", action="store_false", dest="use_digits", help="Exclude digits")
    parser.add_argument("--no-special", action="store_false", dest="use_special", help="Exclude special characters")
    parser.add_argument("--save", action="store_true", help="Save the generated password to a file")

    args = parser.parse_args()

    try:
        password = generate_password(
            length=args.length,
            use_uppercase=args.use_uppercase,
            use_lowercase=args.use_lowercase,
            use_digits=args.use_digits,
            use_special=args.use_special
        )

        strength = password_strength(password)
        print(f"Generated Password: {password}")
        print(f"Password Strength: {strength}")

        if args.save:
            with open("passwords.txt", "a") as f:
                f.write(f"{password}\n")
            print("Password saved to passwords.txt")

    except ValueError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()