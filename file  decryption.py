# file_encrypt_decrypt.py

def caesar_cipher(text, shift):
    """Encrypt or decrypt text using Caesar Cipher."""
    result = ""
    for char in text:
        if char.isalpha():
            base = 'A' if char.isupper() else 'a'
            # shift within alphabet range (26 letters)
            result += chr((ord(char) - ord(base) + shift) % 26 + ord(base))
        else:
            result += char
    return result


def encrypt_file(input_file, output_file, shift):
    """Encrypt file content and save to new file."""
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = f.read()
        encrypted_data = caesar_cipher(data, shift)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(encrypted_data)
        print(f"[+] File encrypted successfully and saved as {output_file}")
    except FileNotFoundError:
        print("[-] Error: Input file not found.")


def decrypt_file(input_file, output_file, shift):
    """Decrypt file content and save to new file."""
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = f.read()
        decrypted_data = caesar_cipher(data, -shift)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(decrypted_data)
        print(f"[+] File decrypted successfully and saved as {output_file}")
    except FileNotFoundError:
        print("[-] Error: Input file not found.")


def main():
    print("=== File Encryption / Decryption Tool ===")
    choice = input("Do you want to (E)ncrypt or (D)ecrypt a file? ").strip().lower()

    input_file = input("Enter input file name (with .txt): ").strip()
    output_file = input("Enter output file name (with .txt): ").strip()
    shift = int(input("Enter shift key (e.g., 3): "))

    if choice == 'e':
        encrypt_file(input_file, output_file, shift)
    elif choice == 'd':
        decrypt_file(input_file, output_file, shift)
    else:
        print("[-] Invalid choice. Please enter 'E' or 'D'.")


if __name__ == "__main__":
    main()
