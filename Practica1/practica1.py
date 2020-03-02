from base64 import b64encode
from base64 import b64decode

def menu():
    print("\n\tMenu")
    print("1. Encrypt")
    print("2. Decrypt")
    print("3. Exit")
    return int(input("Option: "))

def encrypt(shift, input_file, output_file):
    with open(input_file, "r") as file:
        text = file.read()

    encrypted_text = ""

    for character in text:
        encrypted_character = chr((ord(character) + shift) % 256)
        encrypted_text = encrypted_text + encrypted_character

    base64_text = b64encode(bytes(encrypted_text, "utf-8"))

    with open(output_file, "w") as file:
        file.write(base64_text.decode("utf-8"))

def decrypt(shift, input_file, output_file):
    with open(input_file, "r") as file:
        encrypted_text = b64decode(bytes(file.read(), "utf-8")).decode("utf-8")

    decrypted_text = ""

    for character in encrypted_text:
        decrypted_character = chr((ord(character) + (256-shift)) % 256)
        decrypted_text = decrypted_text + decrypted_character
    
    with open(output_file, "w") as file:
        file.write(decrypted_text)


if __name__ == "__main__":
    option = 0
    while(option != 3):
        option = menu()
        if option == 1:
            input_file = input("Input File name: ")
            output_file = input("Output File name: ")
            shift = -1
            while not(shift >= 0 and shift <= 255):
                shift = int(input("Shift: "))
            encrypt(shift, input_file, output_file)
        elif option == 2:
            input_file = input("Input File name: ")
            output_file = input("Output File name: ")
            shift = -1
            while not(shift >= 0 and shift <= 255):
                shift = int(input("Shift: "))
            decrypt(shift, input_file, output_file)
        else:
            print("Invalid option")
            continue