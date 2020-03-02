def decrypt(key, msg, alphabet):
    decrypted_msg = ""
    for index in range(len(msg)):
        Ci = alphabet.index(msg[index])
        Ki = (len(alphabet) - alphabet.index(key[index % len(key)])) % len(alphabet)
        decrypted_char = alphabet[(Ci + Ki) % len(alphabet)]
        decrypted_msg += decrypted_char
    return decrypted_msg


def encrypt(key, message, alphabet):
    encrypted_msg = ""
    for index in range(len(msg)):
        Mi = alphabet.index(msg[index])
        Ki = alphabet.index(key[index % len(key)]) % len(alphabet)
        encrypted_char = alphabet[(Mi + Ki) % len(alphabet)]
        encrypted_msg += encrypted_char
    return encrypted_msg


if __name__ == "__main__":
    alphabet = []
    for character in range(97, 123):
        alphabet.append(chr(character))

    while True:
        print("\n\tMenu")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")
        option = int(input("Option: "))
        if option == 1:
            key = input("Key: ").lower()
            msg = input("Message: ").lower()  
            print(encrypt(key, msg, alphabet))      
        elif option == 2:
            key = input("Key: ").lower()
            msg = input("Message: ").lower()
            print(decrypt(key, msg, alphabet))
        elif option == 3:
            break
        else:
            continue
