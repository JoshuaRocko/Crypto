from Crypto.Cipher import AES
from Crypto.Cipher import DES
#key = "aaaabbbbccccdddd"
# key = "zapatitosblancos"
# cipher = AES.new(key)

# key = b'zapat0te'
# cipher = DES.new(key=key, mode=DES.MODE_ECB)

x = True

while x:
    opc = int(input("Que desea hacer, (1)Cifrar; (2)Decifrar, (3)Salir: "))
    if opc==1:
        filename = input("Filename: ")
        input_key = input("Key (8 bytes): ")
        output_file = input("Output filename: ")

        key = bytes(input_key, "utf-8")
        cipher = DES.new(key=key, mode=DES.MODE_ECB)

        with open(filename, "rb") as f:
            clear = f.read()
        
        mod = len(clear)%16

        clear_trimmed = clear[64:-mod]

        ciphertext = cipher.encrypt(clear_trimmed)

        ciphertext = clear[0:64] + ciphertext + clear[-mod:]

        with open(output_file, "wb") as f:
            f.write(ciphertext)

    if opc==2:
        filename = input("Filename: ")
        input_key = input("Key (8 bytes): ")
        output_file = input("Output filename: ")

        key = bytes(input_key, "utf-8")
        cipher = DES.new(key=key, mode=DES.MODE_ECB)

        with open(filename, "rb") as f:
            clear = f.read()

        mod = len(clear)%16

        clear_trimmed = clear[64:-mod]

        ciphertext = cipher.decrypt(clear_trimmed)

        ciphertext = clear[0:64] + ciphertext + clear[-mod:]

        with open(output_file, "wb") as f:
            f.write(ciphertext)

    if opc==3:
        x = False
