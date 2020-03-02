from Crypto.Cipher import AES
#key = "aaaabbbbccccdddd"
key = "zapatitosblancos"
cipher = AES.new(key)

x = True

while x:
    opc = int(input("Que desea hacer, (1)Cifrar; (2)Decifrar, (3)Salir: "))

    if opc==1:
        with open("corazon.bmp", "rb") as f:
          clear = f.read()
        
        mod = len(clear)%16

        clear_trimmed = clear[64:-mod]

        ciphertext = cipher.encrypt(clear_trimmed)

        ciphertext = clear[0:64] + ciphertext + clear[-mod:]

        with open("corazon_ecb.bmp", "wb") as f:
          f.write(ciphertext)

    if opc==2:
        with open("corazon_ecb.bmp", "rb") as f:
          clear = f.read()

        mod = len(clear)%16

        clear_trimmed = clear[64:-mod]

        ciphertext = cipher.decrypt(clear_trimmed)

        ciphertext = clear[0:64] + ciphertext + clear[-mod:]

        with open("corazon_ecb1.bmp", "wb") as f:
          f.write(ciphertext)

    if opc==3:
        x = False
