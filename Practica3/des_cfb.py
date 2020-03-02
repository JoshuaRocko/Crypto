from Cryptodome.Cipher import DES

if __name__ == "__main__":
    key = b"zapatito"
    iv = b"zapatito"
    cipher = DES.new(key=key, mode=DES.MODE_CFB, iv=iv)
    cipher2 = DES.new(key=key, mode=DES.MODE_CFB, iv=iv)


    with open("tux.bmp", "rb") as image:
        clear_image = image.read()

    mod = len(clear_image) % 8
    aux = clear_image[64:-mod]

    encrypted_image = cipher.encrypt(aux)

    encrypted_image = clear_image[0:64] + encrypted_image + clear_image[-mod:]

    with open("tux_cfb.bmp", "wb") as new_image:
        new_image.write(encrypted_image)

    with open("tux_cfb.bmp", "rb") as image:
        clear_image = image.read()

    mod = len(clear_image) % 8
    aux = clear_image[64:-mod]

    encrypted_image = cipher2.decrypt(aux)

    encrypted_image = clear_image[0:64] + encrypted_image + clear_image[-mod:]

    with open("tux_cfb_d.bmp", "wb") as new_image:
        new_image.write(encrypted_image)