from Cryptodome.Cipher import AES

if __name__ == "__main__":
    key = b"palabrasde16bits"
    iv = b"palabrasde16bits"
    cipher = AES.new(key=key, mode=AES.MODE_OFB, iv=iv)
    cipher2 = AES.new(key=key, mode=AES.MODE_OFB, iv=iv)


    with open("tux.bmp", "rb") as image:
        clear_image = image.read()

    mod = len(clear_image) % 8
    aux = clear_image[64:-mod]

    encrypted_image = cipher.encrypt(aux)

    encrypted_image = clear_image[0:64] + encrypted_image + clear_image[-mod:]

    with open("tux_ofb.bmp", "wb") as new_image:
        new_image.write(encrypted_image)

    with open("tux_ofb.bmp", "rb") as image:
        clear_image = image.read()

    mod = len(clear_image) % 8
    aux = clear_image[64:-mod]

    encrypted_image = cipher2.decrypt(aux)

    encrypted_image = clear_image[0:64] + encrypted_image + clear_image[-mod:]

    with open("tux_ofb_d.bmp", "wb") as new_image:
        new_image.write(encrypted_image)