from Cryptodome.Cipher import DES

if __name__ == "__main__":
    # Creamos una llave y el objeto para cifrar
    key = b'zapat0te'
    cipher = DES.new(key=key, mode=DES.MODE_ECB)

    # Abrimos el archivo en modo binario
    with open("tux.bmp", "rb") as image:
        clear_image = image.read()

    # Eliminamos la cabecera bmp
    mod = len(clear_image) % 8
    aux = clear_image[64:-mod]
    
    # Ciframos la imagen
    encrypted_image = cipher.encrypt(aux)

    # Añadimos la cabecera original a la imagen cifrada
    encrypted_image = clear_image[0:64] + encrypted_image + clear_image[-mod:]

    # Escribimos la imagen cifrada
    with open("tux_ecb.bmp", "wb") as new_image:
        new_image.write(encrypted_image)

    with open("tux_ecb.bmp", "rb") as image:
        encrypted_image = image.read()

    mod = len(encrypted_image) % 8
    aux = encrypted_image[64:-mod]

    decrypted_image = cipher.decrypt(aux)

    decrypted_image = encrypted_image[0:64] + decrypted_image + encrypted_image[-mod:]

    with open("tux_ecb_d.bmp", "wb") as new_image:
        new_image.write(decrypted_image)

class DES_Ecb():
    def __init__(self, key):
        super().__init__()
