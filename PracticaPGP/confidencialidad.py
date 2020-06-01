from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

data = b'secret'
random_key = get_random_bytes(16)
cipher = AES.new(random_key, AES.MODE_CBC)
cipher_text = cipher.encrypt(pad(data, AES.block_size))

try:
    cipher2 = AES.new(random_key, AES.MODE_CBC, cipher.iv)
    plain = unpad(cipher2.decrypt(cipher_text), AES.block_size)
    print("yes")
except:
    print("nope")

