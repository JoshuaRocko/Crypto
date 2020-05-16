from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

#HASH
with open("elvis.txt", "rb") as file:
    text = file.read()
    h = SHA256.new(file.read())

print(type(text))
print(f"Digest = {h.hexdigest()}\n\n")


    #RSA
#Firma (cifrado con llave privada)

with open("private.pem", "rb") as key:
    private_key = RSA.importKey(key.read())

signature = pkcs1_15.new(private_key).sign(h)
signature_str = signature.hex()
signature = b"".fromhex(signature_str)

# Verificación (descifrado con llave pública)

with open("public.pem", "rb") as key:
    public_key = RSA.importKey(key.read())

try:
    aber = pkcs1_15.new(public_key).verify(h,signature)
    print("DONE")
except:
    print("Nope :v")