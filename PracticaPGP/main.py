from tkinter import *
from tkinter import font
from tkinter import filedialog
from tkinter import messagebox
import Crypto.Random as Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA1
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad


class Window(Tk):
    # CONSTRUCTOR (MENU)
    def __init__(self):
        super().__init__()

        #Variables
        self.opcion = IntVar()
        self.var_cifrado_descifrado = IntVar()
        self.var_firma_verificacion = IntVar()
        self.path_completo_archivo = StringVar()
        self.nombre_archivo = StringVar()
        self.path_completo_llave = StringVar()
        self.nombre_archivo_llave = StringVar()
        self.path_completo_llave2 = StringVar()
        self.nombre_archivo_llave2 = StringVar()
        self.texto_llave1 = StringVar()
        self.texto_llave2 = StringVar()

        self.title("PGP")
        self.default_font = font.Font(font=("Ubuntu", 12), name="TkDefaultFont", exists=TRUE)
        self.option_add("*Font", self.default_font)

        Label(self, text="Menu").grid(row=0, column=1, pady=10)

        Label(self, text="Elija los servicios que desea").grid(row=1, column=1, pady=10)
        

        self.radio_cifrado_descifrado = Checkbutton(self, text="Cifrado / Descifrado", 
            variable=self.var_cifrado_descifrado, onvalue=1, offvalue=0).grid(row=2, column=1, pady=10)

        self.radio_firma_verificacion = Checkbutton(self, text="Firma / Verificacion", 
            variable=self.var_firma_verificacion, onvalue=1, offvalue=0).grid(row=3, column=1, pady=10)

        Button(self, text="GO!!", width=30, command=self.handle_buttonGo).grid(row=4, column=1)


    #  SELECCIONAR ACCIONES
    def handle_buttonGo(self):
        if self.var_cifrado_descifrado.get() == 1 and self.var_firma_verificacion.get() == 1:
            self.ventanaPGP()
        elif self.var_cifrado_descifrado.get() == 1:
            self.ventanaCifradoDescifrado()
        elif self.var_firma_verificacion.get() == 1:
            self.ventanaFirmaVerificacion()
        else:
            messagebox.showerror(title="Error", message="Selecciona alguna acción :)")


    # VENTANA CIFRADO Y DESCIFRADO
    def ventanaCifradoDescifrado(self):
        ventana_cifrado_descifrado = Toplevel(self)
        ventana_cifrado_descifrado.title("Confidencialidad")
        ventana_cifrado_descifrado.focus()

        Label(ventana_cifrado_descifrado, text="Cifrar / Descrifrar").grid(row=0, column=0, columnspan=3)
        Radiobutton(ventana_cifrado_descifrado, variable=self.opcion, text="Cifrar", value=1).grid(
            row=1, column=0, pady=20, padx=20, columnspan=2)
        Radiobutton(ventana_cifrado_descifrado, variable=self.opcion, text="Descifrar", value=2).grid(
            row=1, column=1, pady=20, padx=20, columnspan=2)

        Label(ventana_cifrado_descifrado, text="Seleccionar archivo: ").grid(row=2, column=0, sticky="W")
        Label(ventana_cifrado_descifrado, textvariable=self.nombre_archivo, width=15).grid(row=2, column=1)
        Button(ventana_cifrado_descifrado, text="Seleccionar", command=self.seleccionarArchivo).grid(
            row=2, column=2)

        Label(ventana_cifrado_descifrado, text="Seleccionar llave: ").grid(row=3, column=0, sticky="W")
        Label(ventana_cifrado_descifrado, textvariable=self.nombre_archivo_llave, width=15).grid(row=3, column=1)
        Button(ventana_cifrado_descifrado, text="Seleccionar", command=self.seleccionarLlave).grid(
            row=3, column=2)

        Button(ventana_cifrado_descifrado, text="GO!!", command=self.cifrarDescifrar, width=40).grid(row=4, column=0, columnspan=3, padx=10, pady=10)


    # Ventana FIRMA VERIFICACIÓN
    def ventanaFirmaVerificacion(self):
        ventana_firma_verificacion = Toplevel(self)
        ventana_firma_verificacion.title("Autenticación")
        ventana_firma_verificacion.focus()

        Label(ventana_firma_verificacion, text="Firmar / Verificar").grid(row=0, column=0, columnspan=3)
        Radiobutton(ventana_firma_verificacion, variable=self.opcion, text="Firmar", value=1).grid(
            row=1, column=0, pady=20, padx=20, columnspan=2)
        Radiobutton(ventana_firma_verificacion, variable=self.opcion, text="Verificar", value=2).grid(
            row=1, column=1, pady=20, padx=20, columnspan=2)

        Label(ventana_firma_verificacion, text="Seleccionar archivo: ").grid(row=2, column=0, sticky="W")
        Label(ventana_firma_verificacion, textvariable=self.nombre_archivo, width=15).grid(row=2, column=1)
        Button(ventana_firma_verificacion, text="Seleccionar", command=self.seleccionarArchivo).grid(
            row=2, column=2)

        Label(ventana_firma_verificacion, text="Seleccionar llave: ").grid(row=3, column=0, sticky="W")
        Label(ventana_firma_verificacion, textvariable=self.nombre_archivo_llave, width=15).grid(row=3, column=1)
        Button(ventana_firma_verificacion, text="Seleccionar", command=self.seleccionarLlave).grid(
            row=3, column=2)

        Button(ventana_firma_verificacion, text="GO!!", command=self.firmarVerificar, width=40).grid(row=4, column=0, columnspan=3, padx=10, pady=10)


    # Ventana PGP
    def ventanaPGP(self):
        ventana_pgp = Toplevel(self)
        ventana_pgp.title("PGP")
        ventana_pgp.focus()

        Label(ventana_pgp, text="Cifrado-Firma / Descifrar-Verificar").grid(row=0, column=0, columnspan=3)
        self.radio_cifrar = Radiobutton(ventana_pgp, variable=self.opcion, text="Cifrado", value=1, command=self.setText)
        self.radio_cifrar.grid(row=1, column=0, pady=20, padx=20, columnspan=2)

        self.radio_descifrar = Radiobutton(ventana_pgp, variable=self.opcion, text="Descifrado", value=2, command=self.setText)
        self.radio_descifrar.grid(row=1, column=1, pady=20, padx=20, columnspan=2)

        self.radio_cifrar.select()
        self.setText()

        Label(ventana_pgp, text="Seleccionar archivo: ").grid(row=2, column=0, sticky="W")
        Label(ventana_pgp, textvariable=self.nombre_archivo, width=15).grid(row=2, column=1)
        Button(ventana_pgp, text="Seleccionar", command=self.seleccionarArchivo).grid(
            row=2, column=2)

        Label(ventana_pgp, textvariable=self.texto_llave1).grid(row=3, column=0, sticky="W")
        Label(ventana_pgp, textvariable=self.nombre_archivo_llave, width=15).grid(row=3, column=1)
        Button(ventana_pgp, text="Seleccionar", command=self.seleccionarLlave).grid(
            row=3, column=2)

        Label(ventana_pgp, textvariable=self.texto_llave2).grid(row=4, column=0, sticky="W")
        Label(ventana_pgp, textvariable=self.nombre_archivo_llave2, width=15).grid(row=4, column=1)
        Button(ventana_pgp, text="Seleccionar", command=self.seleccionarLlave2).grid(
            row=4, column=2)
        Button(ventana_pgp, text="GO!!", command=self.prettyGoodPrivacy, width=40).grid(row=5, column=0, columnspan=3, padx=10, pady=10)


    # CIFRAR / DESCIFRAR
    def cifrarDescifrar(self):
        if self.path_completo_archivo.get() == "":
            messagebox.showerror(title="Error", message="Selecciona el archivo que quieres cifrar/descifrar.")
            return False
        
        # CIFRAR
        if self.opcion.get() == 1: 

            if self.path_completo_llave.get() == "":
                messagebox.showerror(title="Error", message="Selecciona la llave pública del destinatario.")
                return False

            texto_claro, texto_claro_binario = self.leerArchivoParaCifrar()
            llave_sesion = self.getLlaveAleatoria()
            cifrador = self.getCifradorAES(llave_sesion, None)
            iv = cifrador.iv
            texto_cifrado = self.getTextoCifrado(cifrador, texto_claro_binario)
            llave_publica_bob = self.leerLlave()
            llave_cifrada, iv_cifrado = self.cifradoRSA(llave_publica_bob, llave_sesion, iv)

            if self.crearDocumentoCifrado(texto_cifrado, llave_cifrada, iv_cifrado):
                messagebox.showinfo(title="DONE", message="Se guardó el archivo con éxito :D")
            else:
                messagebox.showerror(title="ERROR", message="No se pudo guardar el archivo. Intentalo de nuevo")

        # DESCIFRAR
        elif self.opcion.get() == 2: 
            
            if self.path_completo_llave.get() == "":
                messagebox.showerror(title="Error", message="Selecciona tu llave privada.")
                return False

            texto_cifrado, llave_sesion_cifrada, iv_cifrado = self.leerAchivoParaDescifrar()
            llave_privada_bob = self.leerLlave()
            llave_sesion, iv = self.descifradoRSA(llave_privada_bob, llave_sesion_cifrada, iv_cifrado)
            descifrador = self.getCifradorAES(llave_sesion, iv)
            texto_descifrado = self.getTextoDescifrado(descifrador, texto_cifrado)

            if self.crearDocumentoDescifrado(texto_descifrado):
                messagebox.showinfo(title="DONE", message="Se guardó el archivo con éxito :D")
            else:
                messagebox.showerror(title="ERROR", message="No se pudo guardar el archivo. Intentalo de nuevo")

        else:
            messagebox.showerror(title="Error", message="Selecciona alguna acción :)")


    # FIRMAR VERIFICAR
    def firmarVerificar(self):
        if self.path_completo_archivo.get() == "":
            messagebox.showerror(title="Error", message="Selecciona el archivo que quieres firmar/verificar.")
            return False
        #Firmar
        if self.opcion.get() == 1:
            if self.path_completo_llave.get() == "":
                messagebox.showerror(title="Error", message="Selecciona tu llave privada.")
                return False

            texto_claro, texto_claro_binario = self.leerArchivoParaFirmar()
            digesto = self.getDigesto(texto_claro_binario)
            llave_privada_alice = self.leerLlave()
            firma = self.firmar(llave_privada_alice, digesto)

            if self.crearDocumentoFirmado(texto_claro, firma):
                messagebox.showinfo(title="DONE", message="Se guardó el archivo con éxito :D")
            else:
                messagebox.showerror(title="ERROR", message="No se pudo guardar el archivo. Intentalo de nuevo")

        #Verificar
        elif self.opcion.get() == 2:

            if self.path_completo_llave.get() == "":
                messagebox.showerror(title="Error", message="Selecciona la llave publica del destinatario")
                return False

            texto_claro_binario, firma = self.leerArchivoParaVerificar()
            llave_publica_alice = self.leerLlave()
            digesto = self.getDigesto(texto_claro_binario)

            if self.verificarFirma(llave_publica_alice, firma, digesto):
                messagebox.showinfo(title="DONE", message=":D")
            else:
                messagebox.showerror(title="ERROR", message="D:")

        else:
            messagebox.showerror(title="Error", message="Selecciona alguna acción :)")


    # PGP CIFRAR FIRMAR / DESCIFRAR VERIFICAR
    def prettyGoodPrivacy(self):
        if self.path_completo_archivo.get() == "":
            messagebox.showerror(title="Error", message="Selecciona el archivo que quieres firmar/verificar.")
            return False

        if self.opcion.get() == 1:
            if self.path_completo_llave.get() == "":
                messagebox.showerror(title="Error", message="Selecciona la llave publica del receptor.")
                return False
            if self.path_completo_llave2.get() == "":
                messagebox.showerror(title="Error", message="Selecciona tu llave privada.")
                return False
            
            # CIFRADO
            texto_claro, texto_claro_binario = self.leerArchivoParaCifrar()
            llave_sesion = self.getLlaveAleatoria()
            cifrador = self.getCifradorAES(llave_sesion, None)
            iv = cifrador.iv
            texto_cifrado = self.getTextoCifrado(cifrador, texto_claro_binario)
            llave_publica_bob = self.leerLlave()
            llave_cifrada, iv_cifrado = self.cifradoRSA(llave_publica_bob, llave_sesion, iv)

            # FIRMA
            digesto = self.getDigesto(bytes("".join(texto_claro.split("\n")), "utf-8"))
            llave_privada_alice = self.leerLlave2()
            firma = self.firmar(llave_privada_alice, digesto)

            # CREAR DOCUMENTO
            if self.crearDocumentoPGP(texto_cifrado, llave_cifrada, iv_cifrado, firma):
                messagebox.showinfo(title="DONE", message="Se guardó el archivo con éxito :D")
            else:
                messagebox.showerror(title="ERROR", message="No se pudo guardar el archivo. Intentalo de nuevo")


        elif self.opcion.get() == 2:
            if self.path_completo_llave.get() == "":
                messagebox.showerror(title="Error", message="Selecciona la llave publica del emisor.")
                return False
            if self.path_completo_llave2.get() == "":
                messagebox.showerror(title="Error", message="Selecciona tu llave privada.")
                return False

            texto_cifrado, llave_cifrada, iv_cifrado, firma = self.leerArchivoParaPGP()
            
            # DESCIFRAR LLAVE, IV, TEXTO
            llave_privada_bob = self.leerLlave2()
            llave_sesion, iv = self.descifradoRSA(llave_privada_bob, llave_cifrada, iv_cifrado)
            descifrador = self.getCifradorAES(llave_sesion, iv)
            texto_descifrado = self.getTextoDescifrado(descifrador, texto_cifrado)

            # VERIFICAR FIRMA
            llave_publica_alice = self.leerLlave()
            digesto = self.getDigesto(bytes("".join(texto_descifrado.decode("utf-8").split("\n")), "utf-8"))
            
            if self.verificarFirma(llave_publica_alice, firma, digesto):
                messagebox.showinfo(title="DONE", message="Verificación correcta :D")
                if self.crearDocumentoDescifrado(texto_descifrado):
                    messagebox.showinfo(title="DONE", message="Se guardó el archivo con éxito :D")
                else:
                    messagebox.showerror(title="ERROR", message="No se pudo guardar el archivo. Intentalo de nuevo")
            else:
                messagebox.showerror(title="ERROR", message="Falló la verificación D:")

            

        else:
            messagebox.showerror(title="Error", message="Selecciona alguna acción :)")




    # Seleccionar Archivo
    def seleccionarArchivo(self):
        file = filedialog.askopenfile(initialdir=".", title="Seleccionar archivo", filetypes=((("Text files","*.txt"),("all files","*.*"))))
        try: 
            self.path_completo_archivo.set(file.name)
            filename = file.name.split("/")
            self.nombre_archivo.set(filename[-1])
        except:
            self.nombre_archivo.set("")
            self.path_completo_archivo.set("")


    # Seleccionar Llave
    def seleccionarLlave(self):
        file = filedialog.askopenfile(initialdir=".", title="Seleccionar llave", filetypes=((("PEM files","*.pem"),("all files","*.*"))))
        try: 
            self.path_completo_llave.set(file.name)
            filename = file.name.split("/")
            self.nombre_archivo_llave.set(filename[-1])
        except:
            self.nombre_archivo_llave.set("")
            self.path_completo_llave.set("")


    # Seleccionar LLave 2
    def seleccionarLlave2(self):
        file = filedialog.askopenfile(initialdir=".", title="Seleccionar llave", filetypes=((("PEM files","*.pem"),("all files","*.*"))))
        try: 
            self.path_completo_llave2.set(file.name)
            filename = file.name.split("/")
            self.nombre_archivo_llave2.set(filename[-1])
        except:
            self.nombre_archivo_llave2.set("")
            self.path_completo_llave2.set("")


    # Leer llave
    def leerLlave(self):
        with open(self.path_completo_llave.get(), "rb") as llave:
            return llave.read()


    def leerLlave2(self):
        with open(self.path_completo_llave2.get(), "rb") as llave:
            return llave.read()


    def getLlaveAleatoria(self):
        return Random.get_random_bytes(16)


    def getCifradorAES(self, key, iv):
        if iv:
            return AES.new(key, AES.MODE_CBC, iv)
        else:
            return AES.new(key, AES.MODE_CBC)


    def leerArchivoParaCifrar(self):
        with open(self.path_completo_archivo.get(), "rb") as archivo:
            texto_claro_binario = archivo.read()

        with open(self.path_completo_archivo.get(), "r") as archivo:
            texto_claro = archivo.read()

        return texto_claro, texto_claro_binario


    def getTextoCifrado(self, cifrador, text_claro_binario):
        return cifrador.encrypt(pad(text_claro_binario, AES.block_size)).hex()


    def cifradoRSA(self, llave_publica, llave_sesion, iv):
        llave_cifrada = PKCS1_OAEP.new(RSA.importKey(llave_publica)).encrypt(llave_sesion).hex()
        iv_cifrado = PKCS1_OAEP.new(RSA.importKey(llave_publica)).encrypt(iv).hex()
        return llave_cifrada, iv_cifrado


    def crearDocumentoCifrado(self, texto, llave, iv):
        nuevo_texto = texto + "\n" + llave + "\n" + iv
        saved_file = filedialog.asksaveasfile(initialdir=".", title="Guardad Archivo", filetypes=((("Text files","*.txt"),("all files","*.*"))))
        if not saved_file:
            return False
        with open(saved_file.name, "w") as file:
            file.write(nuevo_texto)
        return True


    def leerAchivoParaDescifrar(self):
        with open(self.path_completo_archivo.get(), "r") as archivo:
            texto_completo = archivo.readlines()

        texto_cifrado = b"".fromhex(texto_completo[0].strip())
        llave_sesion = b"".fromhex(texto_completo[1].strip())
        iv = b"".fromhex(texto_completo[2].strip())

        return texto_cifrado, llave_sesion, iv


    def descifradoRSA(self, llave_privada, llave_cifrada, iv_cifrado):
        llave_sesion = PKCS1_OAEP.new(RSA.importKey(llave_privada)).decrypt(llave_cifrada)
        iv = PKCS1_OAEP.new(RSA.importKey(llave_privada)).decrypt(iv_cifrado)
        return llave_sesion, iv


    def getTextoDescifrado(self, descifrador, texto_cifrado):
        return unpad(descifrador.decrypt(texto_cifrado), AES.block_size)


    def crearDocumentoDescifrado(self, texto_descifrado):
        saved_file = filedialog.asksaveasfile(initialdir=".", title="Guardad Archivo", filetypes=((("Text files","*.txt"),("all files","*.*"))))
        if not saved_file:
            return False
        with open(saved_file.name, "w") as file:
            file.write(texto_descifrado.decode("utf-8"))
        return True


    def leerArchivoParaFirmar(self):
        with open(self.path_completo_archivo.get(), "r") as archivo:
            texto_claro = archivo.read()
            texto_claro_binario = bytes("".join(texto_claro.split("\n")), "utf-8")
        return texto_claro, texto_claro_binario


    def getDigesto(self, texto):
        return SHA1.new(texto)


    def firmar(self, llave, digesto):
        return pkcs1_15.new(RSA.importKey(llave)).sign(digesto).hex()


    def crearDocumentoFirmado(self, texto, firma):
        texto_nuevo = texto + "\n======================FIRMA======================\n" + firma
        saved_file = filedialog.asksaveasfile(initialdir=".", title="Guardad Archivo", filetypes=((("Text files","*.txt"),("all files","*.*"))))
        if not saved_file:
            return False
        with open(saved_file.name, "w") as file:
            file.write(texto_nuevo)
        return True


    def leerArchivoParaVerificar(self):
        with open(self.path_completo_archivo.get(), "r") as archivo:
            texto_completo = archivo.read().split("\n")
            aux = "".join(texto_completo[:-2])
            texto_claro_binario = bytes(aux, "utf-8")
            firma = b"".fromhex(texto_completo[-1])

        return texto_claro_binario, firma


    def verificarFirma(self, llave, firma, digesto):
        try:
            pkcs1_15.new(RSA.importKey(llave)).verify(digesto, firma)
            return True
        except:
            return False


    def setText(self):
        if self.opcion.get() == 1:
            self.texto_llave1.set("Llave pública del receptor:")
            self.texto_llave2.set("Llave privada del emisor:")
        elif self.opcion.get() == 2:
            self.texto_llave1.set("Llave pública del emisor:")
            self.texto_llave2.set("Llave privada del receptor:")


    def crearDocumentoPGP(self, texto, llave, iv, firma):
        nuevo_texto = texto + "\n" + llave + "\n" + iv + "\n" + firma
        saved_file = filedialog.asksaveasfile(initialdir=".", title="Guardad Archivo", filetypes=((("Text files","*.txt"),("all files","*.*"))))
        if not saved_file:
            return False
        with open(saved_file.name, "w") as file:
            file.write(nuevo_texto)
        return True


    def leerArchivoParaPGP(self):
        with open(self.path_completo_archivo.get(), "r") as archivo:
            full = archivo.readlines()
            try:
                texto_cifrado = b"".fromhex(full[0].strip())
                llave_cifrada = b"".fromhex(full[1].strip())
                iv_cifrado = b"".fromhex(full[2].strip())
                firma = b"".fromhex(full[3].strip())
            except:
                messagebox.showerror(title="Error", message="Falló INTEGRIDAD.\nAl parecer el archivo fue modificado")
            
        return texto_cifrado, llave_cifrada, iv_cifrado, firma

if __name__ == "__main__":
    window = Window()
    window.mainloop()