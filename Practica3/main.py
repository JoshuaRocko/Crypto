from tkinter import *
from tkinter import filedialog
from tkinter import font
from tkinter import messagebox
from Crypto.Cipher import DES

class Window(Tk):
    def __init__(self):
        super().__init__()
        self.title("DES CIPHER")        
        self.default_font = font.Font(font=("Ubuntu", 12), name="TkDefaultFont", exists=TRUE)
        self.option_add("*Font", self.default_font)

        #Seleccionar un modo
        Label(self, text="Select a mode: ").grid(row=0, column=0, sticky=W)
        modes = ["",
            "Electronic Codebook ECB",
            "Cipher-Block Chaining CBC",
            "Outout Feedback OFB",
            "Cipher Feedback CFB"
        ]
        self.str_mode = StringVar(self)
        self.str_mode.set("Electronic Codebook ECB")
        self.mode_menu = OptionMenu(self, self.str_mode, *modes)
        self.mode_menu.grid(row=0, column=1, padx=0, pady=10)

        # Llave
        Label(self, text="Key: ").grid(row=1, column=0, sticky=W)
        self.str_key = StringVar(self)
        self.key_input = Entry(self, textvariable=self.str_key)
        self.key_input.grid(row=1, column=1, padx=0, pady=0, sticky=W,)

        # Vector inicial
        Label(self, text="Initial vector:").grid(row=3, column=0, pady=10, sticky=W)
        self.str_iv = StringVar(self)
        self.iv_input = Entry(self, textvariable=self.str_iv)
        self.iv_input.grid(row=3, column=1, pady=10, sticky=W)
        
        # Imagen
        Label(self, text="Select image").grid(row=4, column=0, pady=10, sticky=W)
        self.str_filename = StringVar(self)
        self.select_button = Button(self, text="Select", command=self.handleSelect)
        Label(self, textvariable=self.str_filename).grid(row=4, column=1, sticky=W)
        self.select_button.grid(row=4, column=1, sticky=E)


        # Elegir accion
        self.radio_var = IntVar()
        self.radio_encrypt = Radiobutton(
            self, variable=self.radio_var, text="Encrypt", value=1)
        self.radio_encrypt.grid(row=5, column=0)
        self.radio_encrypt.select()

        self.radio_decrypt = Radiobutton(
            self, variable=self.radio_var, text="Decrypt", value=2)
        self.radio_decrypt.grid(row=5, column=1)

        Button(self, text="GO!!", width=30, command=self.handleButtonGo, bg="#91ff89").grid(row=6, column=0, columnspan=2, pady=10)
        
        # Notas
        Label(self, text="*Notes", font=("Ubuntu", 7)).grid(row=7, column=0, columnspan=2, padx=0, pady=0, sticky=W)
        Label(self, text="- Key length must be 8 bytes", font=("Ubuntu", 7)).grid(row=8, column=0, columnspan=2, padx=0, pady=0, sticky=W)
        Label(self, text="- Initial vector length must be 8 bytes", font=("Ubuntu", 7)).grid(row=9, column=0, columnspan=2, padx=0, pady=0, sticky=W)
        Label(self, text="- Initial vector will be ignored for ECB mode", font=("Ubuntu", 7)).grid(row=10, column=0, columnspan=2, padx=0, pady=0, sticky=W)

        self.complete_filename = StringVar(self)


    def handleSelect(self):
        # Widget para seleccionar archivo.
        file = filedialog.askopenfile(initialdir=".", title="Select Image", filetypes=((("bmp files","*.bmp"),("all files","*.*"))))
        
        # Guardamos el nombre del archivo que se elegió
        # Si no se eligió alguno guardamos la cadena vacía.
        try: 
            self.complete_filename.set(file.name)
            filename = file.name.split("/")
            self.str_filename.set(filename[-1])
        except:
            self.str_filename.set("")
            self.complete_filename.set("")

    def handleButtonGo(self):
        # Verificamos que se haya seleccionado una imagen, en caso de que
        # no se haya selccionado, se notifica y termina la función.
        if not self.complete_filename.get():
            messagebox.showerror(title="ERROR", message="First Select an image")
            return False

        # Creamos el objeto para cifrar o decifrar.
        cipher = self.getCipher(key=self.str_key.get(), iv=self.str_iv.get(), mode=self.str_mode.get().split()[-1])

        # Si no se pudo crear el objeto, notificamos y terminamos la función
        if not cipher:
            messagebox.showerror(title="ERROR", message="Wrong key or iv length")
            return False

        # Abrimos y leemos el archivo que se seleccionó
        try:
            with open(self.complete_filename.get(), "rb") as image:
                clear_image = image.read()
        except:
            messagebox.showerror(title="ERROR", message="Couldn't open image :(")
            return False

        # Eliminamos la cabecera y el padding extra de la imagen
        mod = len(clear_image) % 8
        aux = clear_image[64:-mod]

        # Ciframos o deciframos
        if self.radio_var.get() == 1:
            new_image = cipher.encrypt(aux)
        else:
            new_image = cipher.decrypt(aux)

        # Añadimos la cabera
        new_image = clear_image[0:64] + new_image + clear_image[-mod:]
        
        # Widget para guardar el archivo
        saved_file = filedialog.asksaveasfile(initialdir=".", title="Save Image", filetypes=((("bmp files","*.bmp"),("all files","*.*"))))
        
        # Si no elegió el archivo termina la función
        if not saved_file:
            messagebox.showerror(title="ERROR", message="Couldn't save image :(")
            return False

        # Abrimos el archivo que se seleccionó y escribimos la imágen
        with open(saved_file.name, "wb") as image:
            image.write(new_image)

        messagebox.showinfo(title="DONE", message="Successfully Finished :D")

    def getCipher(self, key, iv, mode):
        if len(key) != 8:
            return None

        if mode == "ECB":
            return DES.new(key=bytes(key, "utf-8"), mode=DES.MODE_ECB)
        else:
            if len(iv) != 8:
                return None
            if mode == "CBC":
                mode = DES.MODE_CBC
            elif mode == "CFB":
                mode = DES.MODE_CFB
            else:
                mode = DES.MODE_OFB
            return DES.new(key=bytes(key, "utf-8"), mode=mode, iv=bytes(iv, "utf-8"))
    

if __name__ == "__main__":
    window = Window()
    window.mainloop()