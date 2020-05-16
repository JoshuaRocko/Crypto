from tkinter import *
from tkinter import font
from tkinter import filedialog
from tkinter import messagebox
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

class Window(Tk):

    def __init__(self):
        super().__init__()
        self.title("Digital Signature")
        self.default_font = font.Font(font=("Ubuntu", 12), name="TkDefaultFont", exists=TRUE)
        self.option_add("*Font", self.default_font)

        Label(self, text="Menu").grid(row=0, column=1, pady=10)
        Button(self, text="Sign", command=self.signWindow).grid(row=1, column=0, pady=30, padx=30, ipady=10, ipadx=20)
        Button(self, text="Verify", command=self.verifyWindow).grid(row=1, column=2, pady=30, padx=30, ipady=10, ipadx=20)


    def signWindow(self):
        sign_window = Toplevel(self)
        sign_window.title("Sign")
        
        # Seleccionar Archivo para firmar
        self.str_filename = StringVar(sign_window)
        self.complete_filename = StringVar(sign_window)
        Label(sign_window, text="Select file to sign").grid(row=0, column=0, pady=10, sticky=W)
        Button(sign_window, text="Select", command=self.handleSelectFile).grid(row=1, column=1, sticky=E,ipadx=10)
        Label(sign_window, textvariable=self.str_filename).grid(row=1, column=0, sticky=W, ipadx=40)
        
        # Seleccionar Llave privada
        self.str_filename_key = StringVar(sign_window)
        self.complete_filename_key = StringVar(sign_window)
        Label(sign_window, text="Select private key").grid(row=2, column=0, pady=10, sticky=W)
        Button(sign_window, text="Select", command=self.handleSelectKey).grid(row=3, column=1, sticky=E,ipadx=10)
        Label(sign_window, textvariable=self.str_filename_key).grid(row=3, column=0, sticky=W, ipadx=40)
        
        # Firmar
        Button(sign_window, text="Sign", command=self.signFile).grid(row=4, column=0, columnspan=2, ipadx=20, ipady=5, pady=5)


    def signFile(self):
        if not self.complete_filename.get():
            messagebox.showerror(title="ERROR", message="Primero selecciona el archivo")
            return False

        with open(self.complete_filename.get(), "r") as file:
            text = file.read()
            h = SHA256.new(bytes("".join(text.split("\n")), "utf-8"))

        with open(self.complete_filename_key.get(), "rb") as key:
            private_key = RSA.importKey(key.read())
        
        signature = pkcs1_15.new(private_key).sign(h)

        new_text = text + "\n\n===Sign===\n" + signature.hex()        

        saved_file = filedialog.asksaveasfile(initialdir=".", title="Save Image", filetypes=((("Text files","*.txt"),("all files","*.*"))))

        if not saved_file:
            messagebox.showerror(title="ERROR", message="No se pudo guardar el archivo. Intentalo de nuevo")
            return False

        with open(saved_file.name, "w") as file:
            file.write(new_text)

        messagebox.showinfo(title="DONE", message="Se guardó el archivo con éxito :D")

 
    def verifyWindow(self):
        verify_window = Toplevel(self)
        verify_window.title("Verify")
        verify_window.focus()

        # Seleccionar archivo para verificar
        self.str_filename = StringVar(verify_window)
        self.complete_filename = StringVar(verify_window)
        Label(verify_window, text="Select file to verify").grid(row=0, column=0, pady=10, sticky=W)
        Button(verify_window, text="Select", command=self.handleSelectFile).grid(row=1, column=1, sticky=E,ipadx=10)
        Label(verify_window, textvariable=self.str_filename).grid(row=1, column=0, sticky=W, ipadx=40)
        
        #Seleccionar llave pública
        self.str_filename_key = StringVar(verify_window)
        self.complete_filename_key = StringVar(verify_window)
        Label(verify_window, text="Select public key").grid(row=2, column=0, pady=10, sticky=W)
        Button(verify_window, text="Select", command=self.handleSelectKey).grid(row=3, column=1, sticky=E,ipadx=10)
        Label(verify_window, textvariable=self.str_filename_key).grid(row=3, column=0, sticky=W, ipadx=40)

        # Verificar
        Button(verify_window, text="Verify", command=self.verifySign).grid(row=4, column=0, columnspan=2, ipadx=20, ipady=5, pady=5)



    def verifySign(self):
        if not self.complete_filename.get():
            messagebox.showerror(title="ERROR", message="Primero selecciona el archivo")
            return False

        with open(self.complete_filename.get(), "r") as file:
            complete_text = file.read().split("\n")
            text = complete_text[:-3]
            text_to_hash = bytes("".join(text), "utf-8")
        
        with open(self.complete_filename_key.get(), "rb") as key:
            public_key = RSA.importKey(key.read())

        h = SHA256.new(text_to_hash)
        signature = b"".fromhex(complete_text[-1])

        try:
            pkcs1_15.new(public_key).verify(h,signature)
            messagebox.showinfo(title="Correcto", message=":)")
        except:
            messagebox.showerror(title="Error", message=":(")


    def handleSelectFile(self):
        file = filedialog.askopenfile(initialdir=".", title="Select Image", filetypes=((("Text files","*.txt"),("all files","*.*"))))
        try: 
            self.complete_filename.set(file.name)
            filename = file.name.split("/")
            self.str_filename.set(filename[-1])
        except:
            self.str_filename.set("")
            self.complete_filename.set("")


    def handleSelectKey(self):
        file = filedialog.askopenfile(initialdir=".", title="Select Image", filetypes=((("Pem files","*.pem"),("all files","*.*"))))
        try: 
            self.complete_filename_key.set(file.name)
            filename = file.name.split("/")
            self.str_filename_key.set(filename[-1])
        except:
            self.str_filename_key.set("")
            self.complete_filename_key.set("")


if __name__ == "__main__":
    window = Window()
    window.mainloop()