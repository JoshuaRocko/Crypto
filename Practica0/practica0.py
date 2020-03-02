from tkinter import *
from tkinter import scrolledtext as st
from tkinter import messagebox
from cryptography.fernet import Fernet


class Window(Tk):
    def __init__(self):
        super().__init__()
        self.title("Cipher")

        self.radio_var = IntVar()
        self.radio_encrypt = Radiobutton(
            self, variable=self.radio_var, text="Encrypt", value=1)
        self.radio_encrypt.grid(row=0, column=0)
        self.radio_encrypt.select()

        self.radio_decrypt = Radiobutton(
            self, variable=self.radio_var, text="Decrypt", value=2)
        self.radio_decrypt.grid(row=0, column=1)

        Label(self, text="Plain text").grid(row=1, column=0, padx=5, pady=5)

        self.text_plain = st.ScrolledText(self, width=25, height=10)
        self.text_plain.grid(row=2, column=0, padx=5, pady=5)

        Label(self, text="Crypted text").grid(row=1, column=1, padx=5, pady=5)

        self.text_encrypted = st.ScrolledText(self, width=25, height=10)
        self.text_encrypted.grid(row=2, column=1, padx=5, pady=5)

        Label(self, text="Key: ").grid(row=3, column=0, padx=5, pady=5)

        self.stringVar_key = StringVar()
        self.entry_key = Entry(self, width=50, textvariable=self.stringVar_key)
        self.entry_key.grid(row=4, column=0, columnspan=2, padx=5, pady=5)
        self.entry_key.focus()

        Button(self, text="Random Key",
               command=self.random_key).grid(row=3, column=1)

        Button(self, text="GO!!", width=30, command=self.handle_buttonGo).grid(
            row=5, column=0, columnspan=2)

    def random_key(self):
        self.stringVar_key.set(Fernet.generate_key().decode("utf-8"))
        messagebox.showwarning("IMPORTANT", "Keep secret this key!!")

    def handle_buttonGo(self):
        if self.radio_var.get() == 1:
            # print("Encrypt")
            plain_text = self.text_plain.get(1.0, END)
            try:
                self.ferni = Fernet(bytes(self.stringVar_key.get(), "utf-8"))
                encrypted_text = self.ferni.encrypt(bytes(plain_text, "utf-8"))
                self.text_encrypted.delete(1.0, END)
                self.text_encrypted.insert(
                    INSERT, encrypted_text.decode("utf-8"))
            except:
                messagebox.showerror(
                    "Invalid Token", "The key or the token is incorrect")

        elif self.radio_var.get() == 2:
            # print("Decrypt")
            encrypted_text = self.text_encrypted.get(1.0, END)
            try:
                self.ferni = Fernet(bytes(self.stringVar_key.get(), "utf-8"))
                plain_text = self.ferni.decrypt(bytes(encrypted_text, "utf-8"))
                self.text_plain.delete(1.0, END)
                self.text_plain.insert(INSERT, plain_text.decode("utf-8"))
            except:
                messagebox.showerror(
                    "Invalid Token", "The key or the token is incorrect")


if __name__ == "__main__":
    window = Window()
    window.mainloop()
