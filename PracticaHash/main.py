from tkinter import *
from tkinter import filedialog
from tkinter import font
from tkinter import messagebox
import hashlib

class Window(Tk):
    def __init__(self):
        super().__init__()
        self.title("SHA-256")
        self.default_font = font.Font(font=("Ubuntu", 12), name="TkDefaultFont", exists=TRUE)
        self.option_add("*Font", self.default_font)

        Label(self, text="Seleccionar archivo: ").grid(row=0, column=0, pady=10, sticky=W)
        self.str_filename = StringVar(self)
        self.select_button = Button(self, text="Select", command=self.handleSelect)
        Label(self, textvariable=self.str_filename).grid(row=0, column=1, sticky=W, ipadx=40)
        self.select_button.grid(row=0, column=2, sticky=E,ipadx=10)

        self.complete_filename = StringVar(self)

        self.generate_button = Button(self, text="Generar Hash", command=self.handleGenerate)
        self.generate_button.grid(row=1, column=1, ipadx=40)

        self.generate_button = Button(self, text="Verificar Hash", command=self.handleCheck)
        self.generate_button.grid(row=2, column=1, ipadx=40)

    def handleSelect(self):
        file = filedialog.askopenfile(initialdir=".", title="Select Image", filetypes=((("Text files","*.txt"),("all files","*.*"))))
        try: 
            self.complete_filename.set(file.name)
            filename = file.name.split("/")
            self.str_filename.set(filename[-1])
        except:
            self.str_filename.set("")
            self.complete_filename.set("")


    def handleGenerate(self):
        if not self.complete_filename.get():
            messagebox.showerror(title="ERROR", message="Primero selecciona el archivo")
            return False

        with open(self.complete_filename.get(), "r") as file:
            plain_text = file.read()
            aux = plain_text.split("\n")
            binary_text = bytes("".join(aux), "utf-8")

        h1 = hashlib.sha1(binary_text)

        new_text = plain_text + "\n\n===SHA-1===\n" + h1.hexdigest()

        saved_file = filedialog.asksaveasfile(initialdir=".", title="Save Image", filetypes=((("Text files","*.txt"),("all files","*.*"))))

        if not saved_file:
            messagebox.showerror(title="ERROR", message="No se pudo guardar el archivo. Intentalo de nuevo")
            return False

        with open(saved_file.name, "w") as file:
            file.write(new_text)

        messagebox.showinfo(title="DONE", message="Se guardó el archivo con éxito :D")


    def handleCheck(self):
        if not self.complete_filename.get():
            messagebox.showerror(title="ERROR", message="Primero selecciona el archivo")
            return False

        with open(self.complete_filename.get(), "r") as file:
            complete_text = file.read().split("\n")
            text = complete_text[:-3]
            text_to_hash = bytes("".join(text), "utf-8")

        new_hash = hashlib.sha1(text_to_hash).hexdigest()
        origin_hash = complete_text[-1]

        if new_hash == origin_hash:
            messagebox.showinfo(title="Correcto", message=f"Los hash son correctos :D\n\nHash encontrado\n{origin_hash}\nHash  calculado:\n{new_hash}")
        else:
            messagebox.showerror(title="Error", message=f"Los hash son diferentes :0\n\nHash encontrado:\n{origin_hash}\nHash  calculado:\n{new_hash}")


if __name__ == "__main__":
    window = Window()
    window.mainloop()