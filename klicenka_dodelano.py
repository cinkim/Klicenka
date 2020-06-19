import base64
import os

import tkinter as tk
import tkinter.messagebox
from tkinter import ttk, StringVar
from tkinter import LEFT, NO, DISABLED, NORMAL

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Klicenka:

    def __init__(self):
        self.odemceno = False
        self.zaznamy = []
        self.nazev_soubor = "klicenka.tja"
        self.nacti()
        self.pocet_pokusu = 0



    def odemknout(self, hlavni_heslo):
        self.klic = self._priprav_klic(hlavni_heslo)
        try:
            if self.pocet_pokusu < 3:
                self._odsifruj()
            else:
                self.znicit_data()
                tk.messagebox.showwarning("Data", "Poškozená data.")
                os._exit(0)
        except InvalidToken:
            self.klic = ""
            self.pocet_pokusu = self.pocet_pokusu + 1
            tk.messagebox.showwarning("Smula", "Špatné heslo")
            return False

        self.odemceno = True


    def znicit_data(self):
        try:
            with open(self.nazev_soubor, "r", encoding="utf-8") as soubor:
                soubor2 = soubor.read()
        except FileNotFoundError:
            return

        soubor2 = soubor2.replace("_", "")
        soubor2 = soubor2.replace(" ", "")
        soubor2 = soubor2.replace("-", "")
        with open(self.nazev_soubor, mode="w", encoding="utf-8") as soubor_poskodit:
            print(soubor2, file=soubor_poskodit)
        

    def _odsifruj(self):
        f = Fernet(self.klic)
        ozaznamy = []
        for stranka, jmeno, heslo in self.zaznamy:
            zaznam = (f.decrypt(stranka.encode()).decode("utf-8"),
                      f.decrypt(jmeno.encode()).decode("utf-8"),
                      f.decrypt(heslo.encode()).decode("utf-8"))
            ozaznamy.append(zaznam)
        self.zaznamy = ozaznamy

    def zamknout(self):
        self._zasifruj()
        self.odemceno = False
        self.uloz()
        self.klic = ""

    def _zasifruj(self):
        f = Fernet(self.klic)
        zasifrovane_zaznamy = []
        for stranka, jmeno, heslo in self.zaznamy:
            zasifrovany_zaznam = (f.encrypt(stranka.encode()).decode("utf-8"),
                                  f.encrypt(jmeno.encode()).decode("utf-8"),
                                  f.encrypt(heslo.encode()).decode("utf-8"))
            zasifrovane_zaznamy.append(zasifrovany_zaznam)

        self.zaznamy = zasifrovane_zaznamy

    def pridej_zaznam(self, stranka, jmeno, heslo):
        if not self.odemceno:
            raise IndexError("Klicenka je zamcena")

        self.zaznamy.append((stranka, jmeno, heslo))

    def _priprav_klic(self, heslo):
        salt = b"/*-*/45632"

        kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend())

        return base64.urlsafe_b64encode(kdf.derive(heslo.encode()))

    def uloz(self):
        if self.odemceno:
            self._zasifruj()

        with open(self.nazev_soubor, "w", encoding="utf-8") as soubor:
            for stranka, jmeno, heslo in self.zaznamy:
                print(stranka, jmeno, heslo, file=soubor)

        if self.odemceno:
            self._odsifruj()

    def nacti(self):
        try:
            with open(self.nazev_soubor, "r", encoding="utf-8") as soubor:
                for radka in soubor:
                    self.zaznamy.append(tuple(radka.split()))
        except FileNotFoundError:
            return

    def smaz_heslo(self, pozice):
        self.zaznamy.pop(pozice)


class KlicenkaGUI(tk.Frame):

    def __init__(self, parent, klicenka):
        super().__init__(parent)
        self.parent = parent
        self.klicenka = klicenka
        self.parent.title("Moje klíčenka")
        self.entry_width = 30

        self.parent.protocol("WM_DELETE_WINDOW", self.on_close)
        self.create_widgets()

        self.zobraz()

    def create_widgets(self):
        self.label_vyzva = tk.Label(text="Zadejte hlavní heslo")
        self.label_vyzva.pack()

        self.frame_zadani_hesla = tk.Frame()
        self.frame_zadani_hesla.pack()

        self.master_heslo = StringVar()
        self.entry_master_heslo = tk.Entry(self.frame_zadani_hesla,
                                           textvariable=self.master_heslo)
        self.entry_master_heslo.pack(side=LEFT)

        self.button_odezamknout = tk.Button(self.frame_zadani_hesla,
                                            text="Odemknout",
                                            command=self.odezamkni)
        self.button_odezamknout.pack(side=LEFT)

        # Pridavani zaznamu
        self.frame_zaznam = tk.Frame()
        self.frame_zaznam.pack()

        self.stranka = StringVar()
        self.entry_stranka = tk.Entry(self.frame_zaznam,
                                       width=self.entry_width,
                                       textvariable=self.stranka)
        self.entry_stranka.pack(side=LEFT)

        self.jmeno = StringVar()
        self.entry_jmeno = tk.Entry(self.frame_zaznam,
                                     width=self.entry_width,
                                     textvariable=self.jmeno)
        self.entry_jmeno.pack(side=LEFT)

        self.heslo = StringVar()
        self.entry_heslo = ttk.Entry(self.frame_zaznam,
                                     width=self.entry_width,
                                     textvariable=self.heslo)
        self.entry_heslo.pack(side=LEFT)

        self.pridej_button = ttk.Button(self.frame_zaznam,
                                        text="Přidat",
                                        state=DISABLED,
                                        command=self.on_pridej,
                                        )
        self.pridej_button.pack(side=LEFT)

        self.frame_seznam = tk.Frame()
        self.frame_seznam.pack()

        self.tree_zaznamy = ttk.Treeview(self.frame_seznam,
                                         columns=("stranka",
                                                  "jmeno",
                                                  "heslo"))

        self.tree_zaznamy.heading("#0", text="#")
        self.tree_zaznamy.column("#0", minwidth=0, width=30,
                                 stretch=NO)

        self.tree_zaznamy.heading("stranka", text="Stránka")
        self.tree_zaznamy.column("stranka", minwidth=0, width=200,
                                 stretch=NO)

        self.tree_zaznamy.heading("jmeno", text="Jméno")
        self.tree_zaznamy.column("jmeno", minwidth=0, width=300)

        self.tree_zaznamy.heading("heslo", text="Heslo")
        self.tree_zaznamy.column("heslo", minwidth=0, width=300)
        self.tree_zaznamy.pack()

         # Mazani zaznamu
        self.frame_seznam_tlacitka = tk.Frame()
        self.frame_seznam_tlacitka.pack()
        self.smaz_button = ttk.Button(self.frame_seznam_tlacitka,
                                      text="Smazat záznam",
                                      state=DISABLED,
                                      command=self.on_smaz)
        self.smaz_button.pack()

    def on_smaz(self):
        if self.tree_zaznamy.focus():
            pozice = self.tree_zaznamy.focus() # tuhle funkci jse řešil 14 dní
            # print(pozice)
            pozice = self.tree_zaznamy.item(pozice)
            # print(pozice)
            pozice = pozice["text"]
            # print(pozice)
            pozice = int(pozice)
            self.klicenka.smaz_heslo(pozice)
            self.zobraz()

    def odezamkni(self):
        if self.klicenka.odemceno:
            self.entry_master_heslo.config(state=NORMAL)
            self.klicenka.zamknout()
            self.button_odezamknout.config(text="Odemknout")
            self.master_heslo.set("")
            self.pridej_button.config(state=DISABLED)
            self.smaz_button.config(state=DISABLED)
            self.zobraz()
            self.klicenka.pocet_pokusu = 0
        else: # je zamceno
            if self.master_heslo.get() == "":
                return
            else:
                while True:
                    self.klicenka.odemknout(self.master_heslo.get())
                    if self.klicenka.odemceno == True:
                        self.button_odezamknout.config(text="Zamknout")
                        self.pridej_button.config(state=NORMAL)
                        self.smaz_button.config(state=NORMAL)
                        self.entry_master_heslo.config(state=DISABLED)
                        self.zobraz()
                        break
                    else:
                        self.master_heslo.set("")
                        break

        # print(f"Hlavni heslo: {self.master_heslo.get()}")

    def on_pridej(self):
        self.klicenka.pridej_zaznam(
                                self.stranka.get(),
                                self.jmeno.get(),
                                self.heslo.get())
        """
        print(f"Stranka {self.stranka.get()}")
        print(f"Jmeno {self.jmeno.get()}")
        print(f"Heslo {self.heslo.get()}")
        """
        self.zobraz()

        # self.klicenka.pridej_zaznam(zaznam)
        self.stranka.set("")
        self.jmeno.set("")
        self.heslo.set("")
        self.zobraz()

    def on_close(self):
        self.klicenka.uloz()
        self.parent.destroy()

    def zobraz(self):
        for pot in self.tree_zaznamy.get_children():
            self.tree_zaznamy.delete(pot)

        pozice = 0   
        for stranka, jmeno, heslo in self.klicenka.zaznamy:
            self.tree_zaznamy.insert("", "end", text=pozice, values=(stranka, jmeno, heslo))
            pozice += 1
            


if __name__ == '__main__':
    root = tk.Tk()
    klicenka = Klicenka()
    app = KlicenkaGUI(root, klicenka)
    app.mainloop()