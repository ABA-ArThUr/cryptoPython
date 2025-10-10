# gui.py

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import base64

# Importer les fonctions du dépôt existant
import aesgestion
import rsagestion
import hashgestion

class CryptoGUI:
    def __init__(self, root):
        root.title("CryptoPython GUI")
        self.root = root

        self.tab_control = ttk.Notebook(root)

        self.tab_aes = ttk.Frame(self.tab_control)
        self.tab_rsa = ttk.Frame(self.tab_control)
        self.tab_hash = ttk.Frame(self.tab_control)

        self.tab_control.add(self.tab_aes, text="AES")
        self.tab_control.add(self.tab_rsa, text="RSA")
        self.tab_control.add(self.tab_hash, text="Hash")

        self.tab_control.pack(expand=1, fill="both")

        self.build_aes_tab()
        self.build_rsa_tab()
        self.build_hash_tab()

    def build_aes_tab(self):
        frame = self.tab_aes
        ttk.Label(frame, text="Clé AES (base64) :").grid(row=0, column=0, sticky="w")
        self.aes_key_entry = ttk.Entry(frame, width=50)
        self.aes_key_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(frame, text="Texte / Cipher :").grid(row=1, column=0, sticky="nw")
        self.aes_input = scrolledtext.ScrolledText(frame, width=60, height=10)
        self.aes_input.grid(row=1, column=1, padx=5, pady=5)

        btn_encrypt = ttk.Button(frame, text="Chiffrer", command=self.aes_encrypt)
        btn_encrypt.grid(row=2, column=0, padx=5, pady=5)
        btn_decrypt = ttk.Button(frame, text="Déchiffrer", command=self.aes_decrypt)
        btn_decrypt.grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(frame, text="Résultat :").grid(row=3, column=0, sticky="nw")
        self.aes_output = scrolledtext.ScrolledText(frame, width=60, height=10)
        self.aes_output.grid(row=3, column=1, padx=5, pady=5)

    def aes_encrypt(self):
        try:
            key_b64 = self.aes_key_entry.get().strip()
            key = base64.b64decode(key_b64)
            plaintext = self.aes_input.get("1.0", tk.END).encode()
            # Appel à la fonction du dépôt existant
            ciphertext = aesgestion.encrypt_aes(key, plaintext)
            # On encode le résultat en base64 pour l’afficher
            ct_b64 = base64.b64encode(ciphertext).decode()
            self.aes_output.delete("1.0", tk.END)
            self.aes_output.insert(tk.END, ct_b64)
        except Exception as e:
            messagebox.showerror("Erreur chiffrement AES", str(e))

    def aes_decrypt(self):
        try:
            key_b64 = self.aes_key_entry.get().strip()
            key = base64.b64decode(key_b64)
            ct_b64 = self.aes_input.get("1.0", tk.END).strip()
            ciphertext = base64.b64decode(ct_b64)
            plaintext = aesgestion.decrypt_aes(key, ciphertext)
            self.aes_output.delete("1.0", tk.END)
            # Afficher le plaintext déchiffré (décodé en UTF‑8)
            self.aes_output.insert(tk.END, plaintext.decode(errors="ignore"))
        except Exception as e:
            messagebox.showerror("Erreur déchiffrement AES", str(e))

    def build_rsa_tab(self):
        frame = self.tab_rsa
        ttk.Label(frame, text="Clé privée PEM :").grid(row=0, column=0, sticky="nw")
        self.rsa_priv = scrolledtext.ScrolledText(frame, width=60, height=10)
        self.rsa_priv.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(frame, text="Clé publique PEM :").grid(row=1, column=0, sticky="nw")
        self.rsa_pub = scrolledtext.ScrolledText(frame, width=60, height=10)
        self.rsa_pub.grid(row=1, column=1, padx=5, pady=5)

        btn_gen = ttk.Button(frame, text="Générer clés", command=self.rsa_generate)
        btn_gen.grid(row=2, column=0, padx=5, pady=5)

        ttk.Label(frame, text="Texte / Cipher :").grid(row=3, column=0, sticky="nw")
        self.rsa_input = scrolledtext.ScrolledText(frame, width=60, height=5)
        self.rsa_input.grid(row=3, column=1, padx=5, pady=5)

        btn_encrypt = ttk.Button(frame, text="Chiffrer", command=self.rsa_encrypt)
        btn_encrypt.grid(row=4, column=0, padx=5, pady=5)
        btn_decrypt = ttk.Button(frame, text="Déchiffrer", command=self.rsa_decrypt)
        btn_decrypt.grid(row=4, column=1, padx=5, pady=5)

        ttk.Label(frame, text="Résultat :").grid(row=5, column=0, sticky="nw")
        self.rsa_output = scrolledtext.ScrolledText(frame, width=60, height=5)
        self.rsa_output.grid(row=5, column=1, padx=5, pady=5)

    def rsa_generate(self):
        priv_pem, pub_pem = rsagestion.generate_rsa_keys_pem()
        self.rsa_priv.delete("1.0", tk.END)
        self.rsa_pub.delete("1.0", tk.END)
        self.rsa_priv.insert(tk.END, priv_pem.decode())
        self.rsa_pub.insert(tk.END, pub_pem.decode())

    def rsa_encrypt(self):
        try:
            pub_pem = self.rsa_pub.get("1.0", tk.END).encode()
            plaintext = self.rsa_input.get("1.0", tk.END).encode()
            ciphertext = rsagestion.encrypt_rsa(pub_pem, plaintext)
            ct_b64 = base64.b64encode(ciphertext).decode()
            self.rsa_output.delete("1.0", tk.END)
            self.rsa_output.insert(tk.END, ct_b64)
        except Exception as e:
            messagebox.showerror("Erreur chiffrement RSA", str(e))

    def rsa_decrypt(self):
        try:
            priv_pem = self.rsa_priv.get("1.0", tk.END).encode()
            ct_b64 = self.rsa_input.get("1.0", tk.END).strip()
            ciphertext = base64.b64decode(ct_b64)
            plaintext = rsagestion.decrypt_rsa(priv_pem, ciphertext)
            self.rsa_output.delete("1.0", tk.END)
            self.rsa_output.insert(tk.END, plaintext.decode(errors="ignore"))
        except Exception as e:
            messagebox.showerror("Erreur déchiffrement RSA", str(e))

    def build_hash_tab(self):
        frame = self.tab_hash
        ttk.Label(frame, text="Données à hasher :").grid(row=0, column=0, sticky="nw")
        self.hash_input = scrolledtext.ScrolledText(frame, width=60, height=10)
        self.hash_input.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(frame, text="Algorithme :").grid(row=1, column=0, sticky="w")
        self.hash_algo = ttk.Combobox(frame, values=["sha256", "sha512"])
        self.hash_algo.current(0)
        self.hash_algo.grid(row=1, column=1, sticky="w", padx=5, pady=5)

        btn_hash = ttk.Button(frame, text="Hasher", command=self.do_hash)
        btn_hash.grid(row=2, column=0, padx=5, pady=5)

        ttk.Label(frame, text="Résultat :").grid(row=3, column=0, sticky="nw")
        self.hash_output = scrolledtext.ScrolledText(frame, width=60, height=5)
        self.hash_output.grid(row=3, column=1, padx=5, pady=5)

    def do_hash(self):
        try:
            data = self.hash_input.get("1.0", tk.END).encode()
            algo = self.hash_algo.get()
            if algo == "sha256":
                h = hashgestion.hash_sha256(data)
            else:
                h = hashgestion.hash_sha512(data)
            self.hash_output.delete("1.0", tk.END)
            self.hash_output.insert(tk.END, h.hex())
        except Exception as e:
            messagebox.showerror("Erreur hash", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    gui = CryptoGUI(root)
    root.mainloop()
