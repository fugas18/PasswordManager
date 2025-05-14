import os
import json
import random
import string
import pyperclip
from cryptography.fernet import Fernet, InvalidToken
import tkinter as tk
from tkinter import messagebox, simpledialog, Toplevel, Label, Button, filedialog
import base64
import re  # Para verificar a força da palavra-passe


# Arquivos
ARQUIVO_CHAVE = "key.key"
FICHEIRO_DADOS = "passwords.json"

MASTER_PASSWORD_ENCODED = "MTIzNA=="  

MAX_TENTATIVAS = 3

# ----------------------- PASSWORD MESTRE -----------------------
def verificar_password_mestre(max_tentativas=MAX_TENTATIVAS):
    password_real = base64.b64decode(MASTER_PASSWORD_ENCODED).decode()

    for tentativa in range(1, max_tentativas + 1):
        entrada = simpledialog.askstring("Password Mestre", f"Tentativa {tentativa}/{max_tentativas}\nInsira a password mestre:", show="*")
        if entrada is None:
            exit()  # O utilizador cancelou
        if entrada == password_real:
            return  # Autenticado com sucesso
        else:
            messagebox.showerror("Erro", "Password incorreta!")
    messagebox.showerror("Bloqueado", "Número máximo de tentativas excedido. O programa será encerrado.")
    exit()
# --------------------------------------------------------------

# Função para carregar a chave
def carregar_chave(caminho_ficheiro):
    try:
        with open(caminho_ficheiro, "rb") as arquivo_chave:
            chave = arquivo_chave.read()
        Fernet(chave)  # Valida a chave
        return chave
    except (FileNotFoundError, InvalidToken, ValueError):
        messagebox.showerror("Erro", "O ficheiro de chave é inválido!")
        exit()

# Selecionar ficheiro .key
def selecionar_arquivo_chave():
    caminho = filedialog.askopenfilename(
        title="Selecionar ficheiro key.key",
        filetypes=[("Ficheiros de Chave", "*.key")]
    )
    if not caminho:
        messagebox.showerror("Erro", "Nenhum ficheiro selecionado.")
        exit()
    return caminho

# GUI inicial oculta até autenticação ser validada
root = tk.Tk()
root.withdraw()

# Verifica a password mestre antes de qualquer ação
verificar_password_mestre()

# Carrega a chave e inicializa a cifra
def gerar_nova_chave():
    chave = Fernet.generate_key()
    with open(ARQUIVO_CHAVE, "wb") as f:
        f.write(chave)
    messagebox.showinfo("Chave Gerada", f"Nova chave criada e salva como '{ARQUIVO_CHAVE}'.")
    return chave

# Pergunta se deseja gerar uma nova chave
resposta = messagebox.askyesno("Chave de Segurança", "Deseja gerar uma nova chave de segurança?")

if resposta:
    chave = gerar_nova_chave()
else:
    caminho_chave = selecionar_arquivo_chave()
    chave = carregar_chave(caminho_chave)

cifra = Fernet(chave)



# Mostra a janela principal após autenticação
root.deiconify()
root.title("Gestor de Palavras-Passe")
root.geometry("300x400")
root.resizable(False, False)  # Impede que a janela seja redimensionada

# ------------------- Funções auxiliares ---------------------
def carregar_palavras_passe():
    if os.path.exists(FICHEIRO_DADOS):
        with open(FICHEIRO_DADOS, "r") as ficheiro:
            return json.load(ficheiro)
    return {}

def salvar_palavras_passe(dados):
    with open(FICHEIRO_DADOS, "w") as ficheiro:
        json.dump(dados, ficheiro, indent=4)

def gerar_palavra_passe_aleatoria(tamanho=12):
    caracteres = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(caracteres) for _ in range(tamanho))

# Função para verificar a força da palavra-passe
def verificar_forca_palavra_passe(palavra_passe):
    if len(palavra_passe) < 8:
        return "Fraca"
    elif len(palavra_passe) < 12:
        return "Média"
    else:
        if (re.search(r'[A-Z]', palavra_passe) and 
            re.search(r'[a-z]', palavra_passe) and 
            re.search(r'\d', palavra_passe) and 
            re.search(r'[!@#$%^&*(),.?":{}|<>]', palavra_passe)):
            return "Forte"
        return "Média"

# ------------------- Funções principais ---------------------
def adicionar_palavra_passe():
    servico = campo_servico.get().strip()
    utilizador = campo_utilizador.get().strip()
    palavra_passe = campo_palavra_passe.get().strip()

    if not servico or not utilizador or not palavra_passe:
        messagebox.showerror("Erro", "Todos os campos são obrigatórios!")
        return

    dados = carregar_palavras_passe()
    if servico not in dados:
        dados[servico] = {}

    dados[servico][utilizador] = cifra.encrypt(palavra_passe.encode()).decode()
    salvar_palavras_passe(dados)

    campo_servico.delete(0, tk.END)
    campo_utilizador.delete(0, tk.END)
    campo_palavra_passe.delete(0, tk.END)

    messagebox.showinfo("Sucesso", "Palavra-passe salva com sucesso.")

def recuperar_palavra_passe():
    servico = campo_servico.get().strip()
    utilizador = campo_utilizador.get().strip()
    dados = carregar_palavras_passe()

    if servico in dados:
        if utilizador and utilizador in dados[servico]:
            mostrar_palavra(dados[servico][utilizador])
        elif not utilizador:
            utilizadores = list(dados[servico].keys())
            if len(utilizadores) == 1:
                mostrar_palavra(dados[servico][utilizadores[0]])
            else:
                selecionado = simpledialog.askstring("Selecionar Utilizador", "\n".join(utilizadores))
                if selecionado in dados[servico]:
                    mostrar_palavra(dados[servico][selecionado])
                else:
                    messagebox.showerror("Erro", "Utilizador não encontrado.")
        else:
            messagebox.showerror("Erro", "Utilizador não encontrado.")
    else:
        messagebox.showerror("Erro", "Serviço não encontrado.")

def mostrar_palavra(p_encriptada):
    try:
        palavra = cifra.decrypt(p_encriptada.encode()).decode()
    except InvalidToken:
        messagebox.showerror("Erro", "Erro ao desencriptar palavra-passe.")
        return
    janela = Toplevel(root)
    janela.title("Palavra-passe")
    janela.geometry("300x150")
    Label(janela, text=f"Palavra-passe: {palavra}", font=("Arial", 12)).pack(pady=10)
    Button(janela, text="Copiar", command=lambda: pyperclip.copy(palavra)).pack(pady=5)
    Button(janela, text="OK", command=janela.destroy).pack(pady=5)

# ------------------- Interface gráfica ---------------------
tk.Label(root, text="Serviço:").pack()
campo_servico = tk.Entry(root)
campo_servico.pack()

tk.Label(root, text="Utilizador:").pack()
campo_utilizador = tk.Entry(root)
campo_utilizador.pack()

tk.Label(root, text="Palavra-passe:").pack()
campo_palavra_passe = tk.Entry(root, show="*")
campo_palavra_passe.pack()

tk.Button(root, text="Gerar Palavra-Passe Aleatória", 
          command=lambda: gerar_e_atualizar_forca()).pack(pady=5)
tk.Button(root, text="Guardar Palavra-Passe", command=adicionar_palavra_passe).pack(pady=5)
tk.Button(root, text="Recuperar Palavra-Passe", command=recuperar_palavra_passe).pack(pady=5)

# Exibição da força da palavra-passe
tk.Label(root, text="Força da palavra-passe:").pack()
campo_forca = tk.Label(root, text="Fraca", fg="red")
campo_forca.pack()

campo_palavra_passe.bind("<KeyRelease>", lambda event: atualizar_forca())

# Função que atualiza a força da palavra-passe
def atualizar_forca():
    forca = verificar_forca_palavra_passe(campo_palavra_passe.get())
    campo_forca.config(text=forca, fg="green" if forca == "Forte" else "red")

# Função que gera a senha e atualiza a força
def gerar_e_atualizar_forca():
    nova_senha = gerar_palavra_passe_aleatoria()
    campo_palavra_passe.delete(0, tk.END)
    campo_palavra_passe.insert(0, nova_senha)
    atualizar_forca()

root.mainloop()
