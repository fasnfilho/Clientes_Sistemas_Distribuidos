#Cliente para o protocolo Strings
#Autor: Fábio Agostinho da Silva Nascimento Filho (Matrícula: 538521)
#Servidor: 3.88.99.255:8080

import socket
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime
import hashlib

SERVER_IP = "3.88.99.255"
SERVER_PORT = 8080
ENCODING = "utf-8"

def extrair_token_da_resposta(resposta: str):
    if not resposta:
        return None
    for parte in resposta.split("|"):
        if parte.startswith("token="):
            return parte.split("=", 1)[1]
    return None


def gerar_timestamp():
    return datetime.now().isoformat(timespec="seconds")

def enviar_mensagem(sock, mensagem):
    sock.sendall((mensagem + '\n').encode(ENCODING))
    resposta = sock.recv(4096).decode(ENCODING)
    return resposta.strip()

def md5_hash(texto):
    return hashlib.md5(texto.encode()).hexdigest()

class ClienteStringsApp:

    def __init__(self, root):
        self.root = root
        self.root.title("Cliente Strings")
        self.root.geometry("750x600")
        self.root.resizable(False, False)

        self.sock = None
        self.token = None
        self.matricula = "538521"

        self.criar_interface()
    
    def criar_interface(self):
        abas = ttk.Notebook(self.root)
        abas.pack(fill="both", expand=True, padx=10, pady=10)

        self.frame_login = ttk.Frame(abas)
        self.frame_ops = ttk.Frame(abas)
        self.frame_logs = ttk.Frame(abas)

        abas.add(self.frame_login, text="Login")
        abas.add(self.frame_ops, text="Operações")
        abas.add(self.frame_logs, text="Logs")

        ttk.Label(self.frame_login, text="Matrícula:", font=("Arial", 12)).pack(pady=10)
        self.entry_matricula = ttk.Entry(self.frame_login, font=("Arial", 12), width=20)
        self.entry_matricula.insert(0, self.matricula)
        self.entry_matricula.pack()

        ttk.Button(self.frame_login, text="Conectar e Autenticar", command=self.autenticar).pack(pady=20)

        ops_frame = ttk.LabelFrame(self.frame_ops, text="Operações Disponíveis", padding=10)
        ops_frame.pack(fill="both", expand=True, padx=10, pady=10)

        ttk.Button(ops_frame, text="Echo", width=25, command=self.op_echo).pack(pady=5)
        ttk.Button(ops_frame, text="Soma", width=25, command=self.op_soma).pack(pady=5)
        ttk.Button(ops_frame, text="Timestamp", width=25, command=self.op_timestamp).pack(pady=5)
        ttk.Button(ops_frame, text="Status", width=25, command=self.op_status).pack(pady=5)
        ttk.Button(ops_frame, text="Histórico", width=25, command=self.op_historico).pack(pady=5)
        ttk.Button(ops_frame, text="Logout", width=25, command=self.op_logout).pack(pady=5)

        ttk.Label(self.frame_logs, text="Logs de Requisições e Respostas:", font=("Arial", 12, "bold")).pack(pady=5)
        self.text_logs = scrolledtext.ScrolledText(self.frame_logs, width=85, height=30, state="disabled")
        self.text_logs.pack(padx=10, pady=10)

    def log(self, msg):
        self.text_logs.config(state="normal")
        self.text_logs.insert(tk.END, f"[{gerar_timestamp()}] {msg}\n")
        self.text_logs.config(state="disabled")
        self.text_logs.yview(tk.END)
    
    def conectar(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((SERVER_IP, SERVER_PORT))
            self.log(f"Conectado a {SERVER_IP}:{SERVER_PORT}")
            return sock
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao conectar: {e}")
            self.log(f"Erro de conexão: {e}")
            return None
    
    def autenticar(self):
        self.sock = self.conectar()
        if not self.sock:
            return
        matricula = self.entry_matricula.get().strip()
        msg = f"AUTH|aluno_id={matricula}|timestamp={gerar_timestamp()}|FIM"
        self.log(f"->{msg}")
        try:
            resposta = enviar_mensagem(self.sock, msg)
            self.log(f"<-{resposta}")
            token = extrair_token_da_resposta(resposta)
            if "OK" in resposta or "token" in resposta.lower():
                self.token = token
                messagebox.showinfo("Autenticação", "Autenticação realizada com sucesso!")
                self.log(f"Token recebido: {token}")
            else:
                messagebox.showerror("Falha", f"Resposta inesperada: {resposta}")
        except Exception as e:
            messagebox.showerror("Erro", str(e))
            self.log(f"Erro na autenticação: {e}")
    
