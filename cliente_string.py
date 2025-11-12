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

