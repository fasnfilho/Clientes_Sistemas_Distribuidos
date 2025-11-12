#Cliente JSON - Sistemas Distribuídos
#HTTP POST -> http://3.88.99.255:8081/

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime
from typing import Optional, Any, Dict
import http.client
import json

SERVER_IP = "3.88.99.255"
SERVER_PORT = 8081
TIMEOUT = 6  # segundos

def gerar_timestamp() -> str:
    return datetime.now().isoformat(timespec="seconds")


def extrair_token_resposta_json(resp_json: Dict[str, Any]) -> Optional[str]:
    if not isinstance(resp_json, dict):
        return None
    dados = resp_json.get("dados", {})
    if isinstance(dados, dict):
        return dados.get("token")
    return None


class ClienteJSONApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Cliente JSON - Sistemas Distribuídos")
        self.root.geometry("760x620")
        self.root.resizable(False, False)

        self.token: Optional[str] = None
        self.default_matricula = "538521"

        self._build_ui()

    def _build_ui(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=8, pady=8)

        self.frame_login = ttk.Frame(nb)
        self.frame_ops = ttk.Frame(nb)
        self.frame_logs = ttk.Frame(nb)

        nb.add(self.frame_login, text="Login")
        nb.add(self.frame_ops, text="Operações")
        nb.add(self.frame_logs, text="Logs")

        # Login
        ttk.Label(self.frame_login, text="Matrícula:", font=("Segoe UI", 11)).pack(pady=(20, 6))
        entry_frame = ttk.Frame(self.frame_login)
        entry_frame.pack()
        self.entry_matricula = ttk.Entry(entry_frame, font=("Segoe UI", 11), width=22)
        self.entry_matricula.insert(0, self.default_matricula)
        self.entry_matricula.pack(side="left", padx=(0, 6))

        btn_auth = ttk.Button(entry_frame, text="Autenticar (AUTH)", command=self.autenticar)
        btn_auth.pack(side="left")

        ttk.Label(self.frame_login, text=f"HTTP POST -> {SERVER_IP}:{SERVER_PORT}", font=("Segoe UI", 9, "italic")).pack(pady=(12, 0))

        # Operações
        ops_frame = ttk.LabelFrame(self.frame_ops, text="Operações", padding=12)
        ops_frame.pack(fill="both", expand=False, padx=12, pady=12)

        # Buttons
        btn_echo = ttk.Button(ops_frame, text="Echo", command=self.op_echo, width=28)
        btn_echo.grid(row=0, column=0, padx=6, pady=6)
        btn_soma = ttk.Button(ops_frame, text="Soma", command=self.op_soma, width=28)
        btn_soma.grid(row=0, column=1, padx=6, pady=6)
        btn_timestamp = ttk.Button(ops_frame, text="Timestamp", command=self.op_timestamp, width=28)
        btn_timestamp.grid(row=1, column=0, padx=6, pady=6)
        btn_status = ttk.Button(ops_frame, text="Status", command=self.op_status, width=28)
        btn_status.grid(row=1, column=1, padx=6, pady=6)
        btn_historico = ttk.Button(ops_frame, text="Histórico", command=self.op_historico, width=28)
        btn_historico.grid(row=2, column=0, padx=6, pady=6)
        btn_logout = ttk.Button(ops_frame, text="Logout", command=self.logout, width=28)
        btn_logout.grid(row=2, column=1, padx=6, pady=6)

        ttk.Label(self.frame_ops, text="Use as operações após autenticar (token será inserido automaticamente).",
                  font=("Segoe UI", 9)).pack(pady=(6, 0))

        ttk.Label(self.frame_logs, text="Logs (somente nesta aba):", font=("Segoe UI", 11, "bold")).pack(pady=(8, 2))
        self.text_logs = scrolledtext.ScrolledText(self.frame_logs, width=92, height=30, state="disabled", font=("Consolas", 10))
        self.text_logs.pack(padx=8, pady=8)

    def log(self, msg: str):
        ts = gerar_timestamp()
        self.text_logs.config(state="normal")
        self.text_logs.insert(tk.END, f"[{ts}] {msg}\n")
        self.text_logs.config(state="disabled")
        self.text_logs.yview(tk.END)

    def post_json(self, payload: dict) -> dict:
        try:
            body = json.dumps(payload)
            headers = {
                "Content-Type": "application/json",
                "Content-Length": str(len(body.encode("utf-8")))
            }

            conn = http.client.HTTPConnection(SERVER_IP, SERVER_PORT, timeout=TIMEOUT)
            self.log(f"->{body}")
            conn.request("POST", "/", body, headers)
            resp = conn.getresponse()
            text = resp.read().decode("utf-8", errors="replace")
            conn.close()

            try:
                js = json.loads(text)
                self.log(f"<-{json.dumps(js, ensure_ascii=False)}")
                return js
            except json.JSONDecodeError:
                self.log(f"Resposta (texto): {text}")
                raise RuntimeError("Resposta não é JSON válido")
        except Exception as e:
            self.log(f"Erro HTTP: {e}")
            raise

    def autenticar(self):
        matricula = self.entry_matricula.get().strip()
        if not matricula:
            messagebox.showwarning("Matrícula", "Informe a matrícula antes de autenticar.")
            return

        payload = {
            "comando": "AUTH",
            "dados": {
                "aluno_id": matricula
            },
            "timestamp": gerar_timestamp()
        }

        try:
            js = self.post_json(payload)
        except Exception as exc:
            messagebox.showerror("Erro", f"Falha no AUTH: {exc}")
            return

        # extrair token
        token = extrair_token_resposta_json(js)
        if token:
            self.token = token
            messagebox.showinfo("Autenticação", "Autenticação realizada com sucesso.")
            self.log(f"Token recebido: {token}")
        else:
            if isinstance(js, dict) and js.get("status", "").upper() == "OK":
                messagebox.showinfo("Autenticação", "Autenticado (OK), mas token não foi encontrado.")
            else:
                messagebox.showerror("Autenticação", f"Falha: resposta inesperada:\n{js}")

