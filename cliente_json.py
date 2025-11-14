import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime
import json
import socket

SERVER_IP = "3.88.99.255"
SERVER_PORT = 8081
TIMEOUT = 6


def gerar_timestamp():
    return datetime.now().isoformat(timespec="seconds")


class ClienteJSONApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cliente JSON - Sistemas Distribuídos")
        self.root.geometry("760x620")
        self.root.resizable(False, False)

        self.token = None
        self.default_matricula = "538521"

        self.build_ui()

    # ------------------------------------------------------
    def build_ui(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=8, pady=8)

        self.tab_login = ttk.Frame(nb)
        self.tab_ops = ttk.Frame(nb)
        self.tab_logs = ttk.Frame(nb)

        nb.add(self.tab_login, text="Login")
        nb.add(self.tab_ops, text="Operações")
        nb.add(self.tab_logs, text="Logs")

        # LOGIN
        ttk.Label(self.tab_login, text="Matrícula:", font=("Segoe UI", 11)).pack(pady=(20, 6))

        fr = ttk.Frame(self.tab_login)
        fr.pack()

        self.entry_matricula = ttk.Entry(fr, width=22, font=("Segoe UI", 11))
        self.entry_matricula.insert(0, self.default_matricula)
        self.entry_matricula.pack(side="left", padx=(0, 6))

        ttk.Button(fr, text="Autenticar", command=self.autenticar).pack(side="left")

        # OPERACOES
        ops = ttk.LabelFrame(self.tab_ops, text="Operações", padding=12)
        ops.pack(fill="both", expand=False, padx=12, pady=12)

        ttk.Button(ops, text="Echo", width=28, command=self.op_echo).grid(row=0, column=0, padx=6, pady=6)
        ttk.Button(ops, text="Soma", width=28, command=self.op_soma).grid(row=0, column=1, padx=6, pady=6)
        ttk.Button(ops, text="Timestamp", width=28, command=self.op_timestamp).grid(row=1, column=0, padx=6, pady=6)
        ttk.Button(ops, text="Status (info)", width=28, command=self.op_status).grid(row=1, column=1, padx=6, pady=6)
        ttk.Button(ops, text="Histórico", width=28, command=self.op_historico).grid(row=2, column=0, padx=6, pady=6)
        ttk.Button(ops, text="Logout", width=28, command=self.logout).grid(row=2, column=1, padx=6, pady=6)

        # LOGS
        ttk.Label(self.tab_logs, text="Logs:", font=("Segoe UI", 11, "bold")).pack(pady=(8, 2))
        self.text_logs = scrolledtext.ScrolledText(
            self.tab_logs, width=92, height=30, font=("Consolas", 10),
            state="disabled"
        )
        self.text_logs.pack(padx=8, pady=8)

    # ------------------------------------------------------
    def log(self, msg: str):
        ts = gerar_timestamp()
        self.text_logs.config(state="normal")
        self.text_logs.insert("end", f"[{ts}] {msg}\n")
        self.text_logs.config(state="disabled")
        self.text_logs.yview("end")

    # ------------------------------------------------------
    # ENVIO TCP
    # ------------------------------------------------------
    def enviar_json_tcp(self, payload: dict) -> dict:
        data = json.dumps(payload).encode("utf-8")

        self.log(f"→ {data.decode()}")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((SERVER_IP, SERVER_PORT))

        sock.sendall(data)

        buffer = b""
        while not buffer.strip().endswith(b"}"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            buffer += chunk
            if len(buffer) > 65536:
                raise RuntimeError("Resposta muito grande (mais de 64KB)")

        sock.close()

        text = buffer.decode("utf-8", errors="replace")
        self.log(f"← {text}")

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            raise RuntimeError("Resposta inválida (JSON corrompido).")

    # ------------------------------------------------------
    # AUTENTICAÇÃO
    # ------------------------------------------------------
    def autenticar(self):
        mat = self.entry_matricula.get().strip()
        if not mat:
            messagebox.showwarning("Aviso", "Informe a matrícula.")
            return

        payload = {
            "tipo": "autenticar",
            "aluno_id": mat,
            "timestamp": gerar_timestamp()
        }

        try:
            resp = self.enviar_json_tcp(payload)
        except Exception as e:
            messagebox.showerror("Erro", f"Falha no AUTH: {e}")
            return

        if resp.get("sucesso"):
            self.token = resp.get("token")
            messagebox.showinfo("Sucesso", f"Autenticado!\nToken:\n{self.token}")
        else:
            messagebox.showerror("Erro", resp.get("erro", "Erro desconhecido"))

    # ------------------------------------------------------
    # OPERAÇÕES
    # ------------------------------------------------------
    def enviar_operacao(self, operacao: str, extras: dict):
        if not self.token:
            messagebox.showwarning("Aviso", "Autentique primeiro.")
            return

        payload = {
            "tipo": "operacao",
            "operacao": operacao,
            "token": self.token,
            "timestamp": gerar_timestamp(),
            **extras
        }

        try:
            resp = self.enviar_json_tcp(payload)
        except Exception as e:
            messagebox.showerror("Erro", f"Falha na operação: {e}")
            return

        messagebox.showinfo(
            "Resposta",
            json.dumps(resp, ensure_ascii=False, indent=2)
        )

    # ------------------------------------------------------
    def op_echo(self):
        def enviar():
            msg = entry.get().strip()
            dlg.destroy()
            self.enviar_operacao("echo", {"mensagem": msg})

        dlg = tk.Toplevel(self.root)
        dlg.title("Echo")
        ttk.Label(dlg, text="Mensagem:").pack(padx=6, pady=6)
        entry = ttk.Entry(dlg, width=60)
        entry.pack(padx=6, pady=6)
        ttk.Button(dlg, text="Enviar", command=enviar).pack(pady=10)

    def op_soma(self):
        def enviar():
            txt = entry.get().strip()
            nums = [float(x) for x in txt.split(",")]
            dlg.destroy()
            self.enviar_operacao("soma", {"nums": nums})

        dlg = tk.Toplevel(self.root)
        dlg.title("Soma")
        ttk.Label(dlg, text="Números separados por vírgula:").pack(padx=6, pady=6)
        entry = ttk.Entry(dlg, width=50)
        entry.pack(padx=6, pady=6)
        ttk.Button(dlg, text="Enviar", command=enviar).pack(pady=10)

    def op_timestamp(self):
        self.enviar_operacao("timestamp", {})

    def op_status(self):
        # depende do servidor — pode usar tipo=info
        payload = {
            "tipo": "info",
            "token": self.token,
            "timestamp": gerar_timestamp()
        }
        try:
            resp = self.enviar_json_tcp(payload)
            messagebox.showinfo("Status", json.dumps(resp, ensure_ascii=False, indent=2))
        except Exception as e:
            messagebox.showerror("Erro", f"Falha: {e}")

    def op_historico(self):
        def enviar():
            val = entry.get().strip()
            dlg.destroy()
            if val:
                self.enviar_operacao("historico", {"limite": int(val)})
            else:
                self.enviar_operacao("historico", {})

        dlg = tk.Toplevel(self.root)
        dlg.title("Histórico")
        ttk.Label(dlg, text="Limite (opcional):").pack(padx=6, pady=6)
        entry = ttk.Entry(dlg, width=20)
        entry.pack(padx=6, pady=6)
        ttk.Button(dlg, text="Enviar", command=enviar).pack(pady=10)

    # ------------------------------------------------------
    def logout(self):
        if not self.token:
            messagebox.showinfo("Logout", "Nenhuma sessão ativa.")
            return

        payload = {
            "tipo": "logout",
            "token": self.token,
            "timestamp": gerar_timestamp()
        }

        try:
            resp = self.enviar_json_tcp(payload)
            messagebox.showinfo("Logout", json.dumps(resp, ensure_ascii=False))
        except Exception as e:
            messagebox.showerror("Erro", f"Falha no logout: {e}")
        finally:
            self.token = None


def main():
    root = tk.Tk()
    app = ClienteJSONApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
