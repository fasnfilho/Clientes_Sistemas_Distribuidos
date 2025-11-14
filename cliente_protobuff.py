#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cliente ProtoBuf (Tkinter) - comunicação TCP com messages Protobuf
Requer: sd_protocol_pb2.py gerado a partir de sd_protocol.proto
Geração (exemplo):
    protoc --python_out=. sd_protocol.proto
ou
    python -m grpc_tools.protoc -I. --python_out=. sd_protocol.proto
"""

import socket
import json
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from typing import Optional, Dict, Any

# importe o módulo gerado pelo protoc (certifique-se de ter gerado sd_protocol_pb2.py)
import sd_protocol_pb2

# -----------------------
SERVER_IP = "3.88.99.255"
SERVER_PORT = 8082
TIMEOUT = 6

# Se True envia length-prefix 4 bytes big-endian; se False envia blob + b'FIM'
USE_LENGTH_PREFIX = True

# -----------------------
def gerar_timestamp() -> str:
    return datetime.now().isoformat(timespec="seconds")

# helpers para conversão de protobuf <-> dict (apenas para logs)
def map_to_dict(pb_map) -> Dict[str, str]:
    return {k: v for k, v in pb_map.items()}

def dict_to_map(pb_map, d: Dict[str, str]):
    pb_map.clear()
    for k, v in d.items():
        pb_map[k] = v

# -----------------------
class ClienteProtoApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Cliente ProtoBuf - Sistemas Distribuídos")
        self.root.geometry("760x620")
        self.root.resizable(False, False)

        self.token: Optional[str] = None
        self.default_matricula = "538521"

        self.build_ui()

    # ---------------- UI ----------------
    def build_ui(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=8, pady=8)

        self.tab_login = ttk.Frame(nb)
        self.tab_ops = ttk.Frame(nb)
        self.tab_logs = ttk.Frame(nb)

        nb.add(self.tab_login, text="Login")
        nb.add(self.tab_ops, text="Operações")
        nb.add(self.tab_logs, text="Logs")

        # Login
        ttk.Label(self.tab_login, text="Matrícula:", font=("Segoe UI", 11)).pack(pady=(20,6))
        fr = ttk.Frame(self.tab_login)
        fr.pack()
        self.entry_matricula = ttk.Entry(fr, width=22, font=("Segoe UI", 11))
        self.entry_matricula.insert(0, self.default_matricula)
        self.entry_matricula.pack(side="left", padx=(0,6))
        ttk.Button(fr, text="Autenticar (Auth)", command=self.autenticar).pack(side="left")
        ttk.Label(self.tab_login, text=f"ProtoBuf TCP -> {SERVER_IP}:{SERVER_PORT}", font=("Segoe UI",9,"italic")).pack(pady=(12,0))

        # Operations
        ops = ttk.LabelFrame(self.tab_ops, text="Operações", padding=12)
        ops.pack(fill="both", expand=False, padx=12, pady=12)

        ttk.Button(ops, text="Echo", width=28, command=self.op_echo).grid(row=0, column=0, padx=6, pady=6)
        ttk.Button(ops, text="Soma", width=28, command=self.op_soma).grid(row=0, column=1, padx=6, pady=6)
        ttk.Button(ops, text="Timestamp", width=28, command=self.op_timestamp).grid(row=1, column=0, padx=6, pady=6)
        ttk.Button(ops, text="Status/Info", width=28, command=self.op_info).grid(row=1, column=1, padx=6, pady=6)
        ttk.Button(ops, text="Histórico", width=28, command=self.op_historico).grid(row=2, column=0, padx=6, pady=6)
        ttk.Button(ops, text="Logout", width=28, command=self.logout).grid(row=2, column=1, padx=6, pady=6)

        # Logs
        ttk.Label(self.tab_logs, text="Logs (somente nesta aba):", font=("Segoe UI",11,"bold")).pack(pady=(8,2))
        self.text_logs = scrolledtext.ScrolledText(self.tab_logs, width=92, height=30, state="disabled", font=("Consolas",10))
        self.text_logs.pack(padx=8, pady=8)

    def log(self, msg: str):
        ts = gerar_timestamp()
        self.text_logs.config(state="normal")
        self.text_logs.insert("end", f"[{ts}] {msg}\n")
        self.text_logs.config(state="disabled")
        self.text_logs.yview("end")

    # ---------------- Protobuf TCP helpers ----------------
    def _connect(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((SERVER_IP, SERVER_PORT))
        return sock

    def send_protobuf(self, req: sd_protocol_pb2.Requisicao) -> sd_protocol_pb2.Resposta:
        """Serializa e envia Requisicao, recebe e desserializa Resposta."""
        data = req.SerializeToString()
        # log envio em formato legível (json-ish)
        try:
            # construir descrição simples para log
            js = self._requisicao_to_jsonish(req)
            self.log(f"→ {json.dumps(js, ensure_ascii=False)}")
        except Exception:
            self.log(f"→ (protobuf bin) len={len(data)}")

        sock = self._connect()
        try:
            if USE_LENGTH_PREFIX:
                length = len(data)
                prefix = length.to_bytes(4, "big")
                sock.sendall(prefix + data)
            else:
                # envia blob seguido por 'FIM'
                sock.sendall(data + b"FIM")
            # receber resposta
            if USE_LENGTH_PREFIX:
                # primeiro leia 4 bytes
                header = self._recvall(sock, 4)
                if not header or len(header) < 4:
                    raise ConnectionError("Resposta incompleta (header).")
                length = int.from_bytes(header, "big")
                body = self._recvall(sock, length)
                if not body:
                    raise ConnectionError("Resposta incompleta (body).")
                resp = sd_protocol_pb2.Resposta()
                resp.ParseFromString(body)
            else:
                # leia até encontrar b'FIM' ou até fechar (alternativa de terminador)
                buffer = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buffer += chunk
                    if buffer.endswith(b"FIM"):
                        buffer = buffer[:-3]
                        break
                    if len(buffer) > 10 * 1024 * 1024:
                        raise RuntimeError("Resposta muito grande")
                resp = sd_protocol_pb2.Resposta()
                resp.ParseFromString(buffer)
            # log resposta em json-like
            try:
                j = self._resposta_to_jsonish(resp)
                self.log(f"← {json.dumps(j, ensure_ascii=False)}")
            except Exception:
                self.log(f"← (protobuf bin) len={len(resp.SerializeToString())}")
            return resp
        finally:
            sock.close()

    def _recvall(self, sock: socket.socket, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                break
            data += chunk
        return data

    # ---------------- util para logs: converte request/response pra dicionários legíveis
    def _requisicao_to_jsonish(self, req: sd_protocol_pb2.Requisicao) -> Dict[str, Any]:
        d = {}
        which = req.WhichOneof("tipo")
        d["tipo"] = which
        if which == "auth":
            a = req.auth
            d.update({"aluno_id": a.aluno_id, "timestamp_cliente": a.timestamp_cliente})
        elif which == "operacao":
            o = req.operacao
            d.update({"token": o.token, "operacao": o.operacao, "parametros": map_to_dict(o.parametros)})
        elif which == "info":
            i = req.info
            d.update({"tipo_info": i.tipo})
        elif which == "logout":
            l = req.logout
            d.update({"token": l.token})
        return d

    def _resposta_to_jsonish(self, resp: sd_protocol_pb2.Resposta) -> Dict[str, Any]:
        which = resp.WhichOneof("tipo")
        out = {"tipo": which}
        if which == "ok":
            ok = resp.ok
            out["comando"] = ok.comando
            out["dados"] = map_to_dict(ok.dados)
            out["timestamp"] = ok.timestamp
        elif which == "erro":
            err = resp.erro
            out["comando"] = err.comando
            out["mensagem"] = err.mensagem
            out["detalhes"] = map_to_dict(err.detalhes)
            out["timestamp"] = err.timestamp
        return out

    # ---------------- actions ----------------
    def autenticar(self):
        mat = self.entry_matricula.get().strip()
        if not mat:
            messagebox.showwarning("Aviso", "Informe matrícula.")
            return
        req = sd_protocol_pb2.Requisicao()
        req.auth.aluno_id = mat
        req.auth.timestamp_cliente = gerar_timestamp()
        try:
            resp = self.send_protobuf(req)
        except Exception as e:
            messagebox.showerror("Erro", f"Falha no AUTH: {e}")
            return
        if resp.WhichOneof("tipo") == "ok":
            dados = map_to_dict(resp.ok.dados)
            token = dados.get("token") or ""
            if token:
                self.token = token
                messagebox.showinfo("Autenticado", f"Token recebido:\n{token}")
            else:
                messagebox.showwarning("Autenticado", "Recebido OK mas sem token em dados.")
        else:
            messagebox.showerror("Erro AUTH", resp.erro.mensagem if resp.WhichOneof("tipo") == "erro" else "Resposta inesperada")

    def enviar_operacao(self, operacao: str, parametros: Dict[str, str]):
        if not self.token:
            messagebox.showwarning("Aviso", "Autentique primeiro.")
            return
        req = sd_protocol_pb2.Requisicao()
        req.operacao.token = self.token
        req.operacao.operacao = operacao
        # parametros: map<string,string>
        for k, v in parametros.items():
            req.operacao.parametros[k] = v
        try:
            resp = self.send_protobuf(req)
        except Exception as e:
            messagebox.showerror("Erro", f"Falha na operação: {e}")
            return
        # exibe resposta
        if resp.WhichOneof("tipo") == "ok":
            messagebox.showinfo("Resposta", json.dumps(self._resposta_to_jsonish(resp), ensure_ascii=False, indent=2))
        else:
            messagebox.showerror("Erro operação", resp.erro.mensagem)

    # ---------------- GUI ops ----------------
    def op_echo(self):
        def enviar():
            msg = entry.get().strip()
            dlg.destroy()
            self.enviar_operacao("echo", {"mensagem": msg})
        dlg = tk.Toplevel(self.root)
        dlg.title("Echo")
        ttk.Label(dlg, text="Mensagem:").pack(padx=8, pady=6)
        entry = ttk.Entry(dlg, width=60)
        entry.pack(padx=8, pady=6)
        ttk.Button(dlg, text="Enviar", command=enviar).pack(pady=10)

    def op_soma(self):
        def enviar():
            txt = entry.get().strip()
            # envia como string separada por vírgula (server aceita esse estilo nos outros clients)
            dlg.destroy()
            self.enviar_operacao("soma", {"nums": txt})
        dlg = tk.Toplevel(self.root)
        dlg.title("Soma")
        ttk.Label(dlg, text="Números separados por vírgula:").pack(padx=8, pady=6)
        entry = ttk.Entry(dlg, width=50)
        entry.pack(padx=8, pady=6)
        ttk.Button(dlg, text="Enviar", command=enviar).pack(pady=10)

    def op_timestamp(self):
        self.enviar_operacao("timestamp", {})

    def op_info(self):
        # ex.: tipo "basico"|"operacoes"|"estatisticas"
        def enviar():
            t = entry.get().strip()
            dlg.destroy()
            if t:
                self.enviar_operacao("info", {"tipo": t})
            else:
                self.enviar_operacao("info", {})
        dlg = tk.Toplevel(self.root)
        dlg.title("Info")
        ttk.Label(dlg, text='Tipo (ex: "basico" ou "operacoes"):').pack(padx=8, pady=6)
        entry = ttk.Entry(dlg, width=30)
        entry.pack(padx=8, pady=6)
        ttk.Button(dlg, text="Enviar", command=enviar).pack(pady=10)

    def op_historico(self):
        def enviar():
            val = entry.get().strip()
            dlg.destroy()
            if val:
                self.enviar_operacao("historico", {"limite": val})
            else:
                self.enviar_operacao("historico", {})
        dlg = tk.Toplevel(self.root)
        dlg.title("Histórico")
        ttk.Label(dlg, text="Limite (opcional):").pack(padx=8, pady=6)
        entry = ttk.Entry(dlg, width=20)
        entry.pack(padx=8, pady=6)
        ttk.Button(dlg, text="Enviar", command=enviar).pack(pady=10)

    def logout(self):
        if not self.token:
            messagebox.showinfo("Logout", "Nenhuma sessão ativa.")
            return
        req = sd_protocol_pb2.Requisicao()
        req.logout.token = self.token
        try:
            resp = self.send_protobuf(req)
            if resp.WhichOneof("tipo") == "ok":
                messagebox.showinfo("Logout", "Logout OK")
            else:
                messagebox.showerror("Logout", resp.erro.mensagem)
        except Exception as e:
            messagebox.showerror("Erro logout", str(e))
        finally:
            self.token = None

# ---------------- main ----------------
def main():
    root = tk.Tk()
    app = ClienteProtoApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
