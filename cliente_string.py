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

