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

