import os
import sys
import psutil
import time
import threading
import logging
import json
import hashlib
import requests
import yara
import sqlite3
from collections import deque
from datetime import datetime
from threading import Lock
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import numpy as np
from concurrent.futures import ThreadPoolExecutor

# Conditionally import Windows-specific modules if running on Windows.
if sys.platform.startswith('win'):
    import winreg
    import win32api, win32con, win32security, win32process
else:
    pass

# TensorFlow / Keras imports
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, BatchNormalization, Dropout, Activation
from tensorflow.keras.optimizers.experimental import AdamW  # AdamW optimizer

# For scaling and splitting training data.
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from tensorflow.keras.utils import to_categorical

# Tkinter for GUI.
import tkinter as tk
from tkinter import ttk, messagebox

# Configure logging (to console).
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Set your VirusTotal API key from an environment variable, or fallback to a default.
VT_API_KEY = os.environ.get("VT_API_KEY", "0c1cf662725bf06a03d1e0434f26916a3e68a0fb7545b2134a2fa33744650655")

# Name of the SQLite database file.
DB_FILE = "process_logs.db"

def init_db():
    """Initialize the SQLite database and create the table if it does not exist."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS process_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            cpu_percent REAL,
            memory_percent REAL,
            num_threads INTEGER,
            open_files INTEGER,
            connections INTEGER,
            read_bytes REAL,
            write_bytes REAL,
            read_count INTEGER,
            write_count INTEGER,
            rss INTEGER,
            vms INTEGER,
            digital_signature INTEGER,
            threat INTEGER
        )
    """)
    conn.commit()
    conn.close()

# Call init_db() at startup.
init_db()

def mish(x):
    """Custom Mish activation function: x * tanh(softplus(x))."""
    return x * tf.math.tanh(tf.math.softplus(x))

def build_dnn_model(input_size=12):
    """
    Build a DNN model using the Keras Sequential API with:
      - Dense layers with Mish activation, BatchNormalization, Dropout.
      - Output: 2 neurons (softmax) for binary classification.
      - Compiled with AdamW.
    """
    model = Sequential()
    model.add(Dense(4096, input_dim=input_size))
    model.add(Activation(mish))
    model.add(BatchNormalization())
    model.add(Dropout(0.3))
    
    model.add(Dense(2048))
    model.add(Activation(mish))
    model.add(BatchNormalization())
    model.add(Dropout(0.3))
    
    model.add(Dense(1024))
    model.add(Activation(mish))
    model.add(BatchNormalization())
    model.add(Dropout(0.3))
    
    model.add(Dense(512))
    model.add(Activation(mish))
    model.add(BatchNormalization())
    model.add(Dropout(0.3))
    
    model.add(Dense(256))
    model.add(Activation(mish))
    model.add(BatchNormalization())
    model.add(Dropout(0.3))
    
    model.add(Dense(128))
    model.add(Activation(mish))
    model.add(BatchNormalization())
    model.add(Dropout(0.3))
    
    model.add(Dense(64))
    model.add(Activation(mish))
    model.add(BatchNormalization())
    model.add(Dropout(0.3))
    
    model.add(Dense(32))
    model.add(Activation(mish))
    model.add(BatchNormalization())
    model.add(Dropout(0.3))
    
    model.add(Dense(16))
    model.add(Activation(mish))
    model.add(BatchNormalization())
    model.add(Dropout(0.3))
    
    model.add(Dense(8))
    model.add(Activation(mish))
    model.add(BatchNormalization())
    model.add(Dropout(0.3))
    
    # Output layer: 2 neurons for binary classification.
    model.add(Dense(2, activation='softmax'))
    
    optimizer = AdamW(learning_rate=1e-3, weight_decay=1e-4)
    model.compile(optimizer=optimizer, loss='categorical_crossentropy', metrics=['accuracy'])
    return model

class ProcessMonitor:
    """
    Monitors processes and logs 12 features per process into a SQLite DB.
    Uses a DNN for threat scoring (on 12 features) and combines rule-based scores.
    """
    def __init__(self):
        self.running = True
        self.process_cache = {}   # PID -> process details.
        self.suspicious_processes = set()
        self.cpu_history = {}     # PID -> list of recent CPU percentages.
        self.lock = Lock()
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.load_threat_patterns()
        self.dnn_model = build_dnn_model(input_size=12)
        self.model_lock = Lock()  # Protects model updates.
        self.scaler = StandardScaler()  # In-memory scaler.
        self.scaler_fitted = False

    def load_threat_patterns(self):
        # Adjust thresholds as needed.
        self.threat_patterns = {
            'cryptominer': {
                'cpu_sustained': 30,
                'network_connections': ['tcp/3333', 'tcp/14444', 'tcp/7777'],
                'process_names': ['xmrig', 'minergate', 'cgminer']
            }
        }
    
    def log_process_data(self, details, threat):
        """Insert process details and threat label into the SQLite database."""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        timestamp = datetime.now().isoformat()
        cursor.execute("""
            INSERT INTO process_logs (
                timestamp, cpu_percent, memory_percent, num_threads, open_files, connections,
                read_bytes, write_bytes, read_count, write_count, rss, vms, digital_signature, threat
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (timestamp,
              details['cpu_percent'],
              details['memory_percent'],
              details['num_threads'],
              details['open_files'],
              details['connections'],
              details.get('read_bytes', 0),
              details.get('write_bytes', 0),
              details.get('read_count', 0),
              details.get('write_count', 0),
              details.get('rss', 0),
              details.get('vms', 0),
              details.get('digital_signature', 1),
              1 if threat else 0))
        conn.commit()
        conn.close()

    def get_process_details(self, pid):
        try:
            process = psutil.Process(pid)
            with process.oneshot():
                details = {}
                details['name'] = process.name()
                details['exe'] = process.exe()
                details['cpu_percent'] = process.cpu_percent(interval=0.1)
                details['memory_percent'] = process.memory_percent()
                details['num_threads'] = process.num_threads()
                details['open_files'] = len(process.open_files())
                details['connections'] = len(process.connections())
                io = process.io_counters() if hasattr(process, 'io_counters') else None
                if io:
                    details['read_bytes'] = io.read_bytes
                    details['write_bytes'] = io.write_bytes
                    details['read_count'] = io.read_count
                    details['write_count'] = io.write_count
                else:
                    details['read_bytes'] = 0
                    details['write_bytes'] = 0
                    details['read_count'] = 0
                    details['write_count'] = 0
                mem_info = process.memory_info() if hasattr(process, 'memory_info') else None
                if mem_info:
                    details['rss'] = mem_info.rss
                    details['vms'] = mem_info.vms
                else:
                    details['rss'] = 0
                    details['vms'] = 0
                if sys.platform.startswith('win'):
                    sig = self.check_process_signature(details['exe'])
                    details['digital_signature'] = 1 if sig else 0
                else:
                    details['digital_signature'] = 1
                return details
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logging.error(f"Error retrieving details for PID {pid}: {e}")
            return None

    def check_process_signature(self, process_path):
        if not sys.platform.startswith('win'):
            return True
        try:
            return win32api.GetFileVersionInfo(process_path, '\\')
        except Exception as e:
            logging.warning(f"Signature check failed for {process_path}: {e}")
            return None

    def compute_file_hash(self, file_path, chunk_size=4096):
        try:
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                while True:
                    data = f.read(chunk_size)
                    if not data:
                        break
                    sha256.update(data)
            return sha256.hexdigest()
        except Exception as e:
            logging.error(f"Error computing hash for {file_path}: {e}")
            return None

    def query_virustotal_file(self, file_hash):
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": VT_API_KEY}
            response = requests.get(url, headers=headers, timeout=10)
            if response.ok:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                if malicious > 0:
                    logging.critical(f"VirusTotal reports file {file_hash} as malicious: {stats}")
                else:
                    logging.info(f"VirusTotal check for file {file_hash}: Clean")
            else:
                logging.error(f"VirusTotal API error for file {file_hash}: Status code {response.status_code}")
        except Exception as e:
            logging.error(f"Error querying VirusTotal for file {file_hash}: {e}")

    def dnn_predict_threat(self, details):
        try:
            features = [
                details['cpu_percent'],
                details['memory_percent'],
                details['num_threads'],
                details['open_files'],
                details['connections'],
                details['read_bytes'],
                details['write_bytes'],
                details['read_count'],
                details['write_count'],
                details['rss'],
                details['vms'],
                details['digital_signature']
            ]
            input_array = np.array(features).reshape(1, -1)
            # If a scaler is fitted, scale the input.
            if self.scaler_fitted:
                input_array = self.scaler.transform(input_array)
            dnn_prediction = self.dnn_model.predict(input_array)
            dnn_score = dnn_prediction[0][1]
            logging.info(f"DNN threat score: {dnn_score:.2f}")
            return dnn_score
        except Exception as e:
            logging.error(f"Error in DNN threat prediction: {e}")
            return 0

    def monitor_new_processes(self):
        while self.running:
            for proc in psutil.process_iter(['pid']):
                pid = proc.info['pid']
                if pid not in self.process_cache:
                    details = self.get_process_details(pid)
                    if details:
                        with self.lock:
                            self.process_cache[pid] = details
                            if pid in self.cpu_history:
                                self.cpu_history[pid].append(details['cpu_percent'])
                                if len(self.cpu_history[pid]) > 5:
                                    self.cpu_history[pid] = self.cpu_history[pid][-5:]
                            else:
                                self.cpu_history[pid] = [details['cpu_percent']]
                        self.analyze_process(pid, details)
            time.sleep(1)

    def analyze_process(self, pid, details):
        score = 0
        if details['cpu_percent'] > self.threat_patterns['cryptominer']['cpu_sustained']:
            score += 30
        avg_cpu = np.mean(self.cpu_history.get(pid, [details['cpu_percent']]))
        if details['cpu_percent'] > avg_cpu * 1.5:
            score += 10
        if details['connections'] > 50:
            score += 20
        if any(mal in details['name'].lower() for mal in self.threat_patterns['cryptominer']['process_names']):
            score += 50
        if not self.check_process_signature(details['exe']):
            score += 10
        dnn_score = self.dnn_predict_threat(details)
        final_score = score + dnn_score
        logging.info(f"Combined threat score for PID {pid}: {final_score:.2f}")
        threat_flag = 1 if final_score >= 33 else 0  # threshold lowered to 33
        # Log process data into the database.
        self.log_process_data(details, threat_flag)
        if threat_flag:
            with self.lock:
                self.suspicious_processes.add(pid)
            file_hash = self.compute_file_hash(details['exe'])
            if file_hash:
                self.executor.submit(self.query_virustotal_file, file_hash)

    def retrain_model(self):
        """Periodically retrain the model using all logged data."""
        try:
            conn = sqlite3.connect(DB_FILE)
            df = pd.read_sql_query("SELECT * FROM process_logs", conn)
            conn.close()
            if df.empty:
                logging.info("No data for retraining.")
                return
            # Use all columns except id and timestamp as features.
            feature_cols = ['cpu_percent', 'memory_percent', 'num_threads', 'open_files',
                            'connections', 'read_bytes', 'write_bytes', 'read_count',
                            'write_count', 'rss', 'vms', 'digital_signature']
            X = df[feature_cols]
            y = df['threat']
            # Split data for training and testing.
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
            # Scale the data.
            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_test_scaled = scaler.transform(X_test)
            # Convert labels to categorical.
            y_train_cat = to_categorical(y_train, num_classes=2)
            y_test_cat = to_categorical(y_test, num_classes=2)
            # Build a new model.
            new_model = build_dnn_model(input_size=12)
            logging.info("Retraining model on %d samples...", len(X_train_scaled))
            new_model.fit(X_train_scaled, y_train_cat, epochs=10, batch_size=64, verbose=2)
            accuracy = new_model.evaluate(X_test_scaled, y_test_cat, verbose=0)[1]
            logging.info("Retrained model accuracy: %.2f%%", accuracy * 100)
            # Safely update the model and scaler.
            with self.model_lock:
                self.dnn_model = new_model
                self.scaler = scaler
                self.scaler_fitted = True
            logging.info("Model and scaler updated.")
        except Exception as e:
            logging.error("Error during retraining: %s", e)

class MalwareDetector:
    """
    Integrates the monitoring components, provides live GUI updates,
    and schedules periodic retraining.
    """
    def __init__(self, gui_status_callback=None, gui_listbox=None):
        self.process_monitor = ProcessMonitor()
        self.running = False
        self.gui_status_callback = gui_status_callback
        self.gui_listbox = gui_listbox
        self.retraining_interval = 30  # Retrain every 30 seconds (1/2 minutes)
    
    def start(self):
        self.running = True
        threading.Thread(target=self.process_monitor.monitor_new_processes, daemon=True).start()
        threading.Thread(target=self.schedule_retraining, daemon=True).start()
        while self.running:
            if self.gui_status_callback:
                proc_count = len(self.process_monitor.process_cache)
                susp_count = len(self.process_monitor.suspicious_processes)
                self.gui_status_callback(f"Processes scanned: {proc_count} | Suspicious: {susp_count}")
            if self.gui_listbox:
                self.gui_listbox.delete(0, tk.END)
                with self.process_monitor.lock:
                    for pid, details in self.process_monitor.process_cache.items():
                        process_name = details.get('name', 'N/A')
                        if pid in self.process_monitor.suspicious_processes:
                            color = "red"
                            status = "Threat"
                        else:
                            color = "green"
                            status = "No Threat"
                        item = f"PID: {pid} | {process_name} | {status}"
                        self.gui_listbox.insert(tk.END, item)
                        self.gui_listbox.itemconfig(tk.END, {'bg': color})
            time.sleep(1)
    
    def schedule_retraining(self):
        while self.running:
            time.sleep(self.retraining_interval)
            logging.info("Starting periodic retraining...")
            self.process_monitor.retrain_model()
    
    def stop(self):
        self.running = False
        self.process_monitor.running = False

def create_gui():
    root = tk.Tk()
    root.title("Malware Detection System")
    root.geometry("700x500")
    
    status_label = tk.Label(root, text="Status: Waiting...", font=("Arial", 14))
    status_label.pack(pady=5)
    
    listbox_frame = tk.Frame(root)
    listbox_frame.pack(pady=10)
    
    scrollbar = tk.Scrollbar(listbox_frame, orient=tk.VERTICAL)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    listbox = tk.Listbox(listbox_frame, width=80, height=20, font=("Arial", 12), yscrollcommand=scrollbar.set)
    listbox.pack(side=tk.LEFT, fill=tk.BOTH)
    scrollbar.config(command=listbox.yview)
    
    detector = MalwareDetector(
        gui_status_callback=lambda text: status_label.config(text=text),
        gui_listbox=listbox
    )
    
    # Mutable flag to track monitoring state.
    detector_running = [False]
    
    def toggle_monitoring():
        if detector_running[0]:
            detector.stop()
            toggle_button.config(text="Start Monitoring")
            detector_running[0] = False
        else:
            detector_running[0] = True
            threading.Thread(target=detector.start, daemon=True).start()
            toggle_button.config(text="Stop Monitoring")
    
    toggle_button = tk.Button(root, text="Start Monitoring", font=("Arial", 12), command=toggle_monitoring)
    toggle_button.pack(pady=5)
    
    root.mainloop()

if __name__ == "__main__":
    create_gui()

