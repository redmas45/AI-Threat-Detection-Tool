import tkinter as tk
from tkinter import ttk, Listbox, Scrollbar, messagebox
import threading
import time
import psutil
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
import joblib
import random
import warnings
import os
import logging


from keras.models import Sequential, load_model
from keras.layers import Dense
from keras.utils import to_categorical
import tensorflow as tf


warnings.filterwarnings("ignore", category=UserWarning)


observed_pids = set()
flagged_pids = set()  
stop_monitoring = False  
data_file = 'flagged_threats.csv'
monitoring_interval = 5  
model_file = 'neural_network_model.h5'
scaler_file = 'scaler.pkl'


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ProcessMonitor:
    def __init__(self, root, listbox):
        self.root = root
        self.listbox = listbox
        self.observed_behaviors = []  
        self.synthetic_threat_data = []  
        self.history = {'cpu_percent': [], 'memory_percent': [], 'read_count': [], 'write_count': [], 'num_threads': [], 'open_files': []}
        self.percentile_threshold = 50  

    def collect_non_threat_data(self, num_processes=500):
        logging.info(f"Collecting non-threat data for {num_processes} processes.")
        non_threat_data = []
        count = 0
        for pid in psutil.pids():
            if pid == 4:  # Skip PID 4 (System)
                continue
            try:
                process = psutil.Process(pid)
                process_info = self.get_process_info(process)
                process_info.append(0)  
                non_threat_data.append(process_info)
                count += 1
                if count >= num_processes:
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return non_threat_data

    def create_synthetic_threat_data(self, num_samples=10000):
        logging.info(f"Generating synthetic threat data for {num_samples} samples.")
        threat_data = []
        for _ in range(num_samples):
            process_info = [
                random.uniform(20, 100),
                random.uniform(30, 100),  
                random.randint(500, 10000),  
                random.randint(500, 10000),  
                random.randint(1, 500),  
                random.randint(1, 1000)  
            ]
            process_info.append(1)  
            threat_data.append(process_info)
        return threat_data

    def combine_data(self, num_processes=500):
        non_threat_data = self.collect_non_threat_data(num_processes)
        synthetic_threat_data = self.create_synthetic_threat_data(num_samples=10000)
        combined_data = non_threat_data + synthetic_threat_data
        df = pd.DataFrame(combined_data, columns=[
            'cpu_percent', 'memory_percent', 'read_count',
            'write_count', 'num_threads', 'open_files', 'label'
        ])
        df.to_csv('process_data.csv', index=False)
        logging.info("Data combined and saved to process_data.csv.")
        return df

    def get_process_info(self, process):
        cpu_percent = process.cpu_percent(interval=None)
        memory_percent = process.memory_percent()
        io_counters = process.io_counters()
        num_threads = process.num_threads()
        open_files = len(process.open_files()) if process.open_files() is not None else 0
        return [cpu_percent, memory_percent, io_counters.read_count, io_counters.write_count, num_threads, open_files]

    def update_stage(self, new_stage, progress_bar, progress_label, deploy_button=None):
        if new_stage == 1:
            self.train_model(progress_bar, progress_label, deploy_button)
        elif new_stage == 2:
            deploy_button.config(state=tk.NORMAL)

    def collect_data(self, progress_bar, progress_label, deploy_button):
        threading.Thread(target=self.collect_data_generator, args=(progress_bar, progress_label, deploy_button)).start()

    def collect_data_generator(self, progress_bar, progress_label, deploy_button, num_processes=500):
        global collected_data
        collected_data = self.combine_data(num_processes)
        self.update_stage(1, progress_bar, progress_label, deploy_button)

    def train_model(self, progress_bar, progress_label, deploy_button):
        """Trains a neural network model."""
        global collected_data
        X = collected_data.drop('label', axis=1)
        y = collected_data['label']

        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=100)

        
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)


        joblib.dump(scaler, scaler_file)

        
        y_train_cat = to_categorical(y_train, num_classes=2)
        y_test_cat = to_categorical(y_test, num_classes=2)

        
        model = Sequential()
        model.add(Dense(1024, input_dim=X_train.shape[1], activation='relu'))
        model.add(Dense(512, activation='relu'))
        model.add(Dense(512, activation='relu'))
        model.add(Dense(512, activation='relu'))
        model.add(Dense(1024, activation='relu'))

        model.add(Dense(2, activation='softmax'))  

        
        model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])

        
        logging.info("Training the neural network model.")
        model.fit(X_train_scaled, y_train_cat, epochs=10, batch_size=10, verbose=2)

        
        accuracy = model.evaluate(X_test_scaled, y_test_cat, verbose=0)[1]
        logging.info(f"Model accuracy: {accuracy * 100:.2f}%")

        
        model.save(model_file)
        logging.info(f"Model saved to {model_file}.")

        progress_bar['value'] = 100
        progress_label.config(text="Model Trained and Saved")
        self.update_stage(2, progress_bar, progress_label, deploy_button)

    def dynamic_thresholds(self):
        thresholds = {}
        for key in self.history:
            if self.history[key]:
                thresholds[key] = {
                    'mean': sum(self.history[key]) / len(self.history[key]),
                    'std_dev': (sum((x - sum(self.history[key]) / len(self.history[key])) ** 2 for x in self.history[key]) / len(self.history[key])) ** 0.5
                }
                thresholds[key]['high'] = thresholds[key]['mean'] + 2 * thresholds[key]['std_dev']
                thresholds[key]['low'] = thresholds[key]['mean'] - 2 * thresholds[key]['std_dev']
        return thresholds

    def monitor_processes(self):
        global observed_pids, stop_monitoring, flagged_pids

        
        if not os.path.exists(model_file):
            logging.error(f"Model file {model_file} not found. Ensure the model is trained and saved correctly.")
            messagebox.showerror("Error", f"Model file {model_file} not found.")
            return

        if not os.path.exists(scaler_file):
            logging.error(f"Scaler file {scaler_file} not found. Ensure the scaler is saved correctly.")
            messagebox.showerror("Error", f"Scaler file {scaler_file} not found.")
            return

        try:
            model = load_model(model_file)
            scaler = joblib.load(scaler_file)
            logging.info(f"Using model from {model_file}")
        except FileNotFoundError:
            logging.error("File not found. Please ensure the model and scaler files exist.")
            messagebox.showerror("Error", "File not found. Please ensure the model and scaler files exist.")
            return
        except Exception as e:
            logging.error(f"Error loading model or scaler: {e}")
            messagebox.showerror("Error", f"Error loading model or scaler: {e}")
            return

        while not stop_monitoring:  
            for pid in psutil.pids():
                if pid == 4 or pid in observed_pids or pid in flagged_pids:
                    continue
                try:
                    process = psutil.Process(pid)
                    process_name = process.name()

                    process_info = self.get_process_info(process)
                    
                    
                    for i, key in enumerate(['cpu_percent', 'memory_percent', 'read_count', 'write_count', 'num_threads', 'open_files']):
                        self.history[key].append(process_info[i])

                    
                    process_info_scaled = scaler.transform([process_info])
                    prediction = model.predict(process_info_scaled)
                    prediction_class = prediction.argmax(axis=-1)[0]
                    probability = prediction[0][prediction_class] * 100

                    
                    thresholds = self.dynamic_thresholds()
                    
                    
                    abnormal = False
                    for i, key in enumerate(['cpu_percent', 'memory_percent', 'read_count', 'write_count', 'num_threads', 'open_files']):
                        if thresholds.get(key) and (process_info[i] > thresholds[key]['high']):
                            abnormal = True
                            break
                    
                    
                    if prediction_class == 1 or abnormal:  
                        threat_status = "Threat"
                        color = "red"
                        flagged_pids.add(pid)  

            
                        self.save_flagged_threat(process_info, process_name, probability)
                    else:
                        threat_status = "No Threat"
                        color = "green"

                    
                    self.update_gui(pid, process_name, threat_status, probability, color)

                    
                    observed_pids.add(pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            
            time.sleep(monitoring_interval)

    def save_flagged_threat(self, process_info, process_name, probability):
        df = pd.DataFrame([process_info + [process_name, probability]], columns=[
            'cpu_percent', 'memory_percent', 'read_count',
            'write_count', 'num_threads', 'open_files', 'process_name', 'probability'
        ])
        df.to_csv(data_file, mode='a', header=not os.path.isfile(data_file), index=False)
        logging.info(f"Flagged threat information saved to {data_file}.")

    def update_gui(self, pid, process_name, threat_status, probability, color):
        self.listbox.insert(tk.END, f"PID: {pid} | Name: {process_name} | Status: {threat_status} | Probability: {probability:.2f}%")
        self.listbox.itemconfig(tk.END, {'bg': color})

    def start_monitoring(self):
        threading.Thread(target=self.monitor_processes, daemon=True).start()

    def stop_monitoring_processes(self):
        global stop_monitoring
        stop_monitoring = True
        logging.info("Monitoring stopped.")

def deploy_model(monitor):
    monitor.start_monitoring()
    messagebox.showinfo("Info", "Model deployed and monitoring started.")

def create_gui():
    root = tk.Tk()
    root.title("Malware Detection System")

    
    frame = tk.Frame(root)
    frame.pack(padx=10, pady=10)

    progress_label = tk.Label(frame, text="Collecting Data")
    progress_label.pack()

    progress_bar = ttk.Progressbar(frame, length=300, mode='determinate')
    progress_bar.pack(pady=5)

    
    listbox_frame = tk.Frame(frame)
    listbox_frame.pack(pady=10)

    scrollbar_y = Scrollbar(listbox_frame, orient=tk.VERTICAL)
    scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)

    listbox = Listbox(listbox_frame, width=80, height=20, yscrollcommand=scrollbar_y.set, font=('Arial', 12))
    listbox.pack(side=tk.LEFT, fill=tk.BOTH)

    scrollbar_y.config(command=listbox.yview)

    monitor = ProcessMonitor(root, listbox)

    collect_button = tk.Button(frame, text="Collect Data", command=lambda: monitor.collect_data(progress_bar, progress_label, deploy_button))
    collect_button.pack(pady=5)

    deploy_button = tk.Button(frame, text="Deploy Model", state=tk.DISABLED, command=lambda: deploy_model(monitor))
    deploy_button.pack(pady=5)

    stop_button = tk.Button(frame, text="Stop Monitoring", command=monitor.stop_monitoring_processes)
    stop_button.pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
