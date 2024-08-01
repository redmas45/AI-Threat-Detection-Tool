import psutil
import time
import random
import os
import multiprocessing
import logging
import numpy as np

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Threshold values to mimic suspicious activity
CPU_THRESHOLD = 70  # CPU usage above this percentage considered a threat
MEMORY_THRESHOLD = 75  # Memory usage above this percentage considered a threat
IO_THRESHOLD = 1024 * 1024 * 3  # 3MB write to disk per second considered a threat

# Time intervals for checking CPU/Memory/IO usage
CHECK_INTERVAL = 0.5  # Check every 0.5 seconds

def simulate_high_cpu_usage():
    """Simulates high CPU usage to mimic a threat."""
    logging.info("High CPU usage simulation started.")
    while True:
        np.sin(np.random.rand(10**6))  # Use numpy to simulate heavy computation
        time.sleep(0.01)  # Small sleep to keep CPU pegged

def simulate_high_memory_usage():
    """Simulates high memory usage to mimic a threat."""
    logging.info("High memory usage simulation started.")
    large_list = []
    while True:
        large_list.append([random.random() for _ in range(100000)])  # Allocate large chunks of memory
        if psutil.virtual_memory().percent > MEMORY_THRESHOLD:
            logging.info("Memory usage threshold breached. Pausing briefly.")
            time.sleep(0.5)  # Pause if the memory threshold is breached to sustain high usage

def simulate_abnormal_io():
    """Simulates high I/O operations to mimic a threat."""
    logging.info("High I/O simulation started.")
    while True:
        with open('large_file.txt', 'ab') as f:
            f.write(os.urandom(1024 * 1024))  # Write 1MB of random data to file
            f.flush()
        time.sleep(0.2)  # Write every 0.2 seconds to sustain high I/O

def create_synthetic_process(threat_type):
    """Creates a synthetic process that simulates abnormal behavior."""
    if threat_type == 'cpu':
        process = multiprocessing.Process(target=simulate_high_cpu_usage)
    elif threat_type == 'memory':
        process = multiprocessing.Process(target=simulate_high_memory_usage)
    elif threat_type == 'io':
        process = multiprocessing.Process(target=simulate_abnormal_io)
    else:
        raise ValueError("Invalid process type. Choose from 'cpu', 'memory', or 'io'.")
    
    process.start()
    return process

def create_synthetic_threats(num_samples=5):
    """Creates synthetic threat processes."""
    processes = []
    for _ in range(num_samples):
        threat_type = random.choice(['cpu', 'memory', 'io'])
        proc = create_synthetic_process(threat_type)
        processes.append(proc)
        logging.info(f"Started synthetic threat process with type: {threat_type}, PID: {proc.pid}")

    return processes

if __name__ == "__main__":
    synthetic_processes = create_synthetic_threats(num_samples=5)

    # Keep the script running to allow threat processes to execute
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        logging.info("Stopping synthetic threat processes.")
        for proc in synthetic_processes:
            proc.terminate()
