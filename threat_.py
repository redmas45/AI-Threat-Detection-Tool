import time
import threading
import psutil
import numpy as np
import logging
import gc
import tensorflow as tf
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

class ResourceCycler:
    def __init__(self):
        self.running = True
        self.high_usage = False
        self.data_store = []
        
    def gpu_stress(self):
        """Stress the GPU using TensorFlow operations"""
        while self.running:
            if self.high_usage:
                # Create large tensors and perform operations
                with tf.device('/GPU:0'):
                    a = tf.random.normal([5000, 5000])
                    b = tf.random.normal([5000, 5000])
                    c = tf.matmul(a, b)
                    _ = c.numpy()  # Force execution
            else:
                time.sleep(0.1)

    def cpu_stress(self):
        """Stress the CPU with intensive calculations"""
        while self.running:
            if self.high_usage:
                # Increase the matrix size for more CPU load
                size = 100 # Increased size from 1000 to 1500
                matrix1 = np.random.rand(size, size)
                matrix2 = np.random.rand(size, size)
                _ = np.dot(matrix1, matrix2)
            else:
                time.sleep(0.1)

    def memory_stress(self):
        """Stress memory by allocating and deallocating large chunks"""
        while self.running:
            if self.high_usage:
                # Allocate large chunks of memory repeatedly
                try:
                    for _ in range(10):
                        chunk = ' ' * (500 * 1024 * 1024)  # 500MB
                        self.data_store.append(chunk)
                except MemoryError:
                    self.data_store.clear()
            else:
                # Clear memory
                self.data_store.clear()
                gc.collect()
            time.sleep(2)

    def resource_monitor(self):
        """Monitor and log resource usage"""
        while self.running:
            process = psutil.Process(os.getpid())
            cpu_percent = process.cpu_percent(interval=5)
            mem_percent = process.memory_percent()
            
            logging.info(f"CPU Usage: {cpu_percent:.1f}% | Memory Usage: {mem_percent:.1f}%")
            # Sleep here is already handled by cpu_percent(interval=1)

    def usage_cycler(self):
        """Cycle between high and low resource usage with a longer high usage phase."""
        while self.running:
            # High usage phase: extended duration to simulate threat
            logging.info("Starting high resource usage phase (threat active)...")
            self.high_usage = True
            time.sleep(10)  # High usage for 10 seconds

            # Low usage phase: short recovery period
            logging.info("Starting low resource usage phase...")
            self.high_usage = False
            time.sleep(5)  # Low usage for 2 seconds

    def run(self):
        """Start all threads and run the cycle"""
        threads = [
            threading.Thread(target=self.cpu_stress),
            threading.Thread(target=self.memory_stress),
            threading.Thread(target=self.resource_monitor),
            threading.Thread(target=self.usage_cycler)
        ]

        # Add GPU stress if GPU is available
        if tf.config.list_physical_devices('GPU'):
            threads.append(threading.Thread(target=self.gpu_stress))
            logging.info("GPU support enabled")
        else:
            logging.info("No GPU detected, running without GPU stress")

        # Start all threads
        for thread in threads:
            thread.daemon = True
            thread.start()

        try:
            # Run continuously until interrupted
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logging.info("Shutting down...")
            self.running = False
            for thread in threads:
                thread.join()

if __name__ == "__main__":
    cycler = ResourceCycler()
    cycler.run()

