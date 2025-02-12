# AI-Powered Continuous Threat Detection System

A robust, continuously evolving malware detection system that combines real-time behavioral analysis, deep neural network threat scoring, and external threat intelligence (VirusTotal integration) with a user-friendly GUI. This project monitors system processes, logs detailed metrics into a persistent SQLite database, periodically retrains its detection model with emerging threat data, and displays live status updates—all in one integrated solution.

---

## Features

- **Hybrid Threat Detection:**  
  Combines rule-based heuristics with a deep neural network (DNN) to score processes based on 12 features:
  - CPU usage, memory usage, number of threads, open files, network connections
  - Disk I/O metrics (read/write bytes, read/write counts)
  - Detailed memory information (RSS, VMS)
  - Digital signature verification (on Windows)
  
- **Continuous Data Logging:**  
  Captures and stores process behavior data persistently in an SQLite database for future retraining and analysis.

- **Periodic Retraining:**  
  Automatically retrains the DNN model on collected data at regular intervals (e.g., every 5 minutes) so the system evolves with emerging threats.

- **Real-Time VirusTotal Integration:**  
  Computes a SHA256 hash for flagged executables and queries the VirusTotal API for additional threat intelligence.

- **Live GUI Dashboard:**  
  A Tkinter-based graphical interface displays a scrollable, color-coded list of monitored processes:
  - **Green:** Process appears benign.
  - **Red:** Process flagged as a threat.
  - Toggle button to start/stop monitoring and view live status updates.

- **Thread-Safe Model Updates:**  
  Uses locks and thread pooling to ensure that detection, logging, and retraining operate seamlessly without blocking the main monitoring loops.

---

## Requirements

- **Python 3.8+**  
- **TensorFlow 2.x** (with GPU support if available)  
- **psutil**  
- **SQLite3** (Python’s built-in sqlite3 module)  
- **pandas, scikit-learn** (for data processing and model retraining)  
- **tkinter** (usually included with Python on most platforms)  
- **yara-python** (for file signature scanning)  
- **Other standard libraries:** `numpy`, `requests`, `logging`, etc.

---

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/ai-threat-detection.git
   cd ai-threat-detection
   ```

2. **Create a Virtual Environment (Optional but Recommended):**

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

   *Note: Ensure that your system has the proper CUDA and cuDNN libraries installed if you want GPU support with TensorFlow.*

4. **Set Up Environment Variables:**

   - Set your VirusTotal API key:
     ```bash
     export VT_API_KEY=your_virustotal_api_key
     ```

---

## Usage

Run the main script to start the threat detection system:

```bash
python3 rez.py
```

### GUI Overview

- **Status Label:** Displays the number of processes scanned and the number flagged as suspicious.
- **Scrollable Listbox:** Lists each monitored process with its PID, name, and threat status (green for benign, red for threat).
- **Toggle Button:** Click to start or stop monitoring. The button text updates accordingly.
- **Continuous Retraining:** The system automatically retrains the detection model using the latest logged data, ensuring the model adapts to new threats over time.

---

## Architecture Overview

1. **Data Logging Module:**  
   Process metrics are continuously gathered and inserted into an SQLite database (`process_logs.db`), capturing 12 features per process.

2. **Persistent Storage:**  
   The SQLite database stores both benign and suspicious process data, forming the basis for model retraining.

3. **Model Retraining Scheduler:**  
   A dedicated thread wakes at fixed intervals (e.g., every 5 minutes) to:
   - Load logged data.
   - Preprocess and scale the features.
   - Retrain the DNN model.
   - Update the in-memory model safely for real-time detection.

4. **Detection Loop:**  
   The system monitors new processes, computes a combined threat score using both rule-based checks and DNN predictions, and flags processes accordingly. If a process is flagged, additional VirusTotal checks are performed asynchronously.

5. **GUI Dashboard:**  
   A real-time graphical interface built with Tkinter displays live updates and offers controls to start/stop monitoring.

---

## Future Enhancements

- **Advanced Labeling:**  
  Integrate automated labeling based on external threat feeds and manual review to further refine the dataset.

- **Expanded Feature Set:**  
  Incorporate additional features such as API call patterns, file system modifications, and network traffic details.

- **Improved Model Architecture:**  
  Experiment with more complex neural network architectures (e.g., residual networks) and ensemble methods.

- **Cloud Integration:**  
  Use cloud databases and distributed retraining pipelines for scaling the solution in enterprise environments.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- Inspired by modern threat detection systems combining behavioral analysis with external threat intelligence.
- Built using TensorFlow, psutil, SQLite, and Tkinter.

---

Feel free to contribute, open issues, or suggest improvements!

Happy detecting!
