# Intrudex: Network Anomaly Detection using Flajolet-Martin Algorithm

Intrudex is a Python-based tool for detecting potentially malicious activity in network traffic by estimating the number of unique source IP addresses using the **Flajolet-Martin (FM) algorithm**. This probabilistic technique allows for efficient cardinality estimation over large data streams, making it ideal for identifying anomalies like DDoS attacks or network scans.

## 📌 Features

- Read and preprocess real network traffic logs
- Implement the FM algorithm with multiple hash seeds
- Perform sliding window analysis on IP address streams
- Estimate distinct IPs and compute actual distinct counts
- Automatically flag suspicious activity based on deviations
- Evaluate estimation performance using relative error

---

## 🧪 How It Works

1. **Data Loading**  
   Network packet data is loaded from a CSV file containing `Source` and `Destination` IPs.

2. **FM Estimation**  
   For each window, source IPs are hashed using MD5 with multiple seeds to simulate different hash functions. The number of trailing zeros in each hash determines the rarity of the IP, which is then used to estimate the number of distinct elements.

3. **Sliding Window Analysis**  
   FM estimates and actual distinct counts are calculated for every window (e.g., 100 rows), moving forward in steps (e.g., 50 rows).

4. **Anomaly Detection**  
   If a window's FM estimate exceeds 1.5× the median of actual distinct counts, it is flagged as suspicious.

---

## 📂 File Structure

```
Intrudex/
│
├── main.py                  # Main script implementing the FM algorithm
├── networktraffic.csv       # Input CSV file with 'Source' and 'Destination' IPs
└── README.md                # Project documentation
```

---

## 🚀 Usage

1. Place your network traffic CSV file in the project directory.
2. Update the filename in `main.py` if different.
3. Run the script:

```bash
python main.py
```

---

## 📈 Sample Output

- Printed DataFrame with window-wise FM estimates and relative errors
- A list of windows flagged as **suspicious**
- Average relative error across all windows for accuracy evaluation

---

## 📊 Example Output

```
Sliding window analysis results:
   window_start  window_end  fm_estimate  actual_distinct  relative_error
0             0         100         93.4               90            0.037
...

Potentially malicious windows (based on distinct count anomaly):
   window_start  window_end  fm_estimate  actual_distinct  suspicious
1            50         150       145.2               98        True
...
```

---

## 📌 Future Improvements

- Add visualization (matplotlib/seaborn) for IP trends
- Extend to time-based windows
- Implement HyperLogLog for improved accuracy
- Integrate with real-time packet capture tools (e.g., Wireshark, Scapy)

---

## 👨‍💻 Author

Rakshith KK
Built with 💡, Python, and a lot of patience

---

## ⚠️ Disclaimer

This project is for educational and research purposes only. Ensure ethical use when analyzing real network data.