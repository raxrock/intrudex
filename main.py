import pandas as pd
import hashlib
import numpy as np

df = pd.read_csv("Midterm_53_group.csv")
df.head()

# Extract Source and Destination IP
df_filtered = df[['Source', 'Destination']]

print(df_filtered.head())

# --- Helper Function: Count Trailing Zeros ---
def count_trailing_zeros(x):
    if x == 0:
        return 0
    # x & -x isolates the lowest set bit; its bit length minus one gives the count of trailing zeros.
    return (x & -x).bit_length() - 1

# --- FM Algorithm Function ---
def fm_estimate(stream, num_hashes=10):
    estimates = []
    for seed in range(num_hashes):
        max_zeros = 0
        for ip in stream:
            # Use MD5 with an extra seed string to simulate different hash functions.
            hash_value = int(hashlib.md5((ip + str(seed)).encode('utf-8')).hexdigest(), 16)
            tz = count_trailing_zeros(hash_value)
            if tz > max_zeros:
                max_zeros = tz
        # Correction factor phi for the FM algorithm (approximately 0.77351)
        phi = 0.77351
        estimate = (2 ** max_zeros) / phi
        estimates.append(estimate)
    return np.mean(estimates)

# --- Sliding Window Analysis ---
def sliding_window_fm(df, window_size, step, num_hashes=10):
   
    results = []
    for start in range(0, len(df) - window_size + 1, step):
        window = df.iloc[start:start+window_size]
        source_ips = window['Source'].tolist()
        fm_est = fm_estimate(source_ips, num_hashes)
        actual_distinct = len(set(source_ips))
        error = abs(fm_est - actual_distinct) / actual_distinct if actual_distinct > 0 else 0
        results.append({
            'window_start': start,
            'window_end': start + window_size,
            'fm_estimate': fm_est,
            'actual_distinct': actual_distinct,
            'relative_error': error
        })
    return pd.DataFrame(results)

# Set parameters for the sliding window.
window_size = 100
step = 50
num_hashes = 10

# Compute the FM estimates over the sliding windows.
results_df = sliding_window_fm(df_filtered, window_size, step, num_hashes)
print("\nSliding window analysis results:")
print(results_df.head())

# Detecting Attacks
baseline = results_df['actual_distinct'].median()
results_df['suspicious'] = results_df['fm_estimate'] > (1.5 * baseline)
print("\nPotentially malicious windows (based on distinct count anomaly):")
print(results_df[results_df['suspicious']])

#Performance Analysis
mean_relative_error = results_df['relative_error'].mean()
print(f"\nMean Relative Error of FM estimation: {mean_relative_error:.3f}")

# Save results to CSV files
results_df[results_df['suspicious']].to_csv("suspicious_windows.csv", index=False)