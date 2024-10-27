#Makesure to run this code in terminal to install pandas: pip install pandas matplotlib

import pandas as pd
import re
from collections import Counter
import matplotlib.pyplot as plt

# Sample log data for demonstration purposes
sample_logs = [
    '2024-10-25 12:34:56 IP: 192.168.1.10 LOGIN: SUCCESS',
    '2024-10-25 12:35:10 IP: 192.168.1.10 LOGIN: FAILED',
    '2024-10-25 12:35:11 IP: 192.168.1.10 LOGIN: FAILED',
    '2024-10-25 12:35:12 IP: 192.168.1.10 LOGIN: FAILED',
    '2024-10-25 12:40:00 IP: 10.0.0.1 LOGIN: SUCCESS',
    '2024-10-25 12:45:12 IP: 172.16.0.5 LOGIN: FAILED',
    '2024-10-25 12:50:30 IP: 172.16.0.5 LOGIN: FAILED',
    '2024-10-25 12:51:30 IP: 172.16.0.5 LOGIN: FAILED',
    '2024-10-25 12:52:30 IP: 172.16.0.5 LOGIN: FAILED',
    '2024-10-25 13:00:00 IP: 8.8.8.8 LOGIN: FAILED',
    '2024-10-25 13:05:00 IP: 8.8.8.8 LOGIN: SUCCESS',
]

# Step 1: Parse logs into a structured format (DataFrame)
def parse_logs(logs):
    log_data = []
    for log in logs:
        match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) IP: (\d+\.\d+\.\d+\.\d+) LOGIN: (SUCCESS|FAILED)', log)
        if match:
            timestamp, ip, status = match.groups()
            log_data.append({'Timestamp': timestamp, 'IP Address': ip, 'Status': status})
    return pd.DataFrame(log_data)

# Step 2: Detect anomalies (e.g., multiple failed logins from the same IP)
def detect_anomalies(log_df, failed_attempts_threshold=3):
    # Count failed logins per IP
    failed_attempts = log_df[log_df['Status'] == 'FAILED']['IP Address'].value_counts()

    # Detect IPs exceeding the failed attempts threshold
    suspicious_ips = failed_attempts[failed_attempts > failed_attempts_threshold].index.tolist()

    return suspicious_ips

# Step 3: Visualize failed login attempts
def visualize_failed_logins(log_df):
    failed_attempts = log_df[log_df['Status'] == 'FAILED']['IP Address'].value_counts()

    plt.figure(figsize=(10, 6))
    plt.bar(failed_attempts.index, failed_attempts.values)
    plt.title('Failed Login Attempts by IP Address')
    plt.xlabel('IP Address')
    plt.ylabel('Number of Failed Attempts')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

# Step 4: Generate summary report
def generate_report(log_df, suspicious_ips):
    total_logs = len(log_df)
    failed_logins = len(log_df[log_df['Status'] == 'FAILED'])
    report = {
        'Total Logs Processed': total_logs,
        'Total Failed Logins': failed_logins,
        'Suspicious IPs': suspicious_ips,
    }
    return report

# Executing the tool
log_df = parse_logs(sample_logs)
suspicious_ips = detect_anomalies(log_df)
report = generate_report(log_df, suspicious_ips)

# Displaying the log analysis results
print("Parsed Log Data:\n", log_df)
print("\nAnomalies detected: Suspicious IPs:", suspicious_ips)
print("\nSummary Report:", report)

# Visualize failed login attempts
visualize_failed_logins(log_df)
