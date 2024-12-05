from collections import Counter

log_file_path = "sample.log"

threshold = 10

def detect_suspicious_activity(file_path, threshold):
    failed_attempts = Counter()

    with open(file_path, "r") as file:
        for line in file:
            if "401" in line or "Invalid credentials" in line:
                ip_address = line.split()[0]  
                failed_attempts[ip_address] += 1

    suspicious_ips = {ip : count for ip, count in failed_attempts.items() if count > threshold}

    if suspicious_ips:
        print("Suspicious Activity Detected:")
        print(f"{'IP Address':<20} {'Failed Login Attempts':<25}")
        print("-" * 45)
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count:<25}")
    else:
        print("No suspicious activity detected.")


detect_suspicious_activity(log_file_path, threshold)