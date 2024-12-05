import csv
from collections import Counter

# Path to the log file
log_file_path = "sample.log"
output_csv_file = "log_analysis_results.csv"
threshold = 10  # Configurable threshold for failed login attempts

def count_requests_per_ip(file_path):
    ip_counter = Counter()
    try:
        with open(file_path, "r") as file:
            for line in file:
                try:
                    ip_address = line.split()[0]  # Extract IP address
                    ip_counter[ip_address] += 1
                except IndexError:
                    print(f"Malformed log entry skipped: {line.strip()}")
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None
    except PermissionError:
        print(f"Error: Permission denied for file '{file_path}'.")
        return None
    return ip_counter

def most_frequent_endpoint(file_path):
    endpoint_counter = Counter()
    try:
        with open(file_path, "r") as file:
            for line in file:
                try:
                    parts = line.split('"')
                    if len(parts) > 1:
                        request_details = parts[1]
                        endpoint = request_details.split()[1]  # Extract endpoint
                        endpoint_counter[endpoint] += 1
                except (IndexError, ValueError):
                    print(f"Malformed log entry skipped: {line.strip()}")
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None
    except PermissionError:
        print(f"Error: Permission denied for file '{file_path}'.")
        return None
    return endpoint_counter.most_common(1)[0] if endpoint_counter else ("None", 0)

def detect_suspicious_activity(file_path, threshold):
    failed_attempts = Counter()
    try:
        with open(file_path, "r") as file:
            for line in file:
                try:
                    if "401" in line or "Invalid credentials" in line:
                        ip_address = line.split()[0]  # Extract IP address
                        failed_attempts[ip_address] += 1
                except IndexError:
                    print(f"Malformed log entry skipped: {line.strip()}")
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None
    except PermissionError:
        print(f"Error: Permission denied for file '{file_path}'.")
        return None
    return {ip: count for ip, count in failed_attempts.items() if count > threshold}

def save_results_to_csv(ip_requests, most_accessed, suspicious_ips, output_file):
    try:
        with open(output_file, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            
            # Write Requests per IP
            writer.writerow(["Requests per IP"])
            writer.writerow(["IP Address", "Request Count"])
            for ip, count in (ip_requests or {}).items():
                writer.writerow([ip, count])
            
            # Write a blank row for separation
            writer.writerow([])
            
            # Write Most Accessed Endpoint
            writer.writerow(["Most Accessed Endpoint"])
            writer.writerow(["Endpoint", "Access Count"])
            writer.writerow([most_accessed[0], most_accessed[1]])
            
            # Write a blank row for separation
            writer.writerow([])
            
            # Write Suspicious Activity
            writer.writerow(["Suspicious Activity"])
            writer.writerow(["IP Address", "Failed Login Count"])
            for ip, count in (suspicious_ips or {}).items():
                writer.writerow([ip, count])
    except Exception as e:
        print(f"Error writing to CSV file: {e}")

# Execute functions and save results
ip_requests = count_requests_per_ip(log_file_path)
if ip_requests is not None:
    most_accessed = most_frequent_endpoint(log_file_path)
    suspicious_ips = detect_suspicious_activity(log_file_path, threshold)

    # Print results to the terminal
    if ip_requests is not None:
        print("\nRequests per IP:")
        for ip, count in ip_requests.items():
            print(f"{ip}: {count}")

    if most_accessed is not None:
        print("\nMost Frequently Accessed Endpoint:")
        print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    if suspicious_ips is not None:
        print("\nSuspicious Activity Detected:")
        if suspicious_ips:
            for ip, count in suspicious_ips.items():
                print(f"{ip}: {count} failed login attempts")
        else:
            print("No suspicious activity detected.")

    # Save results to a CSV file
    save_results_to_csv(ip_requests, most_accessed, suspicious_ips, output_csv_file)
    print(f"\nResults saved to {output_csv_file}")
else:
    print("\nLog analysis could not be completed due to an error.")
