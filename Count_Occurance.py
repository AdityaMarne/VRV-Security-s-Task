from collections import Counter

log_file_path = "sample.log"

def count_requests_per_ip(file_path):
    ip_counter = Counter()

    with open(file_path, "r") as file:
        for line in file:
            ip_address = line.split()[0]
            ip_counter[ip_address] += 1

    sorted_ips = sorted(ip_counter.items(), key= lambda x:x[1], reverse=True)

    print(f"{'IP Address':<20} {'Request Count':<15}")
    print("-" * 35)
    for ip, count in sorted_ips:
        print(f"{ip:<20} {count:<15}")

count_requests_per_ip(log_file_path)