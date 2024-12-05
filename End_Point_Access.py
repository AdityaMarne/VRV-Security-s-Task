from collections import Counter

log_file_path = "sample.log"

def most_frequent_endpoint(file_path):
    endpoint_counter = Counter()

    with open(file_path, "r") as file:
        for line in file:
            parts = line.split('"')
            if len(parts) > 1:
                request_details = parts[1]
                endpoint = request_details.split()[1]
                endpoint_counter[endpoint] += 1

    most_accessed = endpoint_counter.most_common(1)[0]
    endpoint, count = most_accessed

    print(f"Most Frequently Accessed Endpoint:")
    print(f"{endpoint} (Accessed {count} times)")

most_frequent_endpoint(log_file_path)