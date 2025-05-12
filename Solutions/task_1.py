import re
from collections import Counter

# Regex parsing for the log file provided
expected_pattern = re.compile(r"""
    (?P<ip>\d+\.\d+\.\d+\.\d+)             # IP address
    \s-\s
    (?P<action>\w+)\s                      # HIT or BYPASS
    \[(?P<timestamp>[^\]]+)\]\s            # [timestamp]
    "(?P<domain>[^"]+)"\s                  # domain
    "(?P<method>\w+)\s(?P<path>[^"]+)\sHTTP/[^"]+"\s  # "GET /path HTTP/1.1"
    (?P<status>\d{3})\s                    # HTTP status code
    (?P<bytes_sent>\d+)\s                  # Bytes sent
    (?P<response_size>\d+)\s               # Response size
    "(?P<referer>[^"]*)"\s                 # Referer
    "(?P<user_agent>[^"]+)"\s              # User-Agent
    "[^"]*"\s                              
    "(?P<proxy_ip>[^"]+)"\s                # Proxy IP
    cc="(?P<cc>[A-Z]{2})"\s                # Country code
    rt=(?P<rt>[\d.]+)\s                    # Response time
    uct="(?P<uct>[\d.]+)"\s                # Upstream connect time
    uht="(?P<uht>[\d.]+)"\s                # Upstream header time
    urt="(?P<urt>[\d.]+)"\s                # Upstream response time
    ucs="(?P<ucs>\d{3})"                   # Upstream cache status
""", re.VERBOSE)

fallback_pattern = re.compile(r'''
    (?P<ip>\d+\.\d+\.\d+\.\d+)\s-\s\w+\s
    \[[^\]]+\]\s
    "[^"]+"\s
    "(?P<method>\w+)\s[^"]+"\s
    (?P<status>\d{3})\s
    \d+\s
    (?P<response_size>\d+)
''', re.VERBOSE)

ip_counts = Counter()
error_count = 0
total_lines = 0
malformed_logs = 0
get_response_size_sum = 0
get_request_count = 0

with open("../problems/nginx_access.log", "r") as f:
    for line in f:
        total_lines += 1
        match = expected_pattern.match(line)
        if not match:
            match = fallback_pattern.search(line)
            if not match:
                malformed_logs += 1
                continue

        data = match.groupdict()

        # Count IPs
        ip_counts[data['ip']] += 1

        # Count error statuses (4xx or 5xx)
        status = int(data['status'])
        if 400 <= status <= 599:
            error_count += 1

        # Track GET request sizes
        if data['method'] == "GET":
            get_request_count += 1
            get_response_size_sum += int(data['response_size'])

print("Top 5 IP addresses by request count:")
for ip, count in ip_counts.most_common(5):
    print(f"  {ip}: {count} requests")

if total_lines:
    percent_errors = (error_count / total_lines) * 100
    print(f"\nPercentage of 4xx/5xx responses: {percent_errors:.2f}%")

if get_request_count:
    avg_response_size = get_response_size_sum / get_request_count
    print(f"Average response size for GET requests: {avg_response_size:.1f} bytes")
else:
    print("No GET requests found.")
