import re
from datetime import datetime, timedelta

# Fix 1: Incorect regex
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

def parse_log_line(log_line):
    # Fix 2: Handle logs that fail to parse
    match = expected_pattern.match(log_line)
    if not match:
        match = fallback_pattern.search(log_line)
        if not match:
            return None
    
    ip, action, timestamp_str, domain, method, path, status, bytes_sent, response_size, referer, user_agent, proxy_ip, cc, rt, uct, uht, urt, ucs = match.groups()
    timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')

    return {
        'timestamp': timestamp,
        'status': int(status),
        'ip': ip
    }

def is_error_status(status):
    return 400 <= status <= 599

def monitor_logs(log_file):
    with open(log_file, 'r') as f:
        lines = f.readlines()

    logs = [parse_log_line(line.strip()) for line in lines]
    logs = [log for log in logs if log is not None]
    
    # Fix 4: Sort the logs by timestamp
    logs.sort(key=lambda log: log['timestamp'])

    window_size = 5
    error_threshold = 0.10
    current_window_start = None
    window_requests = 0
    window_errors = 0

    for log_data in logs:
        timestamp = log_data['timestamp']
        status = log_data['status']

        if current_window_start is None:
            current_window_start = timestamp
        
        time_diff = (timestamp - current_window_start).total_seconds() / 60

        if time_diff > window_size:
            if window_requests > 0:
                error_rate = window_errors / window_requests
                if error_rate > error_threshold:
                    # Fix 6: Error rate as percentage
                    print(f"Alert! Error rate {error_rate * 100:.2f}% exceeds threshold at {current_window_start}")
            
            # Fix 7: Correctly reset the window
            current_window_start = timestamp
            window_requests = 0
            window_errors = 0

        window_requests += 1
        if is_error_status(status):
            window_errors += 1

    # Fix 8: Handle potential division by zero
    if window_requests > 0:
        error_rate = window_errors / window_requests
        if error_rate > error_threshold:
            print(f"Alert! Error rate {error_rate * 100:.2f}% exceeds threshold at {current_window_start}")

monitor_logs('../problems/nginx_access.log')
